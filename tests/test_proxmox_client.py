"""
Unit tests for ProxmoxClient methods:
  - get_templates
  - clone_vm
  - create_vm
  - get_next_vmid
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, call

# Make the backend package importable from the tests directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Return a ProxmoxClient with all network/env dependencies mocked out."""
    env = {
        'PROXMOX_HOST': 'proxmox.test',
        'PROXMOX_TOKEN_ID': 'user@pam!mytoken',
        'PROXMOX_TOKEN_SECRET': 'supersecret',
    }
    with patch.dict(os.environ, env):
        with patch('proxmox_client.requests.Session'):
            with patch('urllib3.disable_warnings'):
                from proxmox_client import ProxmoxClient
                c = ProxmoxClient()
                return c


# ---------------------------------------------------------------------------
# get_next_vmid
# ---------------------------------------------------------------------------

class TestGetNextVmid:
    def test_returns_integer_vmid(self, client):
        client._make_request = MagicMock(return_value=200)
        result = client.get_next_vmid()
        assert result == 200
        client._make_request.assert_called_once_with('GET', '/cluster/nextid')

    def test_converts_string_response_to_int(self, client):
        client._make_request = MagicMock(return_value='105')
        result = client.get_next_vmid()
        assert result == 105
        assert isinstance(result, int)

    def test_raises_on_api_error(self, client):
        client._make_request = MagicMock(side_effect=Exception("API unreachable"))
        with pytest.raises(Exception, match="Error getting next VM ID"):
            client.get_next_vmid()


# ---------------------------------------------------------------------------
# get_templates
# ---------------------------------------------------------------------------

class TestGetTemplates:
    def _make_side_effect(self, nodes_data, vms_by_node):
        """Helper to build a _make_request side-effect function."""
        def side_effect(method, endpoint, *args, **kwargs):
            if endpoint == '/nodes':
                return nodes_data
            for node_name, vms in vms_by_node.items():
                if endpoint == f'/nodes/{node_name}/qemu':
                    return vms
            return []
        return side_effect

    def test_returns_only_templates(self, client):
        nodes = [{'node': 'pve1'}]
        vms = [
            {'vmid': 100, 'name': 'ubuntu-template', 'template': 1},
            {'vmid': 101, 'name': 'running-vm',      'template': 0},
            {'vmid': 102, 'name': 'another-vm'},  # missing 'template' key
        ]
        client._make_request = MagicMock(
            side_effect=self._make_side_effect(nodes, {'pve1': vms})
        )
        templates = client.get_templates()
        assert len(templates) == 1
        assert templates[0]['vmid'] == 100
        assert templates[0]['name'] == 'ubuntu-template'
        assert templates[0]['node'] == 'pve1'

    def test_aggregates_templates_across_nodes(self, client):
        nodes = [{'node': 'pve1'}, {'node': 'pve2'}]
        vms = {
            'pve1': [{'vmid': 100, 'name': 'tmpl-ubuntu', 'template': 1}],
            'pve2': [{'vmid': 200, 'name': 'tmpl-debian', 'template': 1}],
        }
        client._make_request = MagicMock(
            side_effect=self._make_side_effect(nodes, vms)
        )
        templates = client.get_templates()
        assert len(templates) == 2
        vmids = {t['vmid'] for t in templates}
        assert vmids == {100, 200}

    def test_returns_empty_list_when_no_templates(self, client):
        nodes = [{'node': 'pve1'}]
        vms = {'pve1': [{'vmid': 101, 'name': 'vm', 'template': 0}]}
        client._make_request = MagicMock(
            side_effect=self._make_side_effect(nodes, vms)
        )
        assert client.get_templates() == []

    def test_skips_node_on_error_and_continues(self, client):
        nodes = [{'node': 'bad'}, {'node': 'good'}]
        def side_effect(method, endpoint, *args, **kwargs):
            if endpoint == '/nodes':
                return nodes
            if endpoint == '/nodes/bad/qemu':
                raise Exception("Node unavailable")
            if endpoint == '/nodes/good/qemu':
                return [{'vmid': 300, 'name': 'tmpl-good', 'template': 1}]
            return []
        client._make_request = MagicMock(side_effect=side_effect)
        templates = client.get_templates()
        assert len(templates) == 1
        assert templates[0]['vmid'] == 300

    def test_uses_fallback_name_when_name_missing(self, client):
        nodes = [{'node': 'pve1'}]
        vms = {'pve1': [{'vmid': 999, 'template': 1}]}  # no 'name' key
        client._make_request = MagicMock(
            side_effect=self._make_side_effect(nodes, vms)
        )
        templates = client.get_templates()
        assert templates[0]['name'] == 'template-999'

    def test_raises_on_nodes_api_error(self, client):
        client._make_request = MagicMock(side_effect=Exception("Cannot reach cluster"))
        with pytest.raises(Exception, match="Error fetching templates"):
            client.get_templates()


# ---------------------------------------------------------------------------
# create_vm
# ---------------------------------------------------------------------------

class TestCreateVm:
    def test_calls_correct_endpoint_with_defaults(self, client):
        client._make_request = MagicMock(return_value='UPID:pve1:task1')
        result = client.create_vm(
            node='pve1', vmid=300, name='test-vm',
            cores=2, memory_mb=2048, storage='local-lvm', disk_gb=20,
        )
        assert result == 'UPID:pve1:task1'
        client._make_request.assert_called_once_with(
            'POST', '/nodes/pve1/qemu',
            data={
                'vmid': 300,
                'name': 'test-vm',
                'cores': 2,
                'memory': 2048,
                'sockets': 1,
                'cpu': 'host',
                'scsi0': 'local-lvm:20',
                'net0': 'virtio,bridge=vmbr0',
                'ostype': 'l26',
                'scsihw': 'virtio-scsi-pci',
                'start': 0,
            },
        )

    def test_start_flag_true(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=301, name='vm', cores=1,
            memory_mb=512, storage='local', disk_gb=10, start=True,
        )
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['start'] == 1

    def test_raises_on_api_error(self, client):
        client._make_request = MagicMock(side_effect=Exception("Disk full"))
        with pytest.raises(Exception, match="Error creating VM on node pve1"):
            client.create_vm('pve1', 302, 'vm', 1, 512, 'local', 10)

    def test_includes_tags_and_description(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=303, name='vm', cores=1,
            memory_mb=512, storage='local', disk_gb=10,
            tags='web;prod', description='My test VM',
        )
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['tags'] == 'web;prod'
        assert kwargs['data']['description'] == 'My test VM'

    def test_cloud_init_adds_ide2_drive(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=304, name='vm', cores=1,
            memory_mb=512, storage='local-lvm', disk_gb=10,
            ciuser='ubuntu', cipassword='secret',
        )
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['ide2'] == 'local-lvm:cloudinit'
        assert kwargs['data']['ciuser'] == 'ubuntu'
        assert kwargs['data']['cipassword'] == 'secret'

    def test_no_ide2_without_cloud_init_fields(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=305, name='vm', cores=1,
            memory_mb=512, storage='local', disk_gb=10,
        )
        _, kwargs = client._make_request.call_args
        assert 'ide2' not in kwargs['data']

    def test_sshkeys_are_url_encoded(self, client):
        import urllib.parse
        raw_key = 'ssh-rsa AAAAB3NzaC1yc user@host'
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=306, name='vm', cores=1,
            memory_mb=512, storage='local', disk_gb=10,
            sshkeys=raw_key,
        )
        _, kwargs = client._make_request.call_args
        expected = urllib.parse.quote(raw_key.strip(), safe='')
        assert kwargs['data']['sshkeys'] == expected

    def test_ipconfig0_included_when_provided(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.create_vm(
            node='pve1', vmid=307, name='vm', cores=1,
            memory_mb=512, storage='local', disk_gb=10,
            ipconfig0='ip=dhcp',
        )
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['ipconfig0'] == 'ip=dhcp'
        assert 'ide2' in kwargs['data']  # auto-added because CI param present


# ---------------------------------------------------------------------------
# clone_vm
# ---------------------------------------------------------------------------

class TestCloneVm:
    def test_full_clone_with_all_options(self, client):
        client._make_request = MagicMock(return_value='UPID:pve1:clone-task')
        result = client.clone_vm(
            node='pve1', vmid=100, newid=400,
            name='my-clone', full=True, storage='local-lvm',
        )
        assert result == 'UPID:pve1:clone-task'
        client._make_request.assert_called_once_with(
            'POST', '/nodes/pve1/qemu/100/clone',
            data={
                'newid': 400,
                'full': 1,
                'name': 'my-clone',
                'storage': 'local-lvm',
            },
        )

    def test_linked_clone_omits_storage(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.clone_vm(node='pve1', vmid=100, newid=401, full=False)
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['full'] == 0
        assert 'storage' not in kwargs['data']

    def test_optional_name_omitted_when_none(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.clone_vm(node='pve1', vmid=100, newid=402)
        _, kwargs = client._make_request.call_args
        assert 'name' not in kwargs['data']

    def test_target_node_included_when_provided(self, client):
        client._make_request = MagicMock(return_value='UPID:task')
        client.clone_vm(node='pve1', vmid=100, newid=403, target_node='pve2')
        _, kwargs = client._make_request.call_args
        assert kwargs['data']['target'] == 'pve2'

    def test_raises_on_api_error(self, client):
        client._make_request = MagicMock(side_effect=Exception("Template locked"))
        with pytest.raises(Exception, match="Error cloning VM 100"):
            client.clone_vm('pve1', 100, 404)

    def test_applies_post_clone_config_with_ci_params(self, client):
        client._make_request = MagicMock(return_value='UPID:pve1:clone-task')
        client._wait_for_task = MagicMock()
        client.update_vm_config = MagicMock()
        client.clone_vm(
            node='pve1', vmid=100, newid=500,
            ciuser='ubuntu', description='My clone',
        )
        client._wait_for_task.assert_called_once_with('pve1', 'UPID:pve1:clone-task')
        client.update_vm_config.assert_called_once_with(
            'pve1', 500,
            {'ciuser': 'ubuntu', 'description': 'My clone'},
        )

    def test_no_post_config_without_optional_fields(self, client):
        client._make_request = MagicMock(return_value='UPID:pve1:clone-task')
        client._wait_for_task = MagicMock()
        client.update_vm_config = MagicMock()
        client.clone_vm(node='pve1', vmid=100, newid=501)
        client._wait_for_task.assert_not_called()
        client.update_vm_config.assert_not_called()

    def test_post_clone_uses_target_node_for_config(self, client):
        client._make_request = MagicMock(return_value='UPID:pve2:clone-task')
        client._wait_for_task = MagicMock()
        client.update_vm_config = MagicMock()
        client.clone_vm(
            node='pve1', vmid=100, newid=502,
            target_node='pve2', tags='web',
        )
        client._wait_for_task.assert_called_once_with('pve2', 'UPID:pve2:clone-task')
        client.update_vm_config.assert_called_once_with('pve2', 502, {'tags': 'web'})
