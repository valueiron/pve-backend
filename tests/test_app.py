"""
Integration tests for Flask API endpoints:
  - GET  /api/templates
  - POST /api/vms/clone
  - GET  /api/nextid
  - POST /api/vms  (create)
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def flask_app():
    """Return a Flask test client with Proxmox/Azure/AWS clients mocked."""
    env = {
        'PROXMOX_HOST': 'proxmox.test',
        'PROXMOX_TOKEN_ID': 'user@pam!mytoken',
        'PROXMOX_TOKEN_SECRET': 'supersecret',
    }
    with patch.dict(os.environ, env):
        with patch('proxmox_client.requests.Session'):
            with patch('urllib3.disable_warnings'):
                import app as flask_app_module
                flask_app_module.app.config['TESTING'] = True
                with flask_app_module.app.test_client() as client:
                    yield client, flask_app_module


@pytest.fixture
def mock_proxmox(flask_app):
    """Yield (test_client, mock_proxmox_client) for each test."""
    test_client, app_module = flask_app
    mock = MagicMock()
    with patch.object(app_module, 'get_proxmox_client', return_value=mock):
        yield test_client, mock


# ---------------------------------------------------------------------------
# GET /api/templates
# ---------------------------------------------------------------------------

class TestGetTemplates:
    def test_returns_template_list(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.get_templates.return_value = [
            {'vmid': 100, 'name': 'ubuntu-22', 'node': 'pve1'},
            {'vmid': 200, 'name': 'debian-12',  'node': 'pve1'},
        ]
        resp = client.get('/api/templates')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data['templates']) == 2
        assert data['templates'][0]['vmid'] == 100

    def test_returns_empty_list_when_no_templates(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.get_templates.return_value = []
        resp = client.get('/api/templates')
        assert resp.status_code == 200
        assert json.loads(resp.data) == {'templates': []}

    def test_returns_500_on_proxmox_error(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.get_templates.side_effect = Exception("Cluster unavailable")
        resp = client.get('/api/templates')
        assert resp.status_code == 500
        assert 'error' in json.loads(resp.data)


# ---------------------------------------------------------------------------
# POST /api/vms/clone
# ---------------------------------------------------------------------------

class TestCloneVm:
    def _payload(self, **overrides):
        base = {
            'node': 'pve1',
            'vmid': 100,
            'newid': 401,
            'name': 'cloned-vm',
            'full': True,
            'storage': 'local-lvm',
        }
        base.update(overrides)
        return base

    def test_successful_clone(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.clone_vm.return_value = 'UPID:pve1:clone-task'
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps(self._payload()),
            content_type='application/json',
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert '401' in data['message']
        proxmox.clone_vm.assert_called_once_with(
            node='pve1', vmid=100, newid=401,
            name='cloned-vm', full=True,
            storage='local-lvm', target_node=None,
            tags=None, description=None,
            ciuser=None, cipassword=None,
            sshkeys=None, ipconfig0=None,
        )

    def test_missing_node_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps({'vmid': 100, 'newid': 402}),
            content_type='application/json',
        )
        assert resp.status_code == 400
        assert 'node' in json.loads(resp.data)['error'].lower()

    def test_missing_vmid_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps({'node': 'pve1', 'newid': 402}),
            content_type='application/json',
        )
        assert resp.status_code == 400
        assert 'vm id' in json.loads(resp.data)['error'].lower()

    def test_missing_newid_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps({'node': 'pve1', 'vmid': 100}),
            content_type='application/json',
        )
        assert resp.status_code == 400
        assert 'new vm id' in json.loads(resp.data)['error'].lower()

    def test_empty_body_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        resp = client.post('/api/vms/clone', content_type='application/json')
        assert resp.status_code == 400

    def test_proxmox_error_returns_500(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.clone_vm.side_effect = Exception("Template locked")
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps(self._payload()),
            content_type='application/json',
        )
        assert resp.status_code == 500
        assert 'error' in json.loads(resp.data)

    def test_clone_without_storage(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.clone_vm.return_value = 'UPID:task'
        payload = {'node': 'pve1', 'vmid': 100, 'newid': 403, 'full': False}
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert resp.status_code == 201
        proxmox.clone_vm.assert_called_once_with(
            node='pve1', vmid=100, newid=403,
            name=None, full=False,
            storage=None, target_node=None,
            tags=None, description=None,
            ciuser=None, cipassword=None,
            sshkeys=None, ipconfig0=None,
        )

    def test_clone_with_ci_and_tags(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.clone_vm.return_value = 'UPID:task'
        payload = {
            'node': 'pve1', 'vmid': 100, 'newid': 404,
            'tags': 'web;prod', 'description': 'My clone',
            'ciuser': 'ubuntu', 'cipassword': 's3cr3t',
            'sshkeys': 'ssh-rsa AAAA user@host',
            'ipconfig0': 'ip=dhcp',
        }
        resp = client.post(
            '/api/vms/clone',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert resp.status_code == 201
        proxmox.clone_vm.assert_called_once_with(
            node='pve1', vmid=100, newid=404,
            name=None, full=True,
            storage=None, target_node=None,
            tags='web;prod', description='My clone',
            ciuser='ubuntu', cipassword='s3cr3t',
            sshkeys='ssh-rsa AAAA user@host',
            ipconfig0='ip=dhcp',
        )


# ---------------------------------------------------------------------------
# GET /api/nextid
# ---------------------------------------------------------------------------

class TestGetNextVmid:
    def test_returns_next_vmid(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.get_next_vmid.return_value = 150
        resp = client.get('/api/nextid')
        assert resp.status_code == 200
        assert json.loads(resp.data) == {'vmid': 150}

    def test_returns_500_on_error(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.get_next_vmid.side_effect = Exception("Cluster error")
        resp = client.get('/api/nextid')
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /api/vms  (create)
# ---------------------------------------------------------------------------

class TestCreateVm:
    def _payload(self, **overrides):
        base = {
            'node': 'pve1',
            'vmid': 300,
            'name': 'test-vm',
            'cores': 2,
            'memory': 2048,
            'storage': 'local-lvm',
            'disk_gb': 20,
            'start': False,
        }
        base.update(overrides)
        return base

    def test_successful_create(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.create_vm.return_value = 'UPID:pve1:create-task'
        resp = client.post(
            '/api/vms',
            data=json.dumps(self._payload()),
            content_type='application/json',
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert '300' in data['message']
        proxmox.create_vm.assert_called_once_with(
            node='pve1', vmid=300, name='test-vm',
            cores=2, memory_mb=2048, storage='local-lvm',
            disk_gb=20, start=False,
            tags=None, description=None,
            ciuser=None, cipassword=None,
            sshkeys=None, ipconfig0=None,
        )

    def test_create_with_ci_and_tags(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.create_vm.return_value = 'UPID:pve1:create-task'
        payload = self._payload(
            tags='web;prod', description='My VM',
            ciuser='ubuntu', cipassword='s3cr3t',
            sshkeys='ssh-rsa AAAA user@host',
            ipconfig0='ip=192.168.1.10/24,gw=192.168.1.1',
        )
        resp = client.post(
            '/api/vms',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert resp.status_code == 201
        proxmox.create_vm.assert_called_once_with(
            node='pve1', vmid=300, name='test-vm',
            cores=2, memory_mb=2048, storage='local-lvm',
            disk_gb=20, start=False,
            tags='web;prod', description='My VM',
            ciuser='ubuntu', cipassword='s3cr3t',
            sshkeys='ssh-rsa AAAA user@host',
            ipconfig0='ip=192.168.1.10/24,gw=192.168.1.1',
        )

    def test_missing_node_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        payload = self._payload()
        del payload['node']
        resp = client.post('/api/vms', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 400

    def test_missing_storage_returns_400(self, mock_proxmox):
        client, proxmox = mock_proxmox
        payload = self._payload()
        del payload['storage']
        resp = client.post('/api/vms', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 400

    def test_proxmox_error_returns_500(self, mock_proxmox):
        client, proxmox = mock_proxmox
        proxmox.create_vm.side_effect = Exception("Storage full")
        resp = client.post(
            '/api/vms',
            data=json.dumps(self._payload()),
            content_type='application/json',
        )
        assert resp.status_code == 500
