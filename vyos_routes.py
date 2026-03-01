"""
vyos_routes.py — Flask Blueprint proxying requests to the vyos-api service.

Prefix: /api/vyos
"""

from flask import Blueprint

import config
from proxy import proxy_request

vyos_bp = Blueprint('vyos', __name__)

_SVC = 'vyos-api'


def _p(path, method='GET'):
    return proxy_request(config.VYOS_API_URL, path, _SVC, method)


# ── Devices ────────────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/devices')
def vyos_list_devices():
    return _p('devices')


# ── Networks (interfaces) ──────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/networks')
def vyos_list_networks(device_id):
    return _p(f'devices/{device_id}/networks')


@vyos_bp.post('/api/vyos/<device_id>/networks')
def vyos_create_network(device_id):
    return _p(f'devices/{device_id}/networks', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/networks/<interface>')
def vyos_get_network(device_id, interface):
    return _p(f'devices/{device_id}/networks/{interface}')


@vyos_bp.put('/api/vyos/<device_id>/networks/<interface>')
def vyos_update_network(device_id, interface):
    return _p(f'devices/{device_id}/networks/{interface}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/networks/<interface>')
def vyos_delete_network(device_id, interface):
    return _p(f'devices/{device_id}/networks/{interface}', 'DELETE')


# ── VRFs ───────────────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/vrfs')
def vyos_list_vrfs(device_id):
    return _p(f'devices/{device_id}/vrfs')


@vyos_bp.post('/api/vyos/<device_id>/vrfs')
def vyos_create_vrf(device_id):
    return _p(f'devices/{device_id}/vrfs', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/vrfs/<vrf>')
def vyos_get_vrf(device_id, vrf):
    return _p(f'devices/{device_id}/vrfs/{vrf}')


@vyos_bp.put('/api/vyos/<device_id>/vrfs/<vrf>')
def vyos_update_vrf(device_id, vrf):
    return _p(f'devices/{device_id}/vrfs/{vrf}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/vrfs/<vrf>')
def vyos_delete_vrf(device_id, vrf):
    return _p(f'devices/{device_id}/vrfs/{vrf}', 'DELETE')


# ── VLANs ──────────────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/vlans')
def vyos_list_vlans(device_id):
    return _p(f'devices/{device_id}/vlans')


@vyos_bp.post('/api/vyos/<device_id>/vlans')
def vyos_create_vlan(device_id):
    return _p(f'devices/{device_id}/vlans', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>')
def vyos_get_vlan(device_id, interface, vlan_id):
    return _p(f'devices/{device_id}/vlans/{interface}/{vlan_id}')


@vyos_bp.put('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>')
def vyos_update_vlan(device_id, interface, vlan_id):
    return _p(f'devices/{device_id}/vlans/{interface}/{vlan_id}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>')
def vyos_delete_vlan(device_id, interface, vlan_id):
    return _p(f'devices/{device_id}/vlans/{interface}/{vlan_id}', 'DELETE')


# ── Firewall Policies ──────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/firewall/policies')
def vyos_list_policies(device_id):
    return _p(f'devices/{device_id}/firewall/policies')


@vyos_bp.post('/api/vyos/<device_id>/firewall/policies')
def vyos_create_policy(device_id):
    return _p(f'devices/{device_id}/firewall/policies', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/firewall/policies/<policy>')
def vyos_get_policy(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}')


@vyos_bp.put('/api/vyos/<device_id>/firewall/policies/<policy>')
def vyos_update_policy(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/firewall/policies/<policy>')
def vyos_delete_policy(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}', 'DELETE')


@vyos_bp.post('/api/vyos/<device_id>/firewall/policies/<policy>/rules')
def vyos_add_rule(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/rules', 'POST')


@vyos_bp.delete('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>')
def vyos_delete_rule(device_id, policy, rule_id):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}', 'DELETE')


@vyos_bp.put('/api/vyos/<device_id>/firewall/policies/<policy>/disable')
def vyos_disable_policy(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/disable', 'PUT')


@vyos_bp.put('/api/vyos/<device_id>/firewall/policies/<policy>/enable')
def vyos_enable_policy(device_id, policy):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/enable', 'PUT')


@vyos_bp.put('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>/disable')
def vyos_disable_rule(device_id, policy, rule_id):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}/disable', 'PUT')


@vyos_bp.put('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>/enable')
def vyos_enable_rule(device_id, policy, rule_id):
    return _p(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}/enable', 'PUT')


# ── Firewall Address Groups ────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/firewall/address-groups')
def vyos_list_address_groups(device_id):
    return _p(f'devices/{device_id}/firewall/address-groups')


@vyos_bp.post('/api/vyos/<device_id>/firewall/address-groups')
def vyos_create_address_group(device_id):
    return _p(f'devices/{device_id}/firewall/address-groups', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/firewall/address-groups/<group>')
def vyos_get_address_group(device_id, group):
    return _p(f'devices/{device_id}/firewall/address-groups/{group}')


@vyos_bp.put('/api/vyos/<device_id>/firewall/address-groups/<group>')
def vyos_update_address_group(device_id, group):
    return _p(f'devices/{device_id}/firewall/address-groups/{group}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/firewall/address-groups/<group>')
def vyos_delete_address_group(device_id, group):
    return _p(f'devices/{device_id}/firewall/address-groups/{group}', 'DELETE')


# ── NAT rules ──────────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/nat/<nat_type>/rules')
def vyos_list_nat_rules(device_id, nat_type):
    return _p(f'devices/{device_id}/nat/{nat_type}/rules')


@vyos_bp.post('/api/vyos/<device_id>/nat/<nat_type>/rules')
def vyos_create_nat_rule(device_id, nat_type):
    return _p(f'devices/{device_id}/nat/{nat_type}/rules', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>')
def vyos_get_nat_rule(device_id, nat_type, rule_id):
    return _p(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}')


@vyos_bp.put('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>')
def vyos_update_nat_rule(device_id, nat_type, rule_id):
    return _p(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>')
def vyos_delete_nat_rule(device_id, nat_type, rule_id):
    return _p(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}', 'DELETE')


# ── Static routes ──────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/routes')
def vyos_list_routes(device_id):
    return _p(f'devices/{device_id}/routes')


@vyos_bp.post('/api/vyos/<device_id>/routes')
def vyos_create_route(device_id):
    return _p(f'devices/{device_id}/routes', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/routes/<prefix>/<mask>')
def vyos_get_route(device_id, prefix, mask):
    return _p(f'devices/{device_id}/routes/{prefix}/{mask}')


@vyos_bp.put('/api/vyos/<device_id>/routes/<prefix>/<mask>')
def vyos_update_route(device_id, prefix, mask):
    return _p(f'devices/{device_id}/routes/{prefix}/{mask}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/routes/<prefix>/<mask>')
def vyos_delete_route(device_id, prefix, mask):
    return _p(f'devices/{device_id}/routes/{prefix}/{mask}', 'DELETE')


# ── DHCP servers ───────────────────────────────────────────────────────────────

@vyos_bp.get('/api/vyos/<device_id>/dhcp/servers')
def vyos_list_dhcp_servers(device_id):
    return _p(f'devices/{device_id}/dhcp/servers')


@vyos_bp.post('/api/vyos/<device_id>/dhcp/servers')
def vyos_create_dhcp_server(device_id):
    return _p(f'devices/{device_id}/dhcp/servers', 'POST')


@vyos_bp.get('/api/vyos/<device_id>/dhcp/servers/<name>')
def vyos_get_dhcp_server(device_id, name):
    return _p(f'devices/{device_id}/dhcp/servers/{name}')


@vyos_bp.put('/api/vyos/<device_id>/dhcp/servers/<name>')
def vyos_update_dhcp_server(device_id, name):
    return _p(f'devices/{device_id}/dhcp/servers/{name}', 'PUT')


@vyos_bp.delete('/api/vyos/<device_id>/dhcp/servers/<name>')
def vyos_delete_dhcp_server(device_id, name):
    return _p(f'devices/{device_id}/dhcp/servers/{name}', 'DELETE')
