"""
docker_routes.py — Flask Blueprint proxying requests to the docker-api service.

Prefix: /api/docker
"""

from flask import Blueprint

import config
from proxy import proxy_request

docker_bp = Blueprint('docker', __name__)

_SVC = 'docker-api'


def _p(path, method='GET'):
    return proxy_request(config.DOCKER_API_URL, path, _SVC, method)


@docker_bp.get('/api/docker/containers')
def docker_list_containers():
    return _p('containers')


@docker_bp.post('/api/docker/containers/<container_id>/start')
def docker_start_container(container_id):
    return _p(f'containers/start/{container_id}', 'POST')


@docker_bp.post('/api/docker/containers/<container_id>/stop')
def docker_stop_container(container_id):
    return _p(f'containers/stop/{container_id}', 'POST')


@docker_bp.post('/api/docker/containers/<container_id>/restart')
def docker_restart_container(container_id):
    return _p(f'containers/restart/{container_id}', 'POST')


@docker_bp.get('/api/docker/containers/<container_id>/logs')
def docker_container_logs(container_id):
    return _p(f'containers/{container_id}/logs')


@docker_bp.get('/api/docker/containers/<container_id>/metrics')
def docker_container_metrics(container_id):
    return _p(f'containers/{container_id}/metrics')


@docker_bp.post('/api/docker/containers/<container_id>/exec')
def docker_container_exec_session(container_id):
    return _p(f'containers/{container_id}/exec', 'POST')


@docker_bp.get('/api/docker/containers/<container_id>')
def docker_inspect_container(container_id):
    return _p(f'containers/{container_id}')


@docker_bp.get('/api/docker/images')
def docker_list_images():
    return _p('images')


@docker_bp.get('/api/docker/images/<path:image_id>')
def docker_inspect_image(image_id):
    return _p(f'images/{image_id}')


@docker_bp.get('/api/docker/volumes')
def docker_list_volumes():
    return _p('volumes')


@docker_bp.get('/api/docker/volumes/<vol_name>')
def docker_inspect_volume(vol_name):
    return _p(f'volumes/{vol_name}')


@docker_bp.get('/api/docker/networks')
def docker_list_networks():
    return _p('networks')


@docker_bp.get('/api/docker/networks/<net_id>')
def docker_inspect_network(net_id):
    return _p(f'networks/{net_id}')


@docker_bp.get('/api/docker/system/info')
def docker_system_info():
    return _p('system/info')


@docker_bp.get('/api/docker/system/disk')
def docker_system_disk():
    return _p('system/disk')


@docker_bp.get('/api/docker/vulnerabilities/status')
def docker_vuln_status():
    return _p('vulnerabilities/status')


@docker_bp.post('/api/docker/vulnerabilities/download')
def docker_vuln_download():
    return _p('vulnerabilities/download', 'POST')


@docker_bp.post('/api/docker/vulnerabilities/scan')
def docker_vuln_scan():
    return proxy_request(config.DOCKER_API_URL, 'vulnerabilities/scan', _SVC, 'POST', timeout=300)
