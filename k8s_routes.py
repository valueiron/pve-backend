"""
k8s_routes.py — Flask Blueprint proxying requests to the k8s-api service.

Prefix: /api/k8s
"""

from flask import Blueprint

import config
from proxy import proxy_request

k8s_bp = Blueprint('k8s', __name__)

_SVC = 'k8s-api'


def _p(path, method='GET'):
    return proxy_request(config.K8S_API_URL, path, _SVC, method)


# ── Pods ───────────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/pods')
def k8s_list_pods():
    return _p('pods')


@k8s_bp.get('/api/k8s/pods/<namespace>/<name>')
def k8s_get_pod(namespace, name):
    return _p(f'pods/{namespace}/{name}')


@k8s_bp.delete('/api/k8s/pods/<namespace>/<name>')
def k8s_delete_pod(namespace, name):
    return _p(f'pods/{namespace}/{name}', 'DELETE')


@k8s_bp.get('/api/k8s/pods/<namespace>/<name>/logs')
def k8s_pod_logs(namespace, name):
    return _p(f'pods/{namespace}/{name}/logs')


@k8s_bp.get('/api/k8s/pods/<namespace>/<name>/metrics')
def k8s_pod_metrics(namespace, name):
    return _p(f'pods/{namespace}/{name}/metrics')


@k8s_bp.post('/api/k8s/pods/<namespace>/<name>/restart')
def k8s_restart_pod(namespace, name):
    return _p(f'pods/{namespace}/{name}/restart', 'POST')


@k8s_bp.post('/api/k8s/pods/<namespace>/<name>/exec')
def k8s_exec_pod(namespace, name):
    return _p(f'pods/{namespace}/{name}/exec', 'POST')


# ── Deployments ────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/deployments')
def k8s_list_deployments():
    return _p('deployments')


@k8s_bp.post('/api/k8s/deployments')
def k8s_create_deployment():
    return _p('deployments', 'POST')


@k8s_bp.get('/api/k8s/deployments/<namespace>/<name>')
def k8s_get_deployment(namespace, name):
    return _p(f'deployments/{namespace}/{name}')


@k8s_bp.delete('/api/k8s/deployments/<namespace>/<name>')
def k8s_delete_deployment(namespace, name):
    return _p(f'deployments/{namespace}/{name}', 'DELETE')


@k8s_bp.post('/api/k8s/deployments/<namespace>/<name>/scale')
def k8s_scale_deployment(namespace, name):
    return _p(f'deployments/{namespace}/{name}/scale', 'POST')


@k8s_bp.post('/api/k8s/deployments/<namespace>/<name>/restart')
def k8s_restart_deployment(namespace, name):
    return _p(f'deployments/{namespace}/{name}/restart', 'POST')


# ── Services ───────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/services')
def k8s_list_services():
    return _p('services')


@k8s_bp.post('/api/k8s/services')
def k8s_create_service():
    return _p('services', 'POST')


@k8s_bp.get('/api/k8s/services/<namespace>/<name>')
def k8s_get_service(namespace, name):
    return _p(f'services/{namespace}/{name}')


@k8s_bp.delete('/api/k8s/services/<namespace>/<name>')
def k8s_delete_service(namespace, name):
    return _p(f'services/{namespace}/{name}', 'DELETE')


# ── Namespaces ─────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/namespaces')
def k8s_list_namespaces():
    return _p('namespaces')


@k8s_bp.post('/api/k8s/namespaces')
def k8s_create_namespace():
    return _p('namespaces', 'POST')


@k8s_bp.get('/api/k8s/namespaces/<name>')
def k8s_get_namespace(name):
    return _p(f'namespaces/{name}')


@k8s_bp.delete('/api/k8s/namespaces/<name>')
def k8s_delete_namespace(name):
    return _p(f'namespaces/{name}', 'DELETE')


# ── ConfigMaps ─────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/configmaps')
def k8s_list_configmaps():
    return _p('configmaps')


@k8s_bp.post('/api/k8s/configmaps')
def k8s_create_configmap():
    return _p('configmaps', 'POST')


@k8s_bp.get('/api/k8s/configmaps/<namespace>/<name>')
def k8s_get_configmap(namespace, name):
    return _p(f'configmaps/{namespace}/{name}')


@k8s_bp.delete('/api/k8s/configmaps/<namespace>/<name>')
def k8s_delete_configmap(namespace, name):
    return _p(f'configmaps/{namespace}/{name}', 'DELETE')


# ── PersistentVolumeClaims ─────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/pvcs')
def k8s_list_pvcs():
    return _p('pvcs')


@k8s_bp.post('/api/k8s/pvcs')
def k8s_create_pvc():
    return _p('pvcs', 'POST')


@k8s_bp.get('/api/k8s/pvcs/<namespace>/<name>')
def k8s_get_pvc(namespace, name):
    return _p(f'pvcs/{namespace}/{name}')


@k8s_bp.delete('/api/k8s/pvcs/<namespace>/<name>')
def k8s_delete_pvc(namespace, name):
    return _p(f'pvcs/{namespace}/{name}', 'DELETE')


# ── Nodes ──────────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/nodes')
def k8s_list_nodes():
    return _p('nodes')


@k8s_bp.get('/api/k8s/nodes/<name>')
def k8s_get_node(name):
    return _p(f'nodes/{name}')


# ── System ─────────────────────────────────────────────────────────────────────

@k8s_bp.get('/api/k8s/system/info')
def k8s_system_info():
    return _p('system/info')
