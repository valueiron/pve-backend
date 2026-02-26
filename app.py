from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time
import sys
import ssl
import asyncio
import threading
import urllib.parse
import websocket as ws_client
import websockets
import requests as http_requests
import os
from proxmox_client import get_proxmox_client

# Docker API base URL - set via DOCKER_API_URL env var (default for local dev)
DOCKER_API_URL = os.getenv('DOCKER_API_URL', 'http://localhost:8080')

# Kubernetes API base URL - set via K8S_API_URL env var (default for local dev)
K8S_API_URL = os.getenv('K8S_API_URL', 'http://localhost:8081')

# VyOS API base URL - set via VYOS_API_URL env var (default for local dev)
VYOS_API_URL = os.getenv('VYOS_API_URL', 'http://localhost:8082')

# Import Azure client with error handling
try:
    from azure_client import get_azure_client
    AZURE_AVAILABLE = True
    import sys
    sys.stderr.write("[App] Azure client module imported successfully\n")
    sys.stderr.flush()
except ImportError as e:
    AZURE_AVAILABLE = False
    import sys
    sys.stderr.write(f"[App] WARNING: Azure client module not available: {str(e)}\n")
    sys.stderr.write("[App] Azure features will be disabled. Install azure-identity, azure-mgmt-compute, azure-mgmt-resource\n")
    sys.stderr.flush()
    def get_azure_client():
        return None
except Exception as e:
    AZURE_AVAILABLE = False
    import sys
    sys.stderr.write(f"[App] WARNING: Error importing Azure client: {str(e)}\n")
    sys.stderr.flush()
    def get_azure_client():
        return None

# Import AWS client with error handling
try:
    from aws_client import get_aws_client
    AWS_AVAILABLE = True
    import sys
    sys.stderr.write("[App] AWS client module imported successfully\n")
    sys.stderr.flush()
except ImportError as e:
    AWS_AVAILABLE = False
    import sys
    sys.stderr.write(f"[App] WARNING: AWS client module not available: {str(e)}\n")
    sys.stderr.write("[App] AWS features will be disabled. Install boto3\n")
    sys.stderr.flush()
    def get_aws_client():
        return None
except Exception as e:
    AWS_AVAILABLE = False
    import sys
    sys.stderr.write(f"[App] WARNING: Error importing AWS client: {str(e)}\n")
    sys.stderr.flush()
    def get_aws_client():
        return None

app = Flask(__name__)
# Enable CORS for all routes to allow pve-portal frontend to make requests
# Allow requests from any origin (you can restrict this in production)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register labs blueprint
from labs_routes import labs_bp
app.register_blueprint(labs_bp)

# --- Prometheus metrics ---
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
APP_HEALTH = Gauge('app_health_status', 'Health status of the Flask app (1=healthy, 0=unhealthy)')
APP_READY = Gauge('app_ready_status', 'Readiness status of the Flask app (1=ready, 0=not ready)')
APP_START_TIME = Gauge('app_start_time_seconds', 'Application start time in seconds since epoch')

# Record when the app started
APP_START_TIME.set(time.time())
APP_HEALTH.set(1)
APP_READY.set(1)

# --- Routes ---
@app.before_request
def before_request():
    # Track request metrics with actual endpoint
    endpoint = request.path
    method = request.method
    REQUEST_COUNT.labels(method=method, endpoint=endpoint).inc()

@app.route('/')
def home():
    return jsonify(status="ok", message="Flask backend is running")

@app.route('/health')
def health():
    return jsonify(status="healthy"), 200

@app.route('/ready')
def ready():
    return jsonify(status="ready"), 200

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

# --- Proxmox API Routes ---

@app.route('/api/vms')
def get_vms():
    """Get list of all VMs across all nodes (Proxmox, Azure, and AWS)"""
    import sys
    sys.stderr.flush()
    sys.stdout.flush()
    
    try:
        all_vms = []
        
        # Fetch Proxmox VMs
        try:
            proxmox = get_proxmox_client()
            proxmox_vms = proxmox.get_all_vms()
            # Add type field to Proxmox VMs
            for vm in proxmox_vms:
                vm['type'] = 'proxmox'
            all_vms.extend(proxmox_vms)
            sys.stderr.write(f"[VM API] Fetched {len(proxmox_vms)} Proxmox VMs\n")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"[VM API] Warning: Failed to fetch Proxmox VMs: {str(e)}\n")
            sys.stderr.flush()
            # Continue even if Proxmox fails
        
        # Fetch Azure VMs
        sys.stderr.write(f"[VM API] Attempting to fetch Azure VMs (Azure available: {AZURE_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            sys.stderr.write("[VM API] Calling get_azure_client()...\n")
            sys.stderr.flush()
            azure = get_azure_client()
            sys.stderr.write(f"[VM API] get_azure_client() returned: {azure is not None}\n")
            sys.stderr.flush()
            
            if azure:
                sys.stderr.write("[VM API] Azure client is available, fetching VMs...\n")
                sys.stderr.flush()
                azure_vms = azure.get_all_vms()
                # Type field already added in azure_client
                all_vms.extend(azure_vms)
                sys.stderr.write(f"[VM API] Successfully fetched {len(azure_vms)} Azure VMs\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[VM API] Azure client not available - credentials may not be configured\n")
                sys.stderr.write("[VM API] Check /api/azure/status endpoint for diagnostic information\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[VM API] Error: Failed to fetch Azure VMs: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
            # Continue even if Azure fails
        
        # Fetch AWS EC2 instances
        sys.stderr.write(f"[VM API] Attempting to fetch AWS instances (AWS available: {AWS_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            sys.stderr.write("[VM API] Calling get_aws_client()...\n")
            sys.stderr.flush()
            aws = get_aws_client()
            sys.stderr.write(f"[VM API] get_aws_client() returned: {aws is not None}\n")
            sys.stderr.flush()
            
            if aws:
                sys.stderr.write("[VM API] AWS client is available, fetching instances...\n")
                sys.stderr.flush()
                aws_vms = aws.get_all_vms()
                # Type field already added in aws_client
                all_vms.extend(aws_vms)
                sys.stderr.write(f"[VM API] Successfully fetched {len(aws_vms)} AWS instances\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[VM API] AWS client not available - credentials may not be configured\n")
                sys.stderr.write("[VM API] Check /api/aws/status endpoint for diagnostic information\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[VM API] Error: Failed to fetch AWS instances: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
            # Continue even if AWS fails
        
        proxmox_count = len([v for v in all_vms if v.get('type') == 'proxmox'])
        azure_count = len([v for v in all_vms if v.get('type') == 'azure'])
        aws_count = len([v for v in all_vms if v.get('type') == 'aws'])
        sys.stderr.write(f"[VM API] Returning {len(all_vms)} total VMs ({proxmox_count} Proxmox, {azure_count} Azure, {aws_count} AWS)\n")
        sys.stderr.flush()
        return jsonify({"vms": all_vms}), 200
    except Exception as e:
        import sys
        import traceback
        sys.stderr.write(f"[VM API] Fatal error: {str(e)}\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        return jsonify({"error": f"Failed to fetch VMs: {str(e)}"}), 500

@app.route('/api/vms/<vmid>')
def get_vm_details(vmid):
    """Get detailed information about a specific VM (Proxmox, Azure, or AWS)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            vm_details = azure.get_vm_details(vmid)
            return jsonify(vm_details), 200
        # Check if this is an AWS instance (starts with 'aws-')
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            vm_details = aws.get_vm_details(vmid)
            return jsonify(vm_details), 200
        else:
            # Proxmox VM (numeric ID)
            try:
                vmid_int = int(vmid)
            except ValueError:
                return jsonify({"error": f"Invalid VM ID: {vmid}"}), 400
            
            proxmox = get_proxmox_client()
            vm_details = proxmox.get_vm_details(vmid_int)
            vm_details['type'] = 'proxmox'
            return jsonify(vm_details), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to fetch VM details: {str(e)}"}), 500

@app.route('/api/nodes')
def get_nodes():
    """Get list of all Proxmox nodes"""
    try:
        proxmox = get_proxmox_client()
        nodes = proxmox.get_nodes()
        return jsonify({"nodes": nodes}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch nodes: {str(e)}"}), 500

@app.route('/api/azure/status')
def azure_status():
    """Diagnostic endpoint to check Azure client status"""
    try:
        import os
        from azure_client import get_azure_client
        
        # Check environment variables
        env_status = {
            'AZURE_CLIENT_ID': 'SET' if os.getenv('AZURE_CLIENT_ID') else 'NOT SET',
            'AZURE_CLIENT_SECRET': 'SET' if os.getenv('AZURE_CLIENT_SECRET') else 'NOT SET',
            'AZURE_TENANT_ID': 'SET' if os.getenv('AZURE_TENANT_ID') else 'NOT SET',
            'AZURE_SUBSCRIPTION_ID': os.getenv('AZURE_SUBSCRIPTION_ID') or 'NOT SET (will search all subscriptions)'
        }
        
        # Try to get Azure client
        azure = get_azure_client()
        if azure:
            # Try to list subscriptions as a test
            try:
                if azure.subscription_id:
                    subscriptions = [azure.subscription_id]
                else:
                    subscription_list = azure.resource_client.subscriptions.list()
                    subscriptions = [sub.subscription_id for sub in subscription_list]
                
                return jsonify({
                    "status": "connected",
                    "message": "Azure client is initialized and working",
                    "environment_variables": env_status,
                    "subscriptions_found": len(subscriptions),
                    "subscriptions": subscriptions[:5]  # Limit to first 5 for security
                }), 200
            except Exception as e:
                import traceback
                return jsonify({
                    "status": "error",
                    "message": f"Azure client initialized but failed to list subscriptions: {str(e)}",
                    "environment_variables": env_status,
                    "error_details": str(e),
                    "traceback": traceback.format_exc()
                }), 200
        else:
            return jsonify({
                "status": "not_configured",
                "message": "Azure client is not available - credentials may be missing or invalid",
                "environment_variables": env_status
            }), 200
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "message": f"Error checking Azure status: {str(e)}",
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/aws/status')
def aws_status():
    """Diagnostic endpoint to check AWS client status"""
    try:
        import os
        from aws_client import get_aws_client
        
        # Check environment variables
        env_status = {
            'AWS_ACCESS_KEY_ID': 'SET' if os.getenv('AWS_ACCESS_KEY_ID') else 'NOT SET',
            'AWS_SECRET_ACCESS_KEY': 'SET' if os.getenv('AWS_SECRET_ACCESS_KEY') else 'NOT SET',
            'AWS_REGION': os.getenv('AWS_REGION') or 'NOT SET (will search all regions)',
            'AWS_SESSION_TOKEN': 'SET' if os.getenv('AWS_SESSION_TOKEN') else 'NOT SET (optional)'
        }
        
        # Try to get AWS client
        aws = get_aws_client()
        if aws:
            # Try to list regions as a test
            try:
                regions = aws._get_all_regions()
                
                return jsonify({
                    "status": "connected",
                    "message": "AWS client is initialized and working",
                    "environment_variables": env_status,
                    "regions_available": len(regions),
                    "regions": regions[:10]  # Limit to first 10
                }), 200
            except Exception as e:
                import traceback
                return jsonify({
                    "status": "error",
                    "message": f"AWS client initialized but failed to list regions: {str(e)}",
                    "environment_variables": env_status,
                    "error_details": str(e),
                    "traceback": traceback.format_exc()
                }), 200
        else:
            return jsonify({
                "status": "not_configured",
                "message": "AWS client is not available - credentials may be missing or invalid",
                "environment_variables": env_status
            }), 200
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "message": f"Error checking AWS status: {str(e)}",
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/vms/<vmid>/start', methods=['POST'])
def start_vm(vmid):
    """Start a virtual machine (Proxmox, Azure, or AWS)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            result = azure.start_vm(vmid)
            return jsonify({"message": f"VM {vmid} started successfully", "data": result}), 200
        # Check if this is an AWS instance (starts with 'aws-')
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            result = aws.start_vm(vmid)
            return jsonify({"message": f"VM {vmid} started successfully", "data": result}), 200
        else:
            # Proxmox VM (numeric ID)
            try:
                vmid_int = int(vmid)
            except ValueError:
                return jsonify({"error": f"Invalid VM ID: {vmid}"}), 400
            
            proxmox = get_proxmox_client()
            result = proxmox.start_vm(vmid_int)
            return jsonify({"message": f"VM {vmid} started successfully", "data": result}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to start VM {vmid}: {str(e)}"}), 500

@app.route('/api/vms/<vmid>/shutdown', methods=['POST'])
def shutdown_vm(vmid):
    """Shutdown a virtual machine gracefully (Proxmox, Azure, or AWS)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            result = azure.stop_vm(vmid)
            return jsonify({"message": f"VM {vmid} shutdown initiated", "data": result}), 200
        # Check if this is an AWS instance (starts with 'aws-')
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            result = aws.stop_vm(vmid)
            return jsonify({"message": f"VM {vmid} shutdown initiated", "data": result}), 200
        else:
            # Proxmox VM (numeric ID)
            try:
                vmid_int = int(vmid)
            except ValueError:
                return jsonify({"error": f"Invalid VM ID: {vmid}"}), 400
            
            proxmox = get_proxmox_client()
            result = proxmox.shutdown_vm(vmid_int)
            return jsonify({"message": f"VM {vmid} shutdown initiated", "data": result}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to shutdown VM {vmid}: {str(e)}"}), 500

@app.route('/api/networking')
def get_networking():
    """Get list of all networking resources (Azure and AWS)"""
    import sys
    sys.stderr.flush()
    sys.stdout.flush()
    
    try:
        all_resources = {
            'vnets': [],
            'subnets': [],
            'nsgs': [],
            'public_ips': [],
            'vpcs': [],
            'security_groups': [],
            'elastic_ips': []
        }
        
        # Fetch Azure networking resources
        sys.stderr.write(f"[Networking API] Attempting to fetch Azure networking (Azure available: {AZURE_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            azure = get_azure_client()
            if azure:
                sys.stderr.write("[Networking API] Azure client is available, fetching networking resources...\n")
                sys.stderr.flush()
                azure_networking = azure.get_all_networking()
                all_resources['vnets'].extend(azure_networking.get('vnets', []))
                all_resources['subnets'].extend(azure_networking.get('subnets', []))
                all_resources['nsgs'].extend(azure_networking.get('nsgs', []))
                all_resources['public_ips'].extend(azure_networking.get('public_ips', []))
                sys.stderr.write(f"[Networking API] Successfully fetched Azure networking resources\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[Networking API] Azure client not available\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[Networking API] Error: Failed to fetch Azure networking: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
        
        # Fetch AWS networking resources
        sys.stderr.write(f"[Networking API] Attempting to fetch AWS networking (AWS available: {AWS_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            aws = get_aws_client()
            if aws:
                sys.stderr.write("[Networking API] AWS client is available, fetching networking resources...\n")
                sys.stderr.flush()
                aws_networking = aws.get_all_networking()
                all_resources['vpcs'].extend(aws_networking.get('vpcs', []))
                all_resources['subnets'].extend(aws_networking.get('subnets', []))
                all_resources['security_groups'].extend(aws_networking.get('security_groups', []))
                all_resources['elastic_ips'].extend(aws_networking.get('elastic_ips', []))
                sys.stderr.write(f"[Networking API] Successfully fetched AWS networking resources\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[Networking API] AWS client not available\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[Networking API] Error: Failed to fetch AWS networking: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
        
        total_count = (
            len(all_resources['vnets']) + len(all_resources['subnets']) + 
            len(all_resources['nsgs']) + len(all_resources['public_ips']) +
            len(all_resources['vpcs']) + len(all_resources['security_groups']) + 
            len(all_resources['elastic_ips'])
        )
        sys.stderr.write(f"[Networking API] Returning {total_count} total networking resources\n")
        sys.stderr.flush()
        return jsonify(all_resources), 200
    except Exception as e:
        import sys
        import traceback
        sys.stderr.write(f"[Networking API] Fatal error: {str(e)}\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        return jsonify({"error": f"Failed to fetch networking resources: {str(e)}"}), 500

@app.route('/api/storage')
def get_storage():
    """Get list of all storage resources (Proxmox, Azure, and AWS)"""
    import sys
    sys.stderr.flush()
    sys.stdout.flush()
    
    try:
        all_resources = {
            'storage_accounts': [],
            'containers': [],
            'buckets': [],
            'storages': []
        }
        
        # Fetch Proxmox storage resources
        sys.stderr.write("[Storage API] Attempting to fetch Proxmox storage...\n")
        sys.stderr.flush()
        try:
            proxmox = get_proxmox_client()
            proxmox_storage = proxmox.get_all_storage()
            all_resources['storages'].extend(proxmox_storage.get('storages', []))
            sys.stderr.write(f"[Storage API] Successfully fetched {len(proxmox_storage.get('storages', []))} Proxmox storage resources\n")
            sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[Storage API] Error: Failed to fetch Proxmox storage: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
            # Continue even if Proxmox fails
        
        # Fetch Azure storage resources
        sys.stderr.write(f"[Storage API] Attempting to fetch Azure storage (Azure available: {AZURE_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            azure = get_azure_client()
            if azure:
                sys.stderr.write("[Storage API] Azure client is available, fetching storage resources...\n")
                sys.stderr.flush()
                azure_storage = azure.get_all_storage()
                all_resources['storage_accounts'].extend(azure_storage.get('storage_accounts', []))
                all_resources['containers'].extend(azure_storage.get('containers', []))
                sys.stderr.write(f"[Storage API] Successfully fetched Azure storage resources\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[Storage API] Azure client not available\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[Storage API] Error: Failed to fetch Azure storage: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
        
        # Fetch AWS storage resources
        sys.stderr.write(f"[Storage API] Attempting to fetch AWS storage (AWS available: {AWS_AVAILABLE})...\n")
        sys.stderr.flush()
        try:
            aws = get_aws_client()
            if aws:
                sys.stderr.write("[Storage API] AWS client is available, fetching storage resources...\n")
                sys.stderr.flush()
                aws_storage = aws.get_all_storage()
                all_resources['buckets'].extend(aws_storage.get('buckets', []))
                sys.stderr.write(f"[Storage API] Successfully fetched AWS storage resources\n")
                sys.stderr.flush()
            else:
                sys.stderr.write("[Storage API] AWS client not available\n")
                sys.stderr.flush()
        except Exception as e:
            import traceback
            error_msg = f"[Storage API] Error: Failed to fetch AWS storage: {str(e)}"
            traceback_str = traceback.format_exc()
            sys.stderr.write(f"{error_msg}\n{traceback_str}\n")
            sys.stderr.flush()
        
        total_count = (
            len(all_resources['storage_accounts']) + len(all_resources['containers']) + 
            len(all_resources['buckets']) + len(all_resources['storages'])
        )
        sys.stderr.write(f"[Storage API] Returning {total_count} total storage resources ({len(all_resources['storage_accounts'])} Storage Accounts, {len(all_resources['containers'])} Containers, {len(all_resources['buckets'])} Buckets, {len(all_resources['storages'])} Proxmox Storages)\n")
        sys.stderr.flush()
        return jsonify(all_resources), 200
    except Exception as e:
        import sys
        import traceback
        sys.stderr.write(f"[Storage API] Fatal error: {str(e)}\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        return jsonify({"error": f"Failed to fetch storage resources: {str(e)}"}), 500

def _docker_proxy(path, method='GET', **kwargs):
    """Forward a request to the docker-api service and return a Flask response."""
    url = f"{DOCKER_API_URL}/{path.lstrip('/')}"
    try:
        resp = http_requests.request(
            method,
            url,
            params=request.args,
            json=request.get_json(silent=True),
            timeout=30,
            **kwargs
        )
        content_type = resp.headers.get('Content-Type', 'application/json')
        return Response(resp.content, status=resp.status_code, content_type=content_type)
    except http_requests.exceptions.ConnectionError:
        return jsonify({"error": "docker-api service is not reachable"}), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "docker-api request timed out"}), 504
    except Exception as e:
        sys.stderr.write(f"[Docker API] Error proxying to {url}: {str(e)}\n")
        sys.stderr.flush()
        return jsonify({"error": f"Docker API error: {str(e)}"}), 500


@app.route('/api/docker/containers')
def docker_list_containers():
    return _docker_proxy('containers')


@app.route('/api/docker/containers/<container_id>/start', methods=['POST'])
def docker_start_container(container_id):
    return _docker_proxy(f'containers/start/{container_id}', method='POST')


@app.route('/api/docker/containers/<container_id>/stop', methods=['POST'])
def docker_stop_container(container_id):
    return _docker_proxy(f'containers/stop/{container_id}', method='POST')


@app.route('/api/docker/containers/<container_id>/restart', methods=['POST'])
def docker_restart_container(container_id):
    return _docker_proxy(f'containers/restart/{container_id}', method='POST')


@app.route('/api/docker/containers/<container_id>/logs')
def docker_container_logs(container_id):
    return _docker_proxy(f'containers/{container_id}/logs')


@app.route('/api/docker/containers/<container_id>/metrics')
def docker_container_metrics(container_id):
    return _docker_proxy(f'containers/{container_id}/metrics')


@app.route('/api/docker/containers/<container_id>', methods=['GET'])
def docker_inspect_container(container_id):
    return _docker_proxy(f'containers/{container_id}')


@app.route('/api/docker/images')
def docker_list_images():
    return _docker_proxy('images')


@app.route('/api/docker/images/<path:image_id>')
def docker_inspect_image(image_id):
    return _docker_proxy(f'images/{image_id}')


@app.route('/api/docker/volumes')
def docker_list_volumes():
    return _docker_proxy('volumes')


@app.route('/api/docker/volumes/<vol_name>')
def docker_inspect_volume(vol_name):
    return _docker_proxy(f'volumes/{vol_name}')


@app.route('/api/docker/networks')
def docker_list_networks():
    return _docker_proxy('networks')


@app.route('/api/docker/networks/<net_id>')
def docker_inspect_network(net_id):
    return _docker_proxy(f'networks/{net_id}')


@app.route('/api/docker/system/info')
def docker_system_info():
    return _docker_proxy('system/info')


@app.route('/api/docker/system/disk')
def docker_system_disk():
    return _docker_proxy('system/disk')


# --- Kubernetes API Proxy ---

def _k8s_proxy(path, method='GET', **kwargs):
    """Forward a request to the k8s-api service and return a Flask response."""
    url = f"{K8S_API_URL}/{path.lstrip('/')}"
    try:
        resp = http_requests.request(
            method,
            url,
            params=request.args,
            json=request.get_json(silent=True),
            timeout=30,
            **kwargs
        )
        content_type = resp.headers.get('Content-Type', 'application/json')
        return Response(resp.content, status=resp.status_code, content_type=content_type)
    except http_requests.exceptions.ConnectionError:
        return jsonify({"error": "k8s-api service is not reachable"}), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "k8s-api request timed out"}), 504
    except Exception as e:
        sys.stderr.write(f"[K8s API] Error proxying to {url}: {str(e)}\n")
        sys.stderr.flush()
        return jsonify({"error": f"K8s API error: {str(e)}"}), 500


# Pods
@app.route('/api/k8s/pods')
def k8s_list_pods():
    return _k8s_proxy('pods')

@app.route('/api/k8s/pods/<namespace>/<name>')
def k8s_get_pod(namespace, name):
    return _k8s_proxy(f'pods/{namespace}/{name}')

@app.route('/api/k8s/pods/<namespace>/<name>', methods=['DELETE'])
def k8s_delete_pod(namespace, name):
    return _k8s_proxy(f'pods/{namespace}/{name}', method='DELETE')

@app.route('/api/k8s/pods/<namespace>/<name>/logs')
def k8s_pod_logs(namespace, name):
    return _k8s_proxy(f'pods/{namespace}/{name}/logs')

@app.route('/api/k8s/pods/<namespace>/<name>/metrics')
def k8s_pod_metrics(namespace, name):
    return _k8s_proxy(f'pods/{namespace}/{name}/metrics')

@app.route('/api/k8s/pods/<namespace>/<name>/restart', methods=['POST'])
def k8s_restart_pod(namespace, name):
    return _k8s_proxy(f'pods/{namespace}/{name}/restart', method='POST')


# Deployments
@app.route('/api/k8s/deployments')
def k8s_list_deployments():
    return _k8s_proxy('deployments')

@app.route('/api/k8s/deployments', methods=['POST'])
def k8s_create_deployment():
    return _k8s_proxy('deployments', method='POST')

@app.route('/api/k8s/deployments/<namespace>/<name>')
def k8s_get_deployment(namespace, name):
    return _k8s_proxy(f'deployments/{namespace}/{name}')

@app.route('/api/k8s/deployments/<namespace>/<name>', methods=['DELETE'])
def k8s_delete_deployment(namespace, name):
    return _k8s_proxy(f'deployments/{namespace}/{name}', method='DELETE')

@app.route('/api/k8s/deployments/<namespace>/<name>/scale', methods=['POST'])
def k8s_scale_deployment(namespace, name):
    return _k8s_proxy(f'deployments/{namespace}/{name}/scale', method='POST')

@app.route('/api/k8s/deployments/<namespace>/<name>/restart', methods=['POST'])
def k8s_restart_deployment(namespace, name):
    return _k8s_proxy(f'deployments/{namespace}/{name}/restart', method='POST')


# Services
@app.route('/api/k8s/services')
def k8s_list_services():
    return _k8s_proxy('services')

@app.route('/api/k8s/services', methods=['POST'])
def k8s_create_service():
    return _k8s_proxy('services', method='POST')

@app.route('/api/k8s/services/<namespace>/<name>')
def k8s_get_service(namespace, name):
    return _k8s_proxy(f'services/{namespace}/{name}')

@app.route('/api/k8s/services/<namespace>/<name>', methods=['DELETE'])
def k8s_delete_service(namespace, name):
    return _k8s_proxy(f'services/{namespace}/{name}', method='DELETE')


# Namespaces
@app.route('/api/k8s/namespaces')
def k8s_list_namespaces():
    return _k8s_proxy('namespaces')

@app.route('/api/k8s/namespaces', methods=['POST'])
def k8s_create_namespace():
    return _k8s_proxy('namespaces', method='POST')

@app.route('/api/k8s/namespaces/<name>')
def k8s_get_namespace(name):
    return _k8s_proxy(f'namespaces/{name}')

@app.route('/api/k8s/namespaces/<name>', methods=['DELETE'])
def k8s_delete_namespace(name):
    return _k8s_proxy(f'namespaces/{name}', method='DELETE')


# ConfigMaps
@app.route('/api/k8s/configmaps')
def k8s_list_configmaps():
    return _k8s_proxy('configmaps')

@app.route('/api/k8s/configmaps', methods=['POST'])
def k8s_create_configmap():
    return _k8s_proxy('configmaps', method='POST')

@app.route('/api/k8s/configmaps/<namespace>/<name>')
def k8s_get_configmap(namespace, name):
    return _k8s_proxy(f'configmaps/{namespace}/{name}')

@app.route('/api/k8s/configmaps/<namespace>/<name>', methods=['DELETE'])
def k8s_delete_configmap(namespace, name):
    return _k8s_proxy(f'configmaps/{namespace}/{name}', method='DELETE')


# PersistentVolumeClaims
@app.route('/api/k8s/pvcs')
def k8s_list_pvcs():
    return _k8s_proxy('pvcs')

@app.route('/api/k8s/pvcs', methods=['POST'])
def k8s_create_pvc():
    return _k8s_proxy('pvcs', method='POST')

@app.route('/api/k8s/pvcs/<namespace>/<name>')
def k8s_get_pvc(namespace, name):
    return _k8s_proxy(f'pvcs/{namespace}/{name}')

@app.route('/api/k8s/pvcs/<namespace>/<name>', methods=['DELETE'])
def k8s_delete_pvc(namespace, name):
    return _k8s_proxy(f'pvcs/{namespace}/{name}', method='DELETE')


# Nodes
@app.route('/api/k8s/nodes')
def k8s_list_nodes():
    return _k8s_proxy('nodes')

@app.route('/api/k8s/nodes/<name>')
def k8s_get_node(name):
    return _k8s_proxy(f'nodes/{name}')


# System
@app.route('/api/k8s/system/info')
def k8s_system_info():
    return _k8s_proxy('system/info')


# --- VyOS API Proxy ---

def _vyos_proxy(path, method='GET', **kwargs):
    """Forward a request to the vyos-api service and return a Flask response."""
    url = f"{VYOS_API_URL}/{path.lstrip('/')}"
    try:
        resp = http_requests.request(
            method,
            url,
            params=request.args,
            json=request.get_json(silent=True),
            timeout=30,
            **kwargs
        )
        content_type = resp.headers.get('Content-Type', 'application/json')
        return Response(resp.content, status=resp.status_code, content_type=content_type)
    except http_requests.exceptions.ConnectionError:
        return jsonify({"error": "vyos-api service is not reachable"}), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "vyos-api request timed out"}), 504
    except Exception as e:
        sys.stderr.write(f"[VyOS API] Error proxying to {url}: {str(e)}\n")
        sys.stderr.flush()
        return jsonify({"error": f"VyOS API error: {str(e)}"}), 500


@app.route('/api/vyos/devices')
def vyos_list_devices():
    return _vyos_proxy('devices')


# Networks (interfaces)
@app.route('/api/vyos/<device_id>/networks', methods=['GET'])
def vyos_list_networks(device_id):
    return _vyos_proxy(f'devices/{device_id}/networks')

@app.route('/api/vyos/<device_id>/networks', methods=['POST'])
def vyos_create_network(device_id):
    return _vyos_proxy(f'devices/{device_id}/networks', method='POST')

@app.route('/api/vyos/<device_id>/networks/<interface>', methods=['GET'])
def vyos_get_network(device_id, interface):
    return _vyos_proxy(f'devices/{device_id}/networks/{interface}')

@app.route('/api/vyos/<device_id>/networks/<interface>', methods=['PUT'])
def vyos_update_network(device_id, interface):
    return _vyos_proxy(f'devices/{device_id}/networks/{interface}', method='PUT')

@app.route('/api/vyos/<device_id>/networks/<interface>', methods=['DELETE'])
def vyos_delete_network(device_id, interface):
    return _vyos_proxy(f'devices/{device_id}/networks/{interface}', method='DELETE')


# VRFs
@app.route('/api/vyos/<device_id>/vrfs', methods=['GET'])
def vyos_list_vrfs(device_id):
    return _vyos_proxy(f'devices/{device_id}/vrfs')

@app.route('/api/vyos/<device_id>/vrfs', methods=['POST'])
def vyos_create_vrf(device_id):
    return _vyos_proxy(f'devices/{device_id}/vrfs', method='POST')

@app.route('/api/vyos/<device_id>/vrfs/<vrf>', methods=['GET'])
def vyos_get_vrf(device_id, vrf):
    return _vyos_proxy(f'devices/{device_id}/vrfs/{vrf}')

@app.route('/api/vyos/<device_id>/vrfs/<vrf>', methods=['PUT'])
def vyos_update_vrf(device_id, vrf):
    return _vyos_proxy(f'devices/{device_id}/vrfs/{vrf}', method='PUT')

@app.route('/api/vyos/<device_id>/vrfs/<vrf>', methods=['DELETE'])
def vyos_delete_vrf(device_id, vrf):
    return _vyos_proxy(f'devices/{device_id}/vrfs/{vrf}', method='DELETE')


# VLANs
@app.route('/api/vyos/<device_id>/vlans', methods=['GET'])
def vyos_list_vlans(device_id):
    return _vyos_proxy(f'devices/{device_id}/vlans')

@app.route('/api/vyos/<device_id>/vlans', methods=['POST'])
def vyos_create_vlan(device_id):
    return _vyos_proxy(f'devices/{device_id}/vlans', method='POST')

@app.route('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>', methods=['GET'])
def vyos_get_vlan(device_id, interface, vlan_id):
    return _vyos_proxy(f'devices/{device_id}/vlans/{interface}/{vlan_id}')

@app.route('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>', methods=['PUT'])
def vyos_update_vlan(device_id, interface, vlan_id):
    return _vyos_proxy(f'devices/{device_id}/vlans/{interface}/{vlan_id}', method='PUT')

@app.route('/api/vyos/<device_id>/vlans/<interface>/<vlan_id>', methods=['DELETE'])
def vyos_delete_vlan(device_id, interface, vlan_id):
    return _vyos_proxy(f'devices/{device_id}/vlans/{interface}/{vlan_id}', method='DELETE')


# Firewall Policies
@app.route('/api/vyos/<device_id>/firewall/policies', methods=['GET'])
def vyos_list_policies(device_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies')

@app.route('/api/vyos/<device_id>/firewall/policies', methods=['POST'])
def vyos_create_policy(device_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies', method='POST')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>', methods=['GET'])
def vyos_get_policy(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>', methods=['PUT'])
def vyos_update_policy(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}', method='PUT')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>', methods=['DELETE'])
def vyos_delete_policy(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}', method='DELETE')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/rules', methods=['POST'])
def vyos_add_rule(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/rules', method='POST')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>', methods=['DELETE'])
def vyos_delete_rule(device_id, policy, rule_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}', method='DELETE')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/disable', methods=['PUT'])
def vyos_disable_policy(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/disable', method='PUT')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/enable', methods=['PUT'])
def vyos_enable_policy(device_id, policy):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/enable', method='PUT')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>/disable', methods=['PUT'])
def vyos_disable_rule(device_id, policy, rule_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}/disable', method='PUT')

@app.route('/api/vyos/<device_id>/firewall/policies/<policy>/rules/<rule_id>/enable', methods=['PUT'])
def vyos_enable_rule(device_id, policy, rule_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/policies/{policy}/rules/{rule_id}/enable', method='PUT')


# Firewall Address Groups
@app.route('/api/vyos/<device_id>/firewall/address-groups', methods=['GET'])
def vyos_list_address_groups(device_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/address-groups')

@app.route('/api/vyos/<device_id>/firewall/address-groups', methods=['POST'])
def vyos_create_address_group(device_id):
    return _vyos_proxy(f'devices/{device_id}/firewall/address-groups', method='POST')

@app.route('/api/vyos/<device_id>/firewall/address-groups/<group>', methods=['GET'])
def vyos_get_address_group(device_id, group):
    return _vyos_proxy(f'devices/{device_id}/firewall/address-groups/{group}')

@app.route('/api/vyos/<device_id>/firewall/address-groups/<group>', methods=['PUT'])
def vyos_update_address_group(device_id, group):
    return _vyos_proxy(f'devices/{device_id}/firewall/address-groups/{group}', method='PUT')

@app.route('/api/vyos/<device_id>/firewall/address-groups/<group>', methods=['DELETE'])
def vyos_delete_address_group(device_id, group):
    return _vyos_proxy(f'devices/{device_id}/firewall/address-groups/{group}', method='DELETE')


# NAT rules (source / destination)
@app.route('/api/vyos/<device_id>/nat/<nat_type>/rules', methods=['GET'])
def vyos_list_nat_rules(device_id, nat_type):
    return _vyos_proxy(f'devices/{device_id}/nat/{nat_type}/rules')

@app.route('/api/vyos/<device_id>/nat/<nat_type>/rules', methods=['POST'])
def vyos_create_nat_rule(device_id, nat_type):
    return _vyos_proxy(f'devices/{device_id}/nat/{nat_type}/rules', method='POST')

@app.route('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>', methods=['GET'])
def vyos_get_nat_rule(device_id, nat_type, rule_id):
    return _vyos_proxy(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}')

@app.route('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>', methods=['PUT'])
def vyos_update_nat_rule(device_id, nat_type, rule_id):
    return _vyos_proxy(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}', method='PUT')

@app.route('/api/vyos/<device_id>/nat/<nat_type>/rules/<rule_id>', methods=['DELETE'])
def vyos_delete_nat_rule(device_id, nat_type, rule_id):
    return _vyos_proxy(f'devices/{device_id}/nat/{nat_type}/rules/{rule_id}', method='DELETE')


@app.route('/api/vms/<vmid>/vncproxy', methods=['POST'])
def create_vnc_proxy(vmid):
    """Create a VNC proxy ticket for a Proxmox VM"""
    try:
        try:
            vmid_int = int(vmid)
        except ValueError:
            return jsonify({"error": f"VNC console is only available for Proxmox VMs (numeric ID), got: {vmid}"}), 400

        proxmox = get_proxmox_client()
        result = proxmox.create_vnc_proxy(vmid_int)
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        sys.stderr.write(f"[VNC API] Error creating VNC proxy for VM {vmid}: {str(e)}\n")
        sys.stderr.flush()
        return jsonify({"error": f"Failed to create VNC proxy: {str(e)}"}), 500


async def vnc_websocket_handler(browser_ws):
    """WebSocket proxy between the browser (noVNC) and the Proxmox VNC WebSocket.
    Runs on port 5001 via the standalone websockets server."""
    path = browser_ws.request.path
    params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)

    vmid = params.get('vmid', [None])[0]
    port = params.get('port', [None])[0]
    vncticket = params.get('vncticket', [None])[0]
    node = params.get('node', [None])[0]

    if not all([vmid, port, vncticket, node]):
        await browser_ws.close(1008, 'Missing required query params: vmid, port, vncticket, node')
        return

    proxmox = get_proxmox_client()
    proxmox_ws_url = proxmox.get_vnc_websocket_url(node, int(vmid), port, vncticket)

    sys.stderr.write(f"[VNC WS] Connecting to Proxmox VNC WebSocket for VM {vmid} on {node}\n")
    sys.stderr.flush()

    # Connect to the Proxmox VNC WebSocket using websocket-client (sync) in a thread
    sslopt = {"cert_reqs": ssl.CERT_NONE}
    proxmox_ws = ws_client.WebSocket(sslopt=sslopt)
    try:
        proxmox_ws.connect(
            proxmox_ws_url,
            header=[f"Authorization: {proxmox.auth_header}"],
            subprotocols=["binary"]
        )
    except Exception as e:
        sys.stderr.write(f"[VNC WS] Failed to connect to Proxmox: {e}\n")
        sys.stderr.flush()
        await browser_ws.close(1011, f'Failed to connect to Proxmox VNC: {e}')
        return

    sys.stderr.write(f"[VNC WS] Connected to Proxmox VNC WebSocket for VM {vmid}\n")
    sys.stderr.flush()

    loop = asyncio.get_event_loop()
    closed = asyncio.Event()

    # Forward Proxmox -> browser (sync recv in thread, async send)
    async def proxmox_to_browser():
        try:
            while not closed.is_set():
                try:
                    opcode, data = await loop.run_in_executor(
                        None, lambda: proxmox_ws.recv_data(control_frame=True)
                    )
                    if opcode == 8:  # close
                        break
                    if opcode == 2 and data:  # binary
                        await browser_ws.send(data)
                    elif opcode == 1 and data:  # text
                        await browser_ws.send(data.decode('utf-8', errors='replace'))
                except Exception as e:
                    sys.stderr.write(f"[VNC WS] Proxmox->browser error VM {vmid}: {type(e).__name__}: {e}\n")
                    sys.stderr.flush()
                    break
        finally:
            closed.set()

    # Forward browser -> Proxmox
    async def browser_to_proxmox():
        try:
            async for message in browser_ws:
                if closed.is_set():
                    break
                if isinstance(message, bytes):
                    await loop.run_in_executor(None, proxmox_ws.send_binary, message)
                else:
                    await loop.run_in_executor(None, proxmox_ws.send, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            sys.stderr.write(f"[VNC WS] Browser->Proxmox error VM {vmid}: {type(e).__name__}: {e}\n")
            sys.stderr.flush()
        finally:
            closed.set()

    try:
        await asyncio.gather(proxmox_to_browser(), browser_to_proxmox())
    finally:
        try:
            proxmox_ws.close()
        except Exception:
            pass

    sys.stderr.write(f"[VNC WS] Disconnected VNC WebSocket for VM {vmid}\n")
    sys.stderr.flush()


def start_vnc_ws_server():
    """Start the standalone WebSocket server for VNC proxying on port 5001"""
    async def _serve():
        async with websockets.serve(
            vnc_websocket_handler,
            '0.0.0.0',
            5001,
            origins=None,
            select_subprotocol=lambda conn, subprotocols: 'binary' if 'binary' in subprotocols else None,
            ping_interval=20,
            ping_timeout=60,
            max_size=2**23,
        ) as server:
            sys.stderr.write("[VNC WS] WebSocket server listening on port 5001\n")
            sys.stderr.flush()
            await asyncio.get_event_loop().create_future()  # run forever

    asyncio.run(_serve())


if __name__ == '__main__':
    # Start VNC WebSocket server in a background thread
    vnc_thread = threading.Thread(target=start_vnc_ws_server, daemon=True)
    vnc_thread.start()

    # Start Flask server
    print("Starting Flask server on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
