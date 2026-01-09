from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time
import sys
from proxmox_client import get_proxmox_client

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

if __name__ == '__main__':
    # Start Flask server
    print("Starting Flask server on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
