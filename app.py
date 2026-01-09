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
    """Get list of all VMs across all nodes (Proxmox and Azure)"""
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
        
        sys.stderr.write(f"[VM API] Returning {len(all_vms)} total VMs ({len([v for v in all_vms if v.get('type') == 'proxmox'])} Proxmox, {len([v for v in all_vms if v.get('type') == 'azure'])} Azure)\n")
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
    """Get detailed information about a specific VM (Proxmox or Azure)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            vm_details = azure.get_vm_details(vmid)
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

@app.route('/api/vms/<vmid>/start', methods=['POST'])
def start_vm(vmid):
    """Start a virtual machine (Proxmox or Azure)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            result = azure.start_vm(vmid)
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
    """Shutdown a virtual machine gracefully (Proxmox or Azure)"""
    try:
        # Check if this is an Azure VM (starts with 'azure-')
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            result = azure.stop_vm(vmid)
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

if __name__ == '__main__':
    # Start Flask server
    print("Starting Flask server on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
