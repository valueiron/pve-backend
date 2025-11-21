from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time
from proxmox_client import get_proxmox_client

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
    """Get list of all VMs across all nodes"""
    try:
        proxmox = get_proxmox_client()
        vms = proxmox.get_all_vms()
        return jsonify({"vms": vms}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to fetch VMs: {str(e)}"}), 500

@app.route('/api/vms/<int:vmid>')
def get_vm_details(vmid):
    """Get detailed information about a specific VM"""
    try:
        proxmox = get_proxmox_client()
        vm_details = proxmox.get_vm_details(vmid)
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

@app.route('/api/vms/<int:vmid>/start', methods=['POST'])
def start_vm(vmid):
    """Start a virtual machine"""
    try:
        proxmox = get_proxmox_client()
        result = proxmox.start_vm(vmid)
        return jsonify({"message": f"VM {vmid} started successfully", "data": result}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to start VM {vmid}: {str(e)}"}), 500

@app.route('/api/vms/<int:vmid>/shutdown', methods=['POST'])
def shutdown_vm(vmid):
    """Shutdown a virtual machine gracefully"""
    try:
        proxmox = get_proxmox_client()
        result = proxmox.shutdown_vm(vmid)
        return jsonify({"message": f"VM {vmid} shutdown initiated", "data": result}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to shutdown VM {vmid}: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
