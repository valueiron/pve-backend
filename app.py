"""
Thin entry-point: configures logging, creates the Flask app, registers
all Blueprints, exposes Prometheus metrics, and starts the WebSocket
server on port 5001 when run directly.
"""

import logging
import sys
import threading
import time

from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    generate_latest,
)

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── Blueprints ─────────────────────────────────────────────────────────────────
from labs_routes  import labs_bp
from dns_routes   import dns_bp
from vm_routes    import vm_bp
from cloud_routes import cloud_bp
from docker_routes import docker_bp
from k8s_routes   import k8s_bp
from vyos_routes  import vyos_bp
from route_api    import route_api_bp, start_auto_register

for bp in (labs_bp, dns_bp, vm_bp, cloud_bp, docker_bp, k8s_bp, vyos_bp, route_api_bp):
    app.register_blueprint(bp)

start_auto_register(app)

# ── Prometheus metrics ─────────────────────────────────────────────────────────
REQUEST_COUNT  = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
APP_HEALTH     = Gauge('app_health_status', 'Health status of the Flask app (1=healthy, 0=unhealthy)')
APP_READY      = Gauge('app_ready_status', 'Readiness status of the Flask app (1=ready, 0=not ready)')
APP_START_TIME = Gauge('app_start_time_seconds', 'Application start time in seconds since epoch')

APP_START_TIME.set(time.time())
APP_HEALTH.set(1)
APP_READY.set(1)


@app.before_request
def _count_request():
    REQUEST_COUNT.labels(method=request.method, endpoint=request.path).inc()


# ── Global error handlers ──────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    return jsonify(error="Bad request", detail=str(e)), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not found"), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify(error="Method not allowed"), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal server error"), 500


# ── Core routes ────────────────────────────────────────────────────────────────

@app.get('/')
def home():
    return jsonify(status="ok", message="Flask backend is running")


@app.get('/health')
def health():
    return jsonify(status="healthy"), 200


@app.get('/ready')
def ready():
    return jsonify(status="ready"), 200


@app.get('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


# ── Entry-point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    from websocket_server import start_websocket_server
    ws_thread = threading.Thread(target=start_websocket_server, daemon=True)
    ws_thread.start()

    print("Starting Flask server on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
