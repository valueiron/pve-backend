"""
gunicorn.conf.py — production Gunicorn configuration for pve-backend.
"""

import threading

bind         = "0.0.0.0:5000"
workers      = 1          # SSH sessions live in-memory; >1 worker = isolated state per process
worker_class = "sync"
timeout      = 120        # long-running proxmox/cloud calls can be slow
accesslog    = "-"        # stdout
errorlog     = "-"        # stderr


def when_ready(server):
    """
    Runs in the master/arbiter process once all workers are ready.
    Starts the standalone WebSocket server (port 5001) as a daemon thread
    so it lives for the lifetime of the Gunicorn master.
    """
    from websocket_server import start_websocket_server

    t = threading.Thread(target=start_websocket_server, daemon=True)
    t.start()
    server.log.info("WebSocket server started on port 5001 (VNC + SSH terminal)")
