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


def post_fork(server, worker):
    """
    Runs inside each worker process after it forks from the master.
    Starting the WebSocket server here means it shares the same memory space
    as Flask request handlers, so ssh_sessions written by HTTP routes are
    immediately visible to the WebSocket session lookup.

    NOTE: with workers > 1, each worker would attempt to bind port 5001 and
    all but the first would fail. workers = 1 is required for this setup.
    """
    from websocket_server import start_websocket_server

    t = threading.Thread(target=start_websocket_server, daemon=True)
    t.start()
    server.log.info("WebSocket server started in worker %s on port 5001", worker.pid)
