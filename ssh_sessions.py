"""
ssh_sessions.py — shared SSH terminal session store.

Imported by vm_routes (session creation) and websocket_server (session consumption).
"""

import threading

_ssh_sessions: dict = {}
_ssh_sessions_lock = threading.Lock()
