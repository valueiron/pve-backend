"""
websocket_server.py — standalone WebSocket server on port 5001.

Handles:
  /vnc               — VNC proxy to Proxmox (noVNC)
  /ws/terminal       — SSH terminal bridge (xterm.js)
"""

import asyncio
import json
import logging
import ssl
import urllib.parse

import asyncssh
import websocket as ws_client
import websockets
import websockets.exceptions

import config
import ssh_sessions
from proxmox_client import get_proxmox_client

logger = logging.getLogger(__name__)


async def vnc_websocket_handler(browser_ws):
    """WebSocket proxy between the browser (noVNC) and the Proxmox VNC WebSocket."""
    path = browser_ws.request.path
    params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)

    vmid     = params.get('vmid',      [None])[0]
    port     = params.get('port',      [None])[0]
    vncticket = params.get('vncticket', [None])[0]
    node     = params.get('node',      [None])[0]

    if not all([vmid, port, vncticket, node]):
        await browser_ws.close(1008, 'Missing required query params: vmid, port, vncticket, node')
        return

    proxmox = get_proxmox_client()
    proxmox_ws_url = proxmox.get_vnc_websocket_url(node, int(vmid), port, vncticket)

    logger.info("[VNC WS] Connecting to Proxmox VNC WebSocket for VM %s on %s", vmid, node)

    sslopt = {"cert_reqs": ssl.CERT_NONE}
    proxmox_ws = ws_client.WebSocket(sslopt=sslopt)
    try:
        proxmox_ws.connect(
            proxmox_ws_url,
            header=[f"Authorization: {proxmox.auth_header}"],
            subprotocols=["binary"],
        )
    except Exception as e:
        logger.error("[VNC WS] Failed to connect to Proxmox: %s", e)
        await browser_ws.close(1011, f'Failed to connect to Proxmox VNC: {e}')
        return

    logger.info("[VNC WS] Connected to Proxmox VNC WebSocket for VM %s", vmid)

    loop = asyncio.get_event_loop()
    closed = asyncio.Event()

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
                    logger.error("[VNC WS] Proxmox->browser error VM %s: %s: %s", vmid, type(e).__name__, e)
                    break
        finally:
            closed.set()

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
            logger.error("[VNC WS] Browser->Proxmox error VM %s: %s: %s", vmid, type(e).__name__, e)
        finally:
            closed.set()

    try:
        await asyncio.gather(proxmox_to_browser(), browser_to_proxmox())
    finally:
        try:
            proxmox_ws.close()
        except Exception:
            pass

    logger.info("[VNC WS] Disconnected VNC WebSocket for VM %s", vmid)


async def ssh_terminal_handler(browser_ws):
    """WebSocket SSH bridge for xterm.js terminal sessions.
    Expects ?sessionId=<uuid> query param."""
    path = browser_ws.request.path
    params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
    session_id = params.get('sessionId', [None])[0]

    if not session_id:
        await browser_ws.send('{"type":"error","message":"No sessionId provided"}')
        await browser_ws.close(1008, 'No sessionId')
        return

    with ssh_sessions._ssh_sessions_lock:
        session = ssh_sessions._ssh_sessions.get(session_id)

    if not session:
        await browser_ws.send('{"type":"error","message":"Session not found or expired"}')
        await browser_ws.close(1008, 'Session not found')
        return

    ip       = session['ip']
    username = session['username']
    vmid     = session['vmid']

    logger.info("[SSH WS] Opening SSH terminal: vmid=%s ip=%s user=%s", vmid, ip, username)

    try:
        conn = await asyncssh.connect(
            host=ip,
            port=config.SSH_PORT,
            username=username,
            client_keys=[config.ssh_private_key],
            known_hosts=None,
            connect_timeout=10,
        )
    except Exception as e:
        logger.error("[SSH WS] Connection failed for session %s: %s", session_id, e)
        await browser_ws.send(f'{{"type":"error","message":"SSH connection failed: {str(e)}"}}')
        await browser_ws.close(1011, 'SSH connection failed')
        with ssh_sessions._ssh_sessions_lock:
            ssh_sessions._ssh_sessions.pop(session_id, None)
        return

    async with conn:
        proc = await conn.create_process(
            term_type='xterm-256color',
            term_size=(80, 24),
            encoding=None,
        )

        await browser_ws.send(f'{{"type":"connected","sessionId":"{session_id}"}}')
        logger.info("[SSH WS] Shell started for session %s", session_id)

        async def shell_to_browser():
            try:
                while True:
                    data = await proc.stdout.read(65536)
                    if not data:
                        break
                    await browser_ws.send(data)
            except Exception as e:
                logger.error("[SSH WS] Shell->browser error %s: %s", session_id, e)
            finally:
                if browser_ws.open:
                    try:
                        await browser_ws.send('{"type":"disconnected"}')
                        await browser_ws.close(1000, 'SSH shell closed')
                    except Exception:
                        pass

        async def browser_to_shell():
            try:
                async for message in browser_ws:
                    if isinstance(message, str):
                        try:
                            msg = json.loads(message)
                            msg_type = msg.get('type')
                            if msg_type == 'ping':
                                await browser_ws.send('{"type":"pong"}')
                            elif msg_type == 'resize':
                                proc.change_terminal_size(
                                    msg.get('cols', 80), msg.get('rows', 24)
                                )
                            elif msg_type == 'inject':
                                data = msg.get('data', '')
                                if data:
                                    proc.stdin.write(data.encode('utf-8'))
                            else:
                                proc.stdin.write(message.encode('utf-8'))
                        except json.JSONDecodeError:
                            proc.stdin.write(message.encode('utf-8'))
                    else:
                        proc.stdin.write(message)
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                logger.error("[SSH WS] Browser->shell error %s: %s", session_id, e)
            finally:
                try:
                    proc.close()
                except Exception:
                    pass

        try:
            await asyncio.gather(shell_to_browser(), browser_to_shell())
        finally:
            with ssh_sessions._ssh_sessions_lock:
                ssh_sessions._ssh_sessions.pop(session_id, None)
            logger.info("[SSH WS] Session %s ended", session_id)


async def _ws_router(websocket):
    """Route incoming WebSocket connections by path."""
    path = urllib.parse.urlparse(websocket.request.path).path
    if path == '/ws/terminal':
        await ssh_terminal_handler(websocket)
    else:
        await vnc_websocket_handler(websocket)


def start_websocket_server():
    """Start the standalone WebSocket server on port 5001 (VNC + SSH terminal)."""
    async def _serve():
        async with websockets.serve(
            _ws_router,
            '0.0.0.0',
            5001,
            origins=None,
            select_subprotocol=lambda conn, subprotocols: 'binary' if 'binary' in subprotocols else None,
            ping_interval=20,
            ping_timeout=60,
            max_size=2**23,
        ):
            logger.info("[WS] WebSocket server listening on port 5001 (VNC + SSH terminal)")
            await asyncio.get_event_loop().create_future()  # run forever

    asyncio.run(_serve())
