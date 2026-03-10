"""
vm_routes.py — Flask Blueprint for VM-related HTTP routes.

Covers: /api/vms, /api/nodes, /api/azure/status, /api/aws/status
"""

import logging
import os
import time
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, jsonify, request

import config
import ssh_sessions
from proxmox_client import get_proxmox_client

logger = logging.getLogger(__name__)

vm_bp = Blueprint('vm', __name__)

# ── Server-side VM list cache ───────────────────────────────────────────────────
_vm_cache_lock = threading.Lock()
_vm_cache = {'data': None, 'expires_at': 0}
_VM_CACHE_TTL = 10  # seconds


def _get_cached_vms(fetch_fn):
    """Return cached VM list if fresh, otherwise call fetch_fn() and cache the result."""
    with _vm_cache_lock:
        if _vm_cache['data'] is not None and time.monotonic() < _vm_cache['expires_at']:
            return _vm_cache['data'], True  # (data, from_cache)
    result = fetch_fn()
    with _vm_cache_lock:
        _vm_cache['data'] = result
        _vm_cache['expires_at'] = time.monotonic() + _VM_CACHE_TTL
    return result, False


# ── /api/vms ───────────────────────────────────────────────────────────────────

@vm_bp.get('/api/vms')
def get_vms():
    """List all VMs across Proxmox, Azure, and AWS."""
    try:
        def _fetch_all():
            def _fetch_proxmox():
                proxmox = get_proxmox_client()
                vms = proxmox.get_all_vms()
                for vm in vms:
                    vm['type'] = 'proxmox'
                return ('proxmox', vms)

            def _fetch_azure():
                if not config.AZURE_AVAILABLE:
                    return ('azure', [])
                azure = config.get_azure_client()
                return ('azure', azure.get_all_vms() if azure else [])

            def _fetch_aws():
                if not config.AWS_AVAILABLE:
                    return ('aws', [])
                aws = config.get_aws_client()
                return ('aws', aws.get_all_vms() if aws else [])

            combined = []
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(_fetch_proxmox),
                    executor.submit(_fetch_azure),
                    executor.submit(_fetch_aws),
                ]
                for future in as_completed(futures):
                    try:
                        source, vms = future.result()
                        combined.extend(vms)
                        logger.info("[VM API] Fetched %d %s VMs", len(vms), source)
                    except Exception as e:
                        logger.error("[VM API] Error fetching VMs: %s\n%s", e, traceback.format_exc())
            return combined

        all_vms, from_cache = _get_cached_vms(_fetch_all)

        proxmox_count = sum(1 for v in all_vms if v.get('type') == 'proxmox')
        azure_count   = sum(1 for v in all_vms if v.get('type') == 'azure')
        aws_count     = sum(1 for v in all_vms if v.get('type') == 'aws')
        logger.info("[VM API] Returning %d VMs (%d Proxmox, %d Azure, %d AWS) [cache=%s]",
                    len(all_vms), proxmox_count, azure_count, aws_count, from_cache)
        return jsonify({"vms": all_vms}), 200
    except Exception as e:
        logger.error("[VM API] Fatal error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": f"Failed to fetch VMs: {str(e)}"}), 500


@vm_bp.get('/api/vms/<vmid>')
def get_vm_details(vmid):
    """Get detailed information about a specific VM."""
    try:
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = config.get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            return jsonify(azure.get_vm_details(vmid)), 200
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = config.get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            return jsonify(aws.get_vm_details(vmid)), 200
        else:
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


@vm_bp.get('/api/vms/<vmid>/metrics')
def get_vm_metrics(vmid):
    """Get live runtime metrics for a Proxmox VM (CPU, memory, net I/O, disk I/O)."""
    try:
        try:
            vmid_int = int(vmid)
        except ValueError:
            return jsonify({"error": f"Metrics are only available for Proxmox VMs (numeric ID), got: {vmid}"}), 400
        proxmox = get_proxmox_client()
        metrics = proxmox.get_vm_metrics(vmid_int)
        return jsonify(metrics), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error("[VM Metrics] Error fetching metrics for VM %s: %s", vmid, e)
        return jsonify({"error": f"Failed to fetch VM metrics: {str(e)}"}), 500


@vm_bp.post('/api/vms/<vmid>/start')
def start_vm(vmid):
    """Start a virtual machine."""
    try:
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = config.get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            return jsonify({"message": f"VM {vmid} started successfully", "data": azure.start_vm(vmid)}), 200
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = config.get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            return jsonify({"message": f"VM {vmid} started successfully", "data": aws.start_vm(vmid)}), 200
        else:
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


@vm_bp.post('/api/vms/<vmid>/shutdown')
def shutdown_vm(vmid):
    """Shutdown a virtual machine gracefully."""
    try:
        if isinstance(vmid, str) and vmid.startswith('azure-'):
            azure = config.get_azure_client()
            if not azure:
                return jsonify({"error": "Azure client not available"}), 503
            return jsonify({"message": f"VM {vmid} shutdown initiated", "data": azure.stop_vm(vmid)}), 200
        elif isinstance(vmid, str) and vmid.startswith('aws-'):
            aws = config.get_aws_client()
            if not aws:
                return jsonify({"error": "AWS client not available"}), 503
            return jsonify({"message": f"VM {vmid} shutdown initiated", "data": aws.stop_vm(vmid)}), 200
        else:
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


@vm_bp.post('/api/vms/<vmid>/vncproxy')
def create_vnc_proxy(vmid):
    """Create a VNC proxy ticket for a Proxmox VM."""
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
        logger.error("[VNC API] Error creating VNC proxy for VM %s: %s", vmid, e)
        return jsonify({"error": f"Failed to create VNC proxy: {str(e)}"}), 500


@vm_bp.post('/api/vms/<vmid>/terminal')
def create_terminal_session(vmid):
    """Create an SSH terminal session. Returns sessionId for the WebSocket."""
    if not config.SSH_USERNAME:
        return jsonify({"error": "SSH_USERNAME is not configured on the backend"}), 500
    if not config.ssh_private_key:
        return jsonify({"error": "SSH private key is not available (check SSH_PRIVATE_KEY_PATH)"}), 500

    try:
        vmid_int = int(vmid)
    except ValueError:
        vmid_int = None

    # Non-numeric vmid: look up in registered lab VMs (e.g. AWS EC2 instances)
    if vmid_int is None:
        from labs_client import _load_lab_vms
        ip = None
        for _lab_id, lab_vms in _load_lab_vms().items():
            for v in lab_vms:
                if str(v.get("vmid")) == vmid:
                    ip = v.get("public_ip")
                    break
            if ip:
                break

        if not ip:
            return jsonify({"error": f"No IP found for vmid '{vmid}' — ensure the lab VM is registered"}), 400

        session_id = str(uuid.uuid4())
        with ssh_sessions._ssh_sessions_lock:
            ssh_sessions._ssh_sessions[session_id] = {
                'vmid': vmid,
                'ip': ip,
                'username': config.SSH_USERNAME,
            }

        logger.info("[SSH API] Created session %s for cloud VM %s at %s", session_id, vmid, ip)
        return jsonify({"sessionId": session_id, "vmid": vmid, "ip": ip}), 200

    # Numeric vmid: Proxmox VM
    try:
        proxmox = get_proxmox_client()
        node = proxmox._find_vm_node(vmid_int)
        ips = proxmox._get_vm_ip_addresses(vmid_int, node)
        if not ips:
            return jsonify({"error": f"Could not resolve IP for VM {vmid} — ensure the guest agent is running"}), 400
        ip = ips[0]

        session_id = str(uuid.uuid4())
        with ssh_sessions._ssh_sessions_lock:
            ssh_sessions._ssh_sessions[session_id] = {
                'vmid': vmid_int,
                'node': node,
                'ip': ip,
                'username': config.SSH_USERNAME,
            }

        logger.info("[SSH API] Created session %s for VM %s at %s", session_id, vmid, ip)
        return jsonify({"sessionId": session_id, "vmid": vmid_int, "ip": ip}), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error("[SSH API] Error creating terminal session for VM %s: %s", vmid, e)
        return jsonify({"error": f"Failed to create terminal session: {str(e)}"}), 500


# ── /api/nodes ─────────────────────────────────────────────────────────────────

@vm_bp.get('/api/nodes')
def get_nodes():
    """List all Proxmox nodes."""
    try:
        proxmox = get_proxmox_client()
        nodes = proxmox.get_nodes()
        return jsonify({"nodes": nodes}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch nodes: {str(e)}"}), 500


# ── /api/azure/status and /api/aws/status ──────────────────────────────────────

@vm_bp.get('/api/azure/status')
def azure_status():
    """Diagnostic endpoint to check Azure client status."""
    try:
        from azure_client import get_azure_client as _gac
        env_status = {
            'AZURE_CLIENT_ID':       'SET' if os.getenv('AZURE_CLIENT_ID') else 'NOT SET',
            'AZURE_CLIENT_SECRET':   'SET' if os.getenv('AZURE_CLIENT_SECRET') else 'NOT SET',
            'AZURE_TENANT_ID':       'SET' if os.getenv('AZURE_TENANT_ID') else 'NOT SET',
            'AZURE_SUBSCRIPTION_ID': os.getenv('AZURE_SUBSCRIPTION_ID') or 'NOT SET (will search all subscriptions)',
        }
        azure = _gac()
        if azure:
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
                    "subscriptions": subscriptions[:5],
                }), 200
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Azure client initialized but failed to list subscriptions: {str(e)}",
                    "environment_variables": env_status,
                    "error_details": str(e),
                    "traceback": traceback.format_exc(),
                }), 200
        else:
            return jsonify({
                "status": "not_configured",
                "message": "Azure client is not available - credentials may be missing or invalid",
                "environment_variables": env_status,
            }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error checking Azure status: {str(e)}",
            "traceback": traceback.format_exc(),
        }), 500


@vm_bp.get('/api/aws/status')
def aws_status():
    """Diagnostic endpoint to check AWS client status."""
    try:
        from aws_client import get_aws_client as _gac
        env_status = {
            'AWS_ACCESS_KEY_ID':     'SET' if os.getenv('AWS_ACCESS_KEY_ID') else 'NOT SET',
            'AWS_SECRET_ACCESS_KEY': 'SET' if os.getenv('AWS_SECRET_ACCESS_KEY') else 'NOT SET',
            'AWS_REGION':            os.getenv('AWS_REGION') or 'NOT SET (will search all regions)',
            'AWS_SESSION_TOKEN':     'SET' if os.getenv('AWS_SESSION_TOKEN') else 'NOT SET (optional)',
        }
        aws = _gac()
        if aws:
            try:
                regions = aws._get_all_regions()
                return jsonify({
                    "status": "connected",
                    "message": "AWS client is initialized and working",
                    "environment_variables": env_status,
                    "regions_available": len(regions),
                    "regions": regions[:10],
                }), 200
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"AWS client initialized but failed to list regions: {str(e)}",
                    "environment_variables": env_status,
                    "error_details": str(e),
                    "traceback": traceback.format_exc(),
                }), 200
        else:
            return jsonify({
                "status": "not_configured",
                "message": "AWS client is not available - credentials may be missing or invalid",
                "environment_variables": env_status,
            }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error checking AWS status: {str(e)}",
            "traceback": traceback.format_exc(),
        }), 500
