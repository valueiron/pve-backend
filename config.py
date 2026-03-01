"""
config.py — centralised configuration for pve-backend.

Loads environment variables, SSH keys, and cloud clients at import time.
"""

import logging
import os
import sys

import asyncssh

logger = logging.getLogger(__name__)

# ── Downstream service URLs ────────────────────────────────────────────────────
DOCKER_API_URL = os.getenv('DOCKER_API_URL', 'http://localhost:8080')
K8S_API_URL    = os.getenv('K8S_API_URL',    'http://localhost:8081')
VYOS_API_URL   = os.getenv('VYOS_API_URL',   'http://localhost:8082')

# ── SSH credentials ────────────────────────────────────────────────────────────
SSH_USERNAME         = os.getenv('SSH_USERNAME', '')
SSH_PRIVATE_KEY_PATH = os.getenv('SSH_PRIVATE_KEY_PATH', '')
SSH_PORT             = int(os.getenv('SSH_PORT', '22'))

ssh_private_key = None
if SSH_PRIVATE_KEY_PATH:
    try:
        ssh_private_key = asyncssh.read_private_key(SSH_PRIVATE_KEY_PATH)
        logger.info("Loaded SSH private key from %s", SSH_PRIVATE_KEY_PATH)
    except Exception as e:
        logger.warning("Failed to load SSH key from %s: %s", SSH_PRIVATE_KEY_PATH, e)

# ── Cloud clients ──────────────────────────────────────────────────────────────
# AZURE_ENABLED / AWS_ENABLED can be set to "false" to explicitly disable a
# provider without removing its credentials (useful in mixed environments).
# Accepted falsy values: "false", "0", "no"  (case-insensitive).

def _is_enabled(env_var: str) -> bool:
    return os.getenv(env_var, 'true').lower() not in ('false', '0', 'no')

AZURE_AVAILABLE = _is_enabled('AZURE_ENABLED') and bool(
    os.getenv('AZURE_CLIENT_ID') and
    os.getenv('AZURE_CLIENT_SECRET') and
    os.getenv('AZURE_TENANT_ID')
)

AWS_AVAILABLE = _is_enabled('AWS_ENABLED') and bool(
    os.getenv('AWS_ACCESS_KEY_ID') and
    os.getenv('AWS_SECRET_ACCESS_KEY')
)

if AZURE_AVAILABLE:
    try:
        from azure_client import get_azure_client as _get_azure_client
        logger.info("Azure client module imported successfully")
    except Exception as e:
        AZURE_AVAILABLE = False
        logger.warning("Azure client not available: %s", e)
        def _get_azure_client():
            return None
else:
    logger.info("Azure credentials not configured (AZURE_CLIENT_ID/SECRET/TENANT_ID) — Azure disabled")
    def _get_azure_client():
        return None

if AWS_AVAILABLE:
    try:
        from aws_client import get_aws_client as _get_aws_client
        logger.info("AWS client module imported successfully")
    except Exception as e:
        AWS_AVAILABLE = False
        logger.warning("AWS client not available: %s", e)
        def _get_aws_client():
            return None
else:
    logger.info("AWS credentials not configured (AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY) — AWS disabled")
    def _get_aws_client():
        return None


def get_azure_client():
    return _get_azure_client()


def get_aws_client():
    return _get_aws_client()
