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
try:
    from azure_client import get_azure_client as _get_azure_client
    AZURE_AVAILABLE = True
    logger.info("Azure client module imported successfully")
except Exception as e:
    AZURE_AVAILABLE = False
    logger.warning("Azure client not available: %s", e)
    def _get_azure_client():
        return None

try:
    from aws_client import get_aws_client as _get_aws_client
    AWS_AVAILABLE = True
    logger.info("AWS client module imported successfully")
except Exception as e:
    AWS_AVAILABLE = False
    logger.warning("AWS client not available: %s", e)
    def _get_aws_client():
        return None


def get_azure_client():
    return _get_azure_client()


def get_aws_client():
    return _get_aws_client()
