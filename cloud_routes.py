"""
cloud_routes.py — Flask Blueprint for multi-cloud resource reads.

Covers: /api/networking, /api/storage
"""

import logging
import traceback

from flask import Blueprint, jsonify

import config
from proxmox_client import get_proxmox_client

logger = logging.getLogger(__name__)

cloud_bp = Blueprint('cloud', __name__)


@cloud_bp.get('/api/networking')
def get_networking():
    """List all networking resources (Azure and AWS)."""
    try:
        all_resources = {
            'vnets': [], 'subnets': [], 'nsgs': [], 'public_ips': [],
            'vpcs': [], 'security_groups': [], 'elastic_ips': [],
        }

        logger.info("[Networking API] Attempting Azure networking (available=%s)", config.AZURE_AVAILABLE)
        try:
            azure = config.get_azure_client()
            if azure:
                net = azure.get_all_networking()
                all_resources['vnets'].extend(net.get('vnets', []))
                all_resources['subnets'].extend(net.get('subnets', []))
                all_resources['nsgs'].extend(net.get('nsgs', []))
                all_resources['public_ips'].extend(net.get('public_ips', []))
                logger.info("[Networking API] Fetched Azure networking resources")
            else:
                logger.info("[Networking API] Azure client not available")
        except Exception as e:
            logger.error("[Networking API] Failed to fetch Azure networking: %s\n%s", e, traceback.format_exc())

        logger.info("[Networking API] Attempting AWS networking (available=%s)", config.AWS_AVAILABLE)
        try:
            aws = config.get_aws_client()
            if aws:
                net = aws.get_all_networking()
                all_resources['vpcs'].extend(net.get('vpcs', []))
                all_resources['subnets'].extend(net.get('subnets', []))
                all_resources['security_groups'].extend(net.get('security_groups', []))
                all_resources['elastic_ips'].extend(net.get('elastic_ips', []))
                logger.info("[Networking API] Fetched AWS networking resources")
            else:
                logger.info("[Networking API] AWS client not available")
        except Exception as e:
            logger.error("[Networking API] Failed to fetch AWS networking: %s\n%s", e, traceback.format_exc())

        total = sum(len(v) for v in all_resources.values())
        logger.info("[Networking API] Returning %d total networking resources", total)
        return jsonify(all_resources), 200
    except Exception as e:
        logger.error("[Networking API] Fatal error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": f"Failed to fetch networking resources: {str(e)}"}), 500


@cloud_bp.get('/api/storage')
def get_storage():
    """List all storage resources (Proxmox, Azure, and AWS)."""
    try:
        all_resources = {
            'storage_accounts': [], 'containers': [], 'buckets': [], 'storages': [],
        }

        logger.info("[Storage API] Attempting Proxmox storage")
        try:
            proxmox = get_proxmox_client()
            pve_storage = proxmox.get_all_storage()
            all_resources['storages'].extend(pve_storage.get('storages', []))
            logger.info("[Storage API] Fetched %d Proxmox storage resources",
                        len(all_resources['storages']))
        except Exception as e:
            logger.error("[Storage API] Failed to fetch Proxmox storage: %s\n%s", e, traceback.format_exc())

        logger.info("[Storage API] Attempting Azure storage (available=%s)", config.AZURE_AVAILABLE)
        try:
            azure = config.get_azure_client()
            if azure:
                stor = azure.get_all_storage()
                all_resources['storage_accounts'].extend(stor.get('storage_accounts', []))
                all_resources['containers'].extend(stor.get('containers', []))
                logger.info("[Storage API] Fetched Azure storage resources")
            else:
                logger.info("[Storage API] Azure client not available")
        except Exception as e:
            logger.error("[Storage API] Failed to fetch Azure storage: %s\n%s", e, traceback.format_exc())

        logger.info("[Storage API] Attempting AWS storage (available=%s)", config.AWS_AVAILABLE)
        try:
            aws = config.get_aws_client()
            if aws:
                stor = aws.get_all_storage()
                all_resources['buckets'].extend(stor.get('buckets', []))
                logger.info("[Storage API] Fetched AWS storage resources")
            else:
                logger.info("[Storage API] AWS client not available")
        except Exception as e:
            logger.error("[Storage API] Failed to fetch AWS storage: %s\n%s", e, traceback.format_exc())

        total = sum(len(v) for v in all_resources.values())
        logger.info("[Storage API] Returning %d total storage resources", total)
        return jsonify(all_resources), 200
    except Exception as e:
        logger.error("[Storage API] Fatal error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": f"Failed to fetch storage resources: {str(e)}"}), 500
