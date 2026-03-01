"""
cloud_routes.py — Flask Blueprint for multi-cloud resource reads.

Covers: /api/networking, /api/storage
"""

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

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

        def _fetch_azure():
            if not config.AZURE_AVAILABLE:
                return {}
            azure = config.get_azure_client()
            return azure.get_all_networking() if azure else {}

        def _fetch_aws():
            if not config.AWS_AVAILABLE:
                return {}
            aws = config.get_aws_client()
            return aws.get_all_networking() if aws else {}

        with ThreadPoolExecutor(max_workers=2) as executor:
            azure_future = executor.submit(_fetch_azure)
            aws_future   = executor.submit(_fetch_aws)

            try:
                net = azure_future.result()
                all_resources['vnets'].extend(net.get('vnets', []))
                all_resources['subnets'].extend(net.get('subnets', []))
                all_resources['nsgs'].extend(net.get('nsgs', []))
                all_resources['public_ips'].extend(net.get('public_ips', []))
                logger.info("[Networking API] Fetched Azure networking resources")
            except Exception as e:
                logger.error("[Networking API] Failed to fetch Azure networking: %s\n%s", e, traceback.format_exc())

            try:
                net = aws_future.result()
                all_resources['vpcs'].extend(net.get('vpcs', []))
                all_resources['subnets'].extend(net.get('subnets', []))
                all_resources['security_groups'].extend(net.get('security_groups', []))
                all_resources['elastic_ips'].extend(net.get('elastic_ips', []))
                logger.info("[Networking API] Fetched AWS networking resources")
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

        def _fetch_proxmox():
            proxmox = get_proxmox_client()
            return ('proxmox', proxmox.get_all_storage())

        def _fetch_azure():
            if not config.AZURE_AVAILABLE:
                return ('azure', {})
            azure = config.get_azure_client()
            return ('azure', azure.get_all_storage() if azure else {})

        def _fetch_aws():
            if not config.AWS_AVAILABLE:
                return ('aws', {})
            aws = config.get_aws_client()
            return ('aws', aws.get_all_storage() if aws else {})

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(_fetch_proxmox),
                executor.submit(_fetch_azure),
                executor.submit(_fetch_aws),
            ]
            for future in as_completed(futures):
                try:
                    source, stor = future.result()
                    if source == 'proxmox':
                        all_resources['storages'].extend(stor.get('storages', []))
                    elif source == 'azure':
                        all_resources['storage_accounts'].extend(stor.get('storage_accounts', []))
                        all_resources['containers'].extend(stor.get('containers', []))
                    elif source == 'aws':
                        all_resources['buckets'].extend(stor.get('buckets', []))
                    logger.info("[Storage API] Fetched %s storage resources", source)
                except Exception as e:
                    logger.error("[Storage API] Failed to fetch storage: %s\n%s", e, traceback.format_exc())

        total = sum(len(v) for v in all_resources.values())
        logger.info("[Storage API] Returning %d total storage resources", total)
        return jsonify(all_resources), 200
    except Exception as e:
        logger.error("[Storage API] Fatal error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": f"Failed to fetch storage resources: {str(e)}"}), 500
