"""
proxy.py — generic HTTP proxy helper for downstream microservices.
"""

import logging

import requests as http_requests
from flask import Response, jsonify, request

logger = logging.getLogger(__name__)


def proxy_request(base_url: str, path: str, service_name: str, method: str = 'GET', timeout: int = 30, **kwargs):
    """Forward the current Flask request to a downstream service and return a Flask response."""
    url = f"{base_url}/{path.lstrip('/')}"
    try:
        resp = http_requests.request(
            method,
            url,
            params=request.args,
            json=request.get_json(silent=True),
            timeout=timeout,
            **kwargs,
        )
        content_type = resp.headers.get('Content-Type', 'application/json')
        return Response(resp.content, status=resp.status_code, content_type=content_type)
    except http_requests.exceptions.ConnectionError:
        return jsonify({"error": f"{service_name} service is not reachable"}), 503
    except http_requests.exceptions.Timeout:
        return jsonify({"error": f"{service_name} request timed out"}), 504
    except Exception as e:
        logger.error("Error proxying to %s: %s", url, e)
        return jsonify({"error": f"{service_name} error: {str(e)}"}), 500
