"""
route_api.py — Flask Blueprint proxying requests to the route-api service.

Prefix: /api/routes  (tenant baked in from config)
Also provides: /api/auth/me  (auth passthrough header extraction)
"""

import logging
import threading
import time

import requests as http_requests
from flask import Blueprint, jsonify, request

import config
from proxy import proxy_request

logger = logging.getLogger(__name__)

route_api_bp = Blueprint('route_api', __name__)

_SVC = 'route-api'


def _p(path, method='GET'):
    return proxy_request(config.ROUTE_API_URL, path, _SVC, method)


def _tenant_path(suffix=''):
    return f"tenants/{config.ROUTE_API_TENANT}/routes{suffix}"


def _unavailable():
    return jsonify({"error": "route-api not configured (ROUTE_API_URL is unset)"}), 503


# ── Status ─────────────────────────────────────────────────────────────────────

@route_api_bp.get('/api/routes/status')
def routes_status():
    if not config.ROUTE_API_URL:
        return jsonify({"available": False, "tenant": config.ROUTE_API_TENANT})
    try:
        resp = http_requests.get(
            f"{config.ROUTE_API_URL}/tenants/{config.ROUTE_API_TENANT}/routes",
            timeout=3,
        )
        available = resp.status_code < 500
    except Exception:
        available = False
    return jsonify({"available": available, "tenant": config.ROUTE_API_TENANT})


# ── CRUD proxy ─────────────────────────────────────────────────────────────────

@route_api_bp.get('/api/routes')
def routes_list():
    if not config.ROUTE_API_URL:
        return _unavailable()
    return _p(_tenant_path())


@route_api_bp.post('/api/routes')
def routes_create():
    if not config.ROUTE_API_URL:
        return _unavailable()
    return _p(_tenant_path(), 'POST')


@route_api_bp.get('/api/routes/<route_id>')
def routes_get(route_id):
    if not config.ROUTE_API_URL:
        return _unavailable()
    return _p(_tenant_path(f'/{route_id}'))


@route_api_bp.put('/api/routes/<route_id>')
def routes_update(route_id):
    if not config.ROUTE_API_URL:
        return _unavailable()
    return _p(_tenant_path(f'/{route_id}'), 'PUT')


@route_api_bp.delete('/api/routes/<route_id>')
def routes_delete(route_id):
    if not config.ROUTE_API_URL:
        return _unavailable()
    return _p(_tenant_path(f'/{route_id}'), 'DELETE')


# ── Auth passthrough ────────────────────────────────────────────────────────────

@route_api_bp.get('/api/auth/me')
def auth_me():
    import base64, json as _json, urllib.parse

    username = request.headers.get('X-Auth-Request-Preferred-Username', '')
    email    = request.headers.get('X-Auth-Request-Email', '')
    user     = request.headers.get('X-Auth-Request-User', '')

    # Build a Keycloak-aware logout URL by decoding the access token's iss claim.
    # /oauth2/sign_out clears the proxy cookie; rd= then ends the Keycloak SSO session.
    logout_url = '/oauth2/sign_out'
    access_token = request.headers.get('X-Auth-Request-Access-Token', '')
    if access_token:
        try:
            payload_b64 = access_token.split('.')[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
            iss = claims.get('iss', '')
            if iss:
                kc_logout = f"{iss}/protocol/openid-connect/logout"
                logout_url = f"/oauth2/sign_out?rd={urllib.parse.quote(kc_logout, safe='')}"
        except Exception:
            pass

    return jsonify({
        "email":      email,
        "username":   username,
        "user":       user,
        "logout_url": logout_url,
    })


# ── Auto-registration ──────────────────────────────────────────────────────────

def start_auto_register(app):
    """Spawn a daemon thread to register the portal as a Traefik route on startup."""
    if not (config.ROUTE_API_URL and config.PORTAL_HOSTNAME and config.PORTAL_SERVICE_URL):
        return

    def _register():
        time.sleep(5)
        for attempt in range(3):
            try:
                # Check if portal route already exists
                resp = http_requests.get(
                    f"{config.ROUTE_API_URL}/tenants/{config.ROUTE_API_TENANT}/routes",
                    timeout=10,
                )
                resp.raise_for_status()
                routes = resp.json()
                existing_names = [r.get('name') for r in (routes if isinstance(routes, list) else [])]
                if config.PORTAL_ROUTE_NAME in existing_names:
                    logger.info("Portal route '%s' already registered — skipping", config.PORTAL_ROUTE_NAME)
                    return

                # Register portal route
                logger.info("Auto-registering portal route '%s'...", config.PORTAL_ROUTE_NAME)
                payload = {
                    "name":         config.PORTAL_ROUTE_NAME,
                    "rule":         f"Host(`{config.PORTAL_HOSTNAME}`)",
                    "entryPoints":  ["websecure"],
                    "serviceUrls":  [config.PORTAL_SERVICE_URL],
                    "middlewares":  ["keycloak-auth@file", "secure-headers@file"],
                }
                create_resp = http_requests.post(
                    f"{config.ROUTE_API_URL}/tenants/{config.ROUTE_API_TENANT}/routes",
                    json=payload,
                    timeout=10,
                )
                create_resp.raise_for_status()
                logger.info("Portal route '%s' registered successfully", config.PORTAL_ROUTE_NAME)
                return

            except (http_requests.exceptions.ConnectionError, http_requests.exceptions.Timeout) as e:
                logger.warning("Auto-register attempt %d/3 failed: %s", attempt + 1, e)
                if attempt < 2:
                    time.sleep(10)
            except Exception as e:
                logger.warning("Auto-register attempt %d/3 error: %s", attempt + 1, e)
                if attempt < 2:
                    time.sleep(10)

        logger.warning("Auto-registration of portal route failed after 3 attempts")

    t = threading.Thread(target=_register, daemon=True)
    t.start()
