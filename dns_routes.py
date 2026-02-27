"""
DNS routes — Flask Blueprint proxying CRUD operations to the valueiron_dns Go API.

Prefix: /api/dns

Routes mirror the valueiron_dns API structure:
  /customers               GET list, POST create
  /customers/<id>          GET, PUT, DELETE
  /customers/<id>/zones    GET list, POST create
  /customers/<id>/blocklists  GET list, POST create
  /zones/<id>              GET, DELETE
  /zones/<id>/records      GET list, POST create
  /zones/<id>/records/<rid>  GET, PUT, DELETE
  /blocklists/<id>         GET, PUT, DELETE
  /audit                   GET
"""

from flask import Blueprint, jsonify, request

import dns_client as dc

dns_bp = Blueprint("dns", __name__, url_prefix="/api/dns")


def _err(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


def _wrap(fn, *args, status: int = 200, **kwargs):
    """Call a dns_client function; map DnsApiError → HTTP status."""
    try:
        result = fn(*args, **kwargs)
        return jsonify(result), status
    except dc.DnsApiError as e:
        return _err(str(e), e.status_code)
    except Exception as e:
        return _err(str(e), 500)


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------

@dns_bp.get("/customers")
def list_customers():
    return _wrap(dc.list_customers)


@dns_bp.post("/customers")
def create_customer():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return _err("'name' is required")
    return _wrap(dc.create_customer, name, status=201)


@dns_bp.get("/customers/<int:customer_id>")
def get_customer(customer_id: int):
    return _wrap(dc.get_customer, customer_id)


@dns_bp.put("/customers/<int:customer_id>")
def update_customer(customer_id: int):
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return _err("'name' is required")
    return _wrap(dc.update_customer, customer_id, name)


@dns_bp.delete("/customers/<int:customer_id>")
def delete_customer(customer_id: int):
    return _wrap(dc.delete_customer, customer_id)


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------

@dns_bp.get("/customers/<int:customer_id>/zones")
def list_zones(customer_id: int):
    return _wrap(dc.list_zones, customer_id)


@dns_bp.post("/customers/<int:customer_id>/zones")
def create_zone(customer_id: int):
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return _err("'name' is required")
    return _wrap(dc.create_zone, customer_id, name, status=201)


@dns_bp.get("/zones/<int:zone_id>")
def get_zone(zone_id: int):
    return _wrap(dc.get_zone, zone_id)


@dns_bp.delete("/zones/<int:zone_id>")
def delete_zone(zone_id: int):
    return _wrap(dc.delete_zone, zone_id)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

VALID_RECORD_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "SRV"}


@dns_bp.get("/zones/<int:zone_id>/records")
def list_records(zone_id: int):
    return _wrap(dc.list_records, zone_id)


@dns_bp.post("/zones/<int:zone_id>/records")
def create_record(zone_id: int):
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    rtype = body.get("type", "").strip().upper()
    value = body.get("value", "").strip()
    ttl = body.get("ttl", 3600)

    if not name:
        return _err("'name' is required")
    if rtype not in VALID_RECORD_TYPES:
        return _err(f"'type' must be one of: {', '.join(sorted(VALID_RECORD_TYPES))}")
    if not value:
        return _err("'value' is required")

    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        ttl = 3600

    return _wrap(dc.create_record, zone_id, name, rtype, value, ttl, status=201)


@dns_bp.get("/zones/<int:zone_id>/records/<int:record_id>")
def get_record(zone_id: int, record_id: int):
    return _wrap(dc.get_record, zone_id, record_id)


@dns_bp.put("/zones/<int:zone_id>/records/<int:record_id>")
def update_record(zone_id: int, record_id: int):
    body = request.get_json(silent=True) or {}
    value = body.get("value", "").strip()
    ttl = body.get("ttl", 3600)

    if not value:
        return _err("'value' is required")

    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        ttl = 3600

    return _wrap(dc.update_record, zone_id, record_id, value, ttl)


@dns_bp.delete("/zones/<int:zone_id>/records/<int:record_id>")
def delete_record(zone_id: int, record_id: int):
    return _wrap(dc.delete_record, zone_id, record_id)


# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

@dns_bp.get("/customers/<int:customer_id>/blocklists")
def list_blocklists(customer_id: int):
    return _wrap(dc.list_blocklists, customer_id)


@dns_bp.post("/customers/<int:customer_id>/blocklists")
def create_blocklist(customer_id: int):
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    domains = body.get("domains", [])

    if not name:
        return _err("'name' is required")
    if not isinstance(domains, list):
        return _err("'domains' must be an array")

    return _wrap(dc.create_blocklist, customer_id, name, domains, status=201)


@dns_bp.get("/blocklists/<int:blocklist_id>")
def get_blocklist(blocklist_id: int):
    return _wrap(dc.get_blocklist, blocklist_id)


@dns_bp.put("/blocklists/<int:blocklist_id>")
def update_blocklist(blocklist_id: int):
    body = request.get_json(silent=True) or {}
    domains = body.get("domains", [])

    if not isinstance(domains, list):
        return _err("'domains' must be an array")

    return _wrap(dc.update_blocklist, blocklist_id, domains)


@dns_bp.delete("/blocklists/<int:blocklist_id>")
def delete_blocklist(blocklist_id: int):
    return _wrap(dc.delete_blocklist, blocklist_id)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dns_bp.get("/audit")
def get_audit():
    customer_id = request.args.get("customer_id", type=int)
    limit = request.args.get("limit", 100, type=int)
    return _wrap(dc.get_audit, customer_id, limit)
