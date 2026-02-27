"""
DNS client — thin HTTP proxy to the valueiron_dns Go API.

No Flask imports. All interaction with the DNS API goes through this module.

Configuration (env vars):
  VALUEIRON_DNS_URL      Base URL of the valueiron_dns API  (default: http://localhost:8080)
  VALUEIRON_DNS_API_KEY  Optional bearer token for auth     (default: empty → auth disabled)
"""

import os

import requests as http_requests

DNS_API_URL = os.getenv("VALUEIRON_DNS_URL", "http://localhost:8080")
DNS_API_KEY = os.getenv("VALUEIRON_DNS_API_KEY", "")


class DnsApiError(Exception):
    """Raised when the DNS API returns a non-2xx response."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if DNS_API_KEY:
        h["Authorization"] = f"Bearer {DNS_API_KEY}"
    return h


def _url(path: str) -> str:
    return f"{DNS_API_URL}/api/v1{path}"


def _handle(resp) -> dict | list:
    """Parse response; raise DnsApiError on non-2xx."""
    if not resp.ok:
        try:
            msg = resp.json().get("error", resp.reason)
        except Exception:
            msg = resp.reason
        raise DnsApiError(resp.status_code, msg)
    if not resp.content:
        return {}
    return resp.json()


def _get(path: str):
    return _handle(http_requests.get(_url(path), headers=_headers(), timeout=10))


def _post(path: str, body: dict):
    return _handle(http_requests.post(_url(path), json=body, headers=_headers(), timeout=10))


def _put(path: str, body: dict):
    return _handle(http_requests.put(_url(path), json=body, headers=_headers(), timeout=10))


def _delete(path: str):
    return _handle(http_requests.delete(_url(path), headers=_headers(), timeout=10))


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------

def list_customers():
    return _get("/customers")


def create_customer(name: str):
    return _post("/customers", {"name": name})


def get_customer(customer_id: int):
    return _get(f"/customers/{customer_id}")


def update_customer(customer_id: int, name: str):
    return _put(f"/customers/{customer_id}", {"name": name})


def delete_customer(customer_id: int):
    return _delete(f"/customers/{customer_id}")


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------

def list_zones(customer_id: int):
    return _get(f"/customers/{customer_id}/zones")


def create_zone(customer_id: int, name: str):
    return _post(f"/customers/{customer_id}/zones", {"name": name})


def get_zone(zone_id: int):
    return _get(f"/zones/{zone_id}")


def delete_zone(zone_id: int):
    return _delete(f"/zones/{zone_id}")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def list_records(zone_id: int):
    return _get(f"/zones/{zone_id}/records")


def create_record(zone_id: int, name: str, rtype: str, value: str, ttl: int = 3600):
    return _post(f"/zones/{zone_id}/records", {
        "name": name,
        "type": rtype,
        "value": value,
        "ttl": ttl,
    })


def get_record(zone_id: int, record_id: int):
    return _get(f"/zones/{zone_id}/records/{record_id}")


def update_record(zone_id: int, record_id: int, value: str, ttl: int):
    return _put(f"/zones/{zone_id}/records/{record_id}", {"value": value, "ttl": ttl})


def delete_record(zone_id: int, record_id: int):
    return _delete(f"/zones/{zone_id}/records/{record_id}")


# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

def list_blocklists(customer_id: int):
    return _get(f"/customers/{customer_id}/blocklists")


def create_blocklist(customer_id: int, name: str, domains: list):
    return _post(f"/customers/{customer_id}/blocklists", {"name": name, "domains": domains})


def get_blocklist(blocklist_id: int):
    return _get(f"/blocklists/{blocklist_id}")


def update_blocklist(blocklist_id: int, domains: list):
    return _put(f"/blocklists/{blocklist_id}", {"domains": domains})


def delete_blocklist(blocklist_id: int):
    return _delete(f"/blocklists/{blocklist_id}")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def get_audit(customer_id: int | None = None, limit: int = 100):
    params = f"?limit={limit}"
    if customer_id is not None:
        params += f"&customer_id={customer_id}"
    return _get(f"/audit{params}")
