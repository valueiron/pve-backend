"""
Labs routes — Flask Blueprint exposing labs management endpoints.

Prefix: /api/labs
"""

from flask import Blueprint, jsonify, request

import labs_client as lc
from labs.registry import create_lab

labs_bp = Blueprint("labs", __name__, url_prefix="/api/labs")


def _err(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


# ---------------------------------------------------------------------------
# Repo endpoints
# ---------------------------------------------------------------------------

@labs_bp.get("/repos")
def list_repos():
    try:
        repos = lc.get_repos()
        return jsonify({"repos": repos})
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/repos")
def add_repo():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    url = body.get("url", "").strip()
    branch = body.get("branch", "main").strip() or "main"

    if not name:
        return _err("'name' is required")
    if not url:
        return _err("'url' is required")

    try:
        repo = lc.add_repo(name, url, branch)
        return jsonify({"repo": repo}), 201
    except RuntimeError as e:
        return _err(str(e), 422)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.delete("/repos/<repo_id>")
def delete_repo(repo_id: str):
    try:
        lc.delete_repo(repo_id)
        return jsonify({"deleted": True})
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/repos/<repo_id>/sync")
def sync_repo(repo_id: str):
    try:
        repo = lc.sync_repo(repo_id)
        return jsonify({"repo": repo})
    except KeyError as e:
        return _err(str(e), 404)
    except RuntimeError as e:
        return _err(str(e), 422)
    except Exception as e:
        return _err(str(e), 500)


# ---------------------------------------------------------------------------
# Lab endpoints
# ---------------------------------------------------------------------------

@labs_bp.get("")
def list_labs():
    try:
        labs = lc.get_all_labs()
        return jsonify({"labs": labs})
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.get("/<path:lab_id>/instructions")
def get_lab_instructions(lab_id: str):
    try:
        md = lc.get_lab_instructions(lab_id)
        return jsonify({"instructions": md})
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/<path:lab_id>/launch")
def launch_lab(lab_id: str):
    body = request.get_json(silent=True) or {}
    try:
        lab_def = lc.get_lab(lab_id)
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    try:
        result = create_lab(lab_def).launch(**body)
        return jsonify(result)
    except RuntimeError as e:
        return _err(str(e), 422)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.get("/<path:lab_id>/vms")
def get_lab_vms(lab_id: str):
    try:
        lab_def = lc.get_lab(lab_id)
        return jsonify({"vms": create_lab(lab_def).get_targets()})
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/<path:lab_id>/vms")
def register_lab_vms(lab_id: str):
    body = request.get_json(silent=True) or {}
    vms = body.get("vms", [])
    if not isinstance(vms, list):
        return _err("'vms' must be an array")
    try:
        registered = lc.register_lab_vms(lab_id, vms)
        return jsonify({"vms": registered}), 201
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/<path:lab_id>/stop")
def stop_lab(lab_id: str):
    try:
        lab_def = lc.get_lab(lab_id)
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    try:
        create_lab(lab_def).stop()
        return jsonify({"stopped": True})
    except RuntimeError as e:
        return _err(str(e), 400)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.post("/<path:lab_id>/validate")
def validate_lab(lab_id: str):
    try:
        result = lc.run_lab_validation(lab_id)
        return jsonify(result)
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    except RuntimeError as e:
        return _err(str(e), 422)
    except Exception as e:
        return _err(str(e), 500)


@labs_bp.get("/<path:lab_id>/status")
def get_lab_status(lab_id: str):
    try:
        lab_def = lc.get_lab(lab_id)
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    try:
        return jsonify(create_lab(lab_def).status())
    except RuntimeError as e:
        return _err(str(e), 422)
    except Exception as e:
        return _err(str(e), 500)


# ---------------------------------------------------------------------------
# Generic lab detail — must be registered LAST so the sub-routes above
# (/<path:lab_id>/vms, /status, /instructions, etc.) are tried first.
# ---------------------------------------------------------------------------

@labs_bp.get("/<path:lab_id>")
def get_lab(lab_id: str):
    try:
        lab = lc.get_lab(lab_id)
        return jsonify({"lab": lab})
    except KeyError:
        return _err(f"Lab '{lab_id}' not found", 404)
    except Exception as e:
        return _err(str(e), 500)
