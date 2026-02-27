"""
Labs client — core logic for managing GitHub lab repositories and triggering runs.

Repos are persisted in repos.json (next to this file).
Cloned repos live under LABS_DIR (env var, default ./labs_repos).
Each lab folder must contain a lab.yml with metadata.
"""

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

REPOS_FILE = Path(__file__).parent / "repos.json"
LAB_VMS_FILE = Path(__file__).parent / "lab_vms.json"
LABS_DIR = Path(os.getenv("LABS_DIR", "./labs_repos")).resolve()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_repos() -> list:
    if REPOS_FILE.exists():
        with REPOS_FILE.open() as f:
            return json.load(f)
    return []


def _save_repos(repos: list) -> None:
    with REPOS_FILE.open("w") as f:
        json.dump(repos, f, indent=2)


def _load_lab_vms() -> dict:
    if LAB_VMS_FILE.exists():
        with LAB_VMS_FILE.open() as f:
            return json.load(f)
    return {}


def _save_lab_vms(data: dict) -> None:
    with LAB_VMS_FILE.open("w") as f:
        json.dump(data, f, indent=2)


def _repo_dir(repo_id: str) -> Path:
    return LABS_DIR / repo_id


def _run(cmd: list, cwd: Path = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_owner_repo(url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL."""
    # Handles https://github.com/owner/repo and https://github.com/owner/repo.git
    parts = url.rstrip("/").rstrip(".git").split("/")
    return parts[-2], parts[-1]


# ---------------------------------------------------------------------------
# Repo management
# ---------------------------------------------------------------------------

def get_repos() -> list:
    """Return list of configured repos."""
    return _load_repos()


def _auth_url(url: str) -> str:
    """Return the URL with the GitHub token embedded so git never prompts."""
    if not GITHUB_TOKEN:
        return url
    # Inject token: https://TOKEN@github.com/owner/repo
    return url.replace("https://", f"https://{GITHUB_TOKEN}@", 1)


def add_repo(name: str, url: str, branch: str = "main") -> dict:
    """Clone a GitHub repo and register it. Returns the new repo dict."""
    repos = _load_repos()

    repo_id = str(uuid.uuid4())
    dest = _repo_dir(repo_id)
    LABS_DIR.mkdir(parents=True, exist_ok=True)

    clone_url = _auth_url(url)
    result = _run(["git", "clone", "--branch", branch, "--depth", "1", clone_url, str(dest)])
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

    repo = {
        "id": repo_id,
        "name": name,
        "url": url,
        "branch": branch,
        "last_synced": _now_iso(),
    }
    repos.append(repo)
    _save_repos(repos)
    return repo


def delete_repo(repo_id: str) -> None:
    """Remove a repo from the registry and delete its local clone."""
    repos = _load_repos()
    repos = [r for r in repos if r["id"] != repo_id]
    _save_repos(repos)

    dest = _repo_dir(repo_id)
    if dest.exists():
        import shutil
        shutil.rmtree(str(dest))


def sync_repo(repo_id: str) -> dict:
    """Run git pull in a cloned repo and update last_synced."""
    repos = _load_repos()
    repo = next((r for r in repos if r["id"] == repo_id), None)
    if repo is None:
        raise KeyError(f"Repo {repo_id} not found")

    dest = _repo_dir(repo_id)

    # Update the remote URL to include the current token before pulling
    auth_url = _auth_url(repo["url"])
    _run(["git", "remote", "set-url", "origin", auth_url], cwd=dest)

    result = _run(["git", "pull"], cwd=dest)
    if result.returncode != 0:
        raise RuntimeError(f"git pull failed: {result.stderr.strip()}")

    repo["last_synced"] = _now_iso()
    _save_repos(repos)
    return repo


# ---------------------------------------------------------------------------
# Lab discovery
# ---------------------------------------------------------------------------

def _parse_lab_yml(lab_yml_path: Path, repo_id: str) -> dict | None:
    """Parse a lab.yml file and return a lab dict, or None on error."""
    try:
        with lab_yml_path.open() as f:
            meta = yaml.safe_load(f) or {}
    except Exception:
        return None

    lab_folder = lab_yml_path.parent
    repo_dir = _repo_dir(repo_id)
    relative_path = str(lab_folder.relative_to(repo_dir))

    lab_id = f"{repo_id}/{relative_path}".replace("/", "_").replace("\\", "_")

    raw_vms = meta.get("vms", [])
    vms = []
    for v in raw_vms:
        if isinstance(v, dict) and "vmid" in v:
            vms.append({
                "vmid": int(v["vmid"]),
                "name": str(v.get("name", f"VM {v['vmid']}")),
                "source": "static",
            })

    return {
        "id": lab_id,
        "name": meta.get("name", lab_folder.name),
        "description": meta.get("description", ""),
        "repo_id": repo_id,
        "difficulty": meta.get("difficulty", "beginner"),
        "estimated_time": meta.get("estimated_time", ""),
        "tags": meta.get("tags", []),
        "clouds": meta.get("clouds", []),
        "path": relative_path,
        "lab_path": str(lab_folder),
        "vms": vms,
    }


def get_all_labs() -> list:
    """Walk all cloned repos and return labs with a lab.yml file."""
    repos = _load_repos()
    labs = []
    for repo in repos:
        repo_dir = _repo_dir(repo["id"])
        if not repo_dir.exists():
            continue
        for lab_yml in repo_dir.rglob("lab.yml"):
            lab = _parse_lab_yml(lab_yml, repo["id"])
            if lab:
                labs.append(lab)
    return labs


def get_lab(lab_id: str) -> dict:
    """Return a single lab dict by ID."""
    for lab in get_all_labs():
        if lab["id"] == lab_id:
            return lab
    raise KeyError(f"Lab {lab_id} not found")


def get_lab_instructions(lab_id: str) -> str:
    """Return the contents of instructions.md for a lab."""
    lab = get_lab(lab_id)
    instructions_path = Path(lab["lab_path"]) / "instructions.md"
    if not instructions_path.exists():
        return "# No instructions found\n\nThis lab does not have an `instructions.md` file."
    return instructions_path.read_text()


def register_lab_vms(lab_id: str, vms: list) -> list:
    """Store dynamically posted VMs (from GitHub Actions). Replaces previous dynamic entries."""
    data = _load_lab_vms()
    validated = []
    for v in vms:
        if not isinstance(v, dict) or "vmid" not in v:
            continue
        validated.append({
            "vmid": int(v["vmid"]),
            "name": str(v.get("name", f"VM {v['vmid']}")),
            "source": "dynamic",
            "registered_at": _now_iso(),
        })
    data[lab_id] = validated
    _save_lab_vms(data)
    return validated


def get_lab_vms(lab_id: str) -> list:
    """Merge static VMs (from lab.yml) + dynamic VMs (registered by GitHub Actions)."""
    try:
        lab = get_lab(lab_id)
        static_vms = lab.get("vms", [])
    except KeyError:
        static_vms = []

    data = _load_lab_vms()
    dynamic_vms = data.get(lab_id, [])

    # Dynamic overrides static for same vmid
    merged = {v["vmid"]: v for v in static_vms}
    for v in dynamic_vms:
        merged[v["vmid"]] = v
    return list(merged.values())


# ---------------------------------------------------------------------------
# GitHub Actions
# ---------------------------------------------------------------------------

def _github_headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def trigger_github_action(
    repo_url: str,
    lab_id: str,
    lab_path: str,
    action: str = "deploy",
    workflow_file: str = "deploy-lab.yml",
) -> dict:
    """Dispatch a workflow_dispatch event for the given lab."""
    owner, repo = _parse_owner_repo(repo_url)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches"

    # Look up the branch for this repo
    repos = _load_repos()
    matching = next((r for r in repos if r["url"].rstrip("/").rstrip(".git") == repo_url.rstrip("/").rstrip(".git")), None)
    branch = matching["branch"] if matching else "main"

    payload = {
        "ref": branch,
        "inputs": {
            "lab_id": lab_id,
            "lab_path": lab_path,
            "action": action,
        },
    }

    resp = requests.post(api_url, headers=_github_headers(), json=payload, timeout=15)
    if resp.status_code not in (200, 201, 204):
        raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text}")

    return {"run_triggered": True}


def get_lab_run_status(repo_url: str, workflow_file: str = "deploy-lab.yml") -> dict:
    """Return the status of the most recent workflow run."""
    owner, repo = _parse_owner_repo(repo_url)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_file}/runs"

    resp = requests.get(
        api_url,
        headers=_github_headers(),
        params={"per_page": 1},
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text}")

    data = resp.json()
    runs = data.get("workflow_runs", [])
    if not runs:
        return {"status": "idle", "conclusion": None, "run_id": None, "html_url": None}

    run = runs[0]
    return {
        "status": run.get("status"),        # queued | in_progress | completed
        "conclusion": run.get("conclusion"), # success | failure | cancelled | None
        "run_id": run.get("id"),
        "html_url": run.get("html_url"),
    }
