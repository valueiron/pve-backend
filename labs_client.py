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
LAB_STATE_FILE = Path(__file__).parent / "lab_state.json"
LABS_DIR = Path(os.getenv("LABS_DIR", "./labs_repos")).resolve()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
DOCKER_API_URL = os.getenv("DOCKER_API_URL", "http://localhost:8080")
K8S_API_URL = os.getenv("K8S_API_URL", "http://localhost:8081")


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


def _load_lab_state() -> dict:
    if LAB_STATE_FILE.exists():
        with LAB_STATE_FILE.open() as f:
            return json.load(f)
    return {}


def _save_lab_state(data: dict) -> None:
    with LAB_STATE_FILE.open("w") as f:
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
        "type": meta.get("type", "github"),  # "github" (default) or "dockerk8s"
        "difficulty": meta.get("difficulty", "beginner"),
        "estimated_time": meta.get("estimated_time", ""),
        "tags": meta.get("tags", []),
        "clouds": meta.get("clouds", []),
        "path": relative_path,
        "lab_path": str(lab_folder),
        "vms": vms,
        # Optional manifest filenames (relative to the lab directory)
        "docker_compose": meta.get("docker_compose"),  # e.g. "docker-compose.yml"
        "k8s_manifest": meta.get("k8s_manifest"),      # e.g. "k8s-manifest.yaml"
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
    """Merge static VMs (from lab.yml) + dynamic VMs (registered by GitHub Actions).
    For dockerk8s labs, returns the live container/pod targets from state instead."""
    try:
        lab = get_lab(lab_id)
    except KeyError:
        lab = {}

    if lab.get("type") == "dockerk8s":
        return _get_dockerk8s_targets(lab_id)

    static_vms = lab.get("vms", [])
    data = _load_lab_vms()
    dynamic_vms = data.get(lab_id, [])

    # Dynamic overrides static for same vmid
    merged = {v["vmid"]: v for v in static_vms}
    for v in dynamic_vms:
        merged[v["vmid"]] = v
    return list(merged.values())


# ---------------------------------------------------------------------------
# Docker + Kubernetes local lab support
# ---------------------------------------------------------------------------

def _launch_from_compose(compose_path: Path, project_name: str) -> list:
    """Parse a docker-compose.yml and create one container per service.

    Returns a list of dicts: [{"service": ..., "id": ..., "name": ...}]
    """
    with compose_path.open() as f:
        compose = yaml.safe_load(f) or {}

    services = compose.get("services", {})
    if not services:
        raise RuntimeError(f"docker-compose.yml has no services defined: {compose_path}")

    containers = []
    for service_name, svc in services.items():
        container_name = f"{project_name}-{service_name}"
        payload: dict = {
            "image": svc.get("image", "ubuntu:24.04"),
            "name": container_name,
        }

        cmd = svc.get("command")
        if cmd is not None:
            payload["command"] = cmd.split() if isinstance(cmd, str) else list(cmd)

        env = svc.get("environment")
        if env is not None:
            if isinstance(env, dict):
                payload["environment"] = [f"{k}={v}" for k, v in env.items()]
            else:
                payload["environment"] = list(env)

        labels = svc.get("labels")
        if labels is not None:
            if isinstance(labels, list):
                labels_dict: dict = {}
                for item in labels:
                    k, _, v = str(item).partition("=")
                    labels_dict[k] = v
                payload["labels"] = labels_dict
            else:
                payload["labels"] = dict(labels)

        volumes = svc.get("volumes")
        if volumes is not None:
            payload["binds"] = [str(v) for v in volumes]

        resp = requests.post(
            f"{DOCKER_API_URL}/containers/run",
            json=payload,
            timeout=120,
        )
        if not resp.ok:
            raise RuntimeError(
                f"Docker container creation failed for service '{service_name}': {resp.text}"
            )
        containers.append({
            "service": service_name,
            "id": resp.json()["id"],
            "name": container_name,
        })

    return containers


def _apply_k8s_manifest(manifest_path: Path) -> list:
    """POST a raw YAML manifest to k8s-api /manifests/apply.

    Returns a list of dicts: [{"kind": ..., "name": ..., "namespace": ...}]
    """
    manifest_yaml = manifest_path.read_text()
    resp = requests.post(
        f"{K8S_API_URL}/manifests/apply",
        data=manifest_yaml.encode(),
        headers={"Content-Type": "text/plain; charset=utf-8"},
        timeout=60,
    )
    if not resp.ok:
        raise RuntimeError(f"K8s manifest apply failed: {resp.text}")
    return resp.json().get("applied", [])


def launch_dockerk8s_lab(lab_id: str) -> dict:
    """Provision Docker container(s) and K8s resource(s) for a dockerk8s lab.

    Provisioning is driven entirely by manifest files referenced in lab.yml:
      docker_compose  — path (relative to the lab dir) to a docker-compose.yml
      k8s_manifest    — path (relative to the lab dir) to a Kubernetes YAML manifest

    At least one of the two must be present. Neither key causes a RuntimeError.
    """
    import re
    lab = get_lab(lab_id)
    lab_path = Path(lab["lab_path"])
    short = re.sub(r"[^a-z0-9]", "", lab_id.lower())[:16]
    project_name = f"lab-{short}"

    compose_file = lab.get("docker_compose")
    k8s_manifest_file = lab.get("k8s_manifest")
    if not compose_file and not k8s_manifest_file:
        raise RuntimeError(
            "Lab has no manifest files defined. Add 'docker_compose' and/or "
            "'k8s_manifest' keys to lab.yml pointing to files in the lab directory."
        )

    state_entry: dict = {"type": "dockerk8s", "launched_at": _now_iso()}

    # ── Docker provisioning ────────────────────────────────────────────────
    if compose_file:
        compose_path = lab_path / compose_file
        if not compose_path.exists():
            raise RuntimeError(f"docker_compose file not found: {compose_path}")
        state_entry["docker_containers"] = _launch_from_compose(compose_path, project_name)
        state_entry["docker_project"] = project_name

    # ── K8s provisioning ──────────────────────────────────────────────────
    if k8s_manifest_file:
        manifest_path = lab_path / k8s_manifest_file
        if not manifest_path.exists():
            raise RuntimeError(f"k8s_manifest file not found: {manifest_path}")
        state_entry["k8s_resources"] = _apply_k8s_manifest(manifest_path)

    state = _load_lab_state()
    state[lab_id] = state_entry
    _save_lab_state(state)
    return state_entry


def stop_dockerk8s_lab(lab_id: str) -> None:
    """Deprovision all Docker containers and K8s resources for a dockerk8s lab."""
    state = _load_lab_state()
    entry = state.get(lab_id)
    if not entry:
        return

    for c in entry.get("docker_containers", []):
        try:
            requests.delete(
                f"{DOCKER_API_URL}/containers/{c['id']}",
                params={"force": "true"},
                timeout=30,
            )
        except Exception:
            pass

    for res in entry.get("k8s_resources", []):
        try:
            ns = res.get("namespace") or "_"
            requests.delete(
                f"{K8S_API_URL}/manifests/{ns}/{res['kind']}/{res['name']}",
                params={"force": "true"},
                timeout=30,
            )
        except Exception:
            pass

    del state[lab_id]
    _save_lab_state(state)


def get_dockerk8s_status(lab_id: str) -> dict:
    """Return a status dict for a dockerk8s lab (mirrors get_lab_run_status shape)."""
    state = _load_lab_state()
    entry = state.get(lab_id)
    if not entry:
        return {"status": "idle", "conclusion": None, "run_id": None, "html_url": None}

    containers_ok = _check_containers(entry.get("docker_containers", []))
    pods_ok = _check_pods(entry.get("k8s_resources", []))

    if containers_ok and pods_ok:
        return {"status": "completed", "conclusion": "success", "run_id": None, "html_url": None}
    return {"status": "in_progress", "conclusion": None, "run_id": None, "html_url": None}


def _check_containers(containers: list) -> bool:
    for c in containers:
        try:
            resp = requests.get(f"{DOCKER_API_URL}/containers/{c['id']}", timeout=10)
            if not resp.ok or resp.json().get("State", {}).get("Status") != "running":
                return False
        except Exception:
            return False
    return True


def _check_pods(resources: list) -> bool:
    pods = [r for r in resources if r.get("kind") == "Pod"]
    if not pods:
        return True  # No pods defined (e.g. Docker-only lab or only Services/ConfigMaps)
    for pod in pods:
        try:
            ns = pod.get("namespace", "default")
            resp = requests.get(f"{K8S_API_URL}/pods/{ns}/{pod['name']}", timeout=10)
            if not resp.ok:
                return False
            phase = resp.json().get("status", {}).get("phase", "")
            if phase not in ("Running", "Succeeded"):
                return False
        except Exception:
            return False
    return True


def _get_dockerk8s_targets(lab_id: str) -> list:
    """Return exec targets for a dockerk8s lab."""
    state = _load_lab_state()
    entry = state.get(lab_id)
    if not entry:
        return []

    targets = []

    for c in entry.get("docker_containers", []):
        try:
            resp = requests.get(f"{DOCKER_API_URL}/containers/{c['id']}", timeout=10)
            if resp.ok and resp.json().get("State", {}).get("Status") == "running":
                targets.append({
                    "vmid": f"docker-{c['service']}",
                    "name": f"Docker: {c['service']}",
                    "type": "docker",
                    "container_id": c["id"],
                })
        except Exception:
            pass

    for res in entry.get("k8s_resources", []):
        if res.get("kind") != "Pod":
            continue
        try:
            ns = res.get("namespace", "default")
            resp = requests.get(f"{K8S_API_URL}/pods/{ns}/{res['name']}", timeout=10)
            if resp.ok and resp.json().get("status", {}).get("phase") in ("Running", "Succeeded"):
                targets.append({
                    "vmid": f"k8s-{res['name']}",
                    "name": f"K8s: {res['name']}",
                    "type": "k8s",
                    "namespace": ns,
                    "pod": res["name"],
                })
        except Exception:
            pass

    return targets


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
