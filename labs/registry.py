from labs.base import BaseLab
from labs.chromium_lab import ChromiumLab
from labs.codeserver_lab import CodeServerLab
from labs.dockerk8s_lab import DockerK8sLab
from labs.github_lab import GithubLab

_REGISTRY: dict[str, type[BaseLab]] = {
    "dockerk8s": DockerK8sLab,
    "codeserver": CodeServerLab,
    "chromium": ChromiumLab,
    "github": GithubLab,
}


def create_lab(lab_def: dict) -> BaseLab:
    cls = _REGISTRY.get(lab_def.get("type", "github"), GithubLab)
    return cls(lab_def)
