import labs_client as lc
from labs.base import BaseLab


class GithubLab(BaseLab):
    def _repo(self) -> dict:
        repos = lc.get_repos()
        repo = next((r for r in repos if r["id"] == self.lab_def["repo_id"]), None)
        if repo is None:
            raise RuntimeError("Parent repo not found")
        return repo

    def launch(self, action: str = "deploy", **_) -> dict:
        repo = self._repo()
        return lc.trigger_github_action(
            repo_url=repo["url"],
            lab_id=self.lab_id,
            lab_path=self.lab_def["path"],
            action=action,
        )

    def stop(self) -> None:
        raise RuntimeError("Stop is not supported for github labs")

    def status(self) -> dict:
        return lc.get_lab_run_status(self._repo()["url"])

    def get_targets(self) -> list:
        return lc.get_lab_vms(self.lab_id)
