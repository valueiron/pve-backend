import labs_client as lc
from labs.base import BaseLab


class DockerK8sLab(BaseLab):
    def launch(self, **_) -> dict:
        lc.launch_dockerk8s_lab(self.lab_id)
        return {"run_triggered": True}

    def stop(self) -> None:
        lc.stop_dockerk8s_lab(self.lab_id)

    def status(self) -> dict:
        return lc.get_dockerk8s_status(self.lab_id)

    def get_targets(self) -> list:
        return lc._get_dockerk8s_targets(self.lab_id)
