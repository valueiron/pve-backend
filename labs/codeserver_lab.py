import labs_client as lc
from labs.base import BaseLab


class CodeServerLab(BaseLab):
    def launch(self, **_) -> dict:
        lc.launch_codeserver_lab(self.lab_id)
        return {"run_triggered": True}

    def stop(self) -> None:
        lc.stop_codeserver_lab(self.lab_id)

    def status(self) -> dict:
        return lc.get_codeserver_status(self.lab_id)

    def get_targets(self) -> list:
        return lc._get_codeserver_targets(self.lab_id)
