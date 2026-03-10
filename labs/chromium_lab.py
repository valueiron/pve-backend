import labs_client as lc
from labs.base import BaseLab


class ChromiumLab(BaseLab):
    def launch(self, chrome_url: str = "https://www.google.com", **_) -> dict:
        lc.launch_chromium_lab(self.lab_id, chrome_url)
        return {"run_triggered": True}

    def stop(self) -> None:
        lc.stop_chromium_lab(self.lab_id)

    def status(self) -> dict:
        return lc.get_chromium_status(self.lab_id)

    def get_targets(self) -> list:
        return lc._get_chromium_targets(self.lab_id)
