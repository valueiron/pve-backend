from abc import ABC, abstractmethod


class BaseLab(ABC):
    def __init__(self, lab_def: dict):
        self.lab_def = lab_def
        self.lab_id = lab_def["id"]

    @abstractmethod
    def launch(self, **kwargs) -> dict: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def status(self) -> dict: ...

    @abstractmethod
    def get_targets(self) -> list: ...
