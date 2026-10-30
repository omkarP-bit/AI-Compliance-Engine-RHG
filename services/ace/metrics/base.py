from __future__ import annotations

from abc import ABC, abstractmethod


class MetricsClient(ABC):
    @abstractmethod
    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None: ...

    @abstractmethod
    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None: ...

    @abstractmethod
    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None: ...
