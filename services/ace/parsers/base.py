from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel


class NormalizedArtifact(BaseModel):
    artifact_type: str
    name: str
    raw: dict[str, Any]
    metadata: dict[str, Any]


class BaseParser(ABC):
    @abstractmethod
    def parse(self, content: str, name: str) -> NormalizedArtifact:
        ...

    @abstractmethod
    def supports(self, filename: str) -> bool:
        ...
