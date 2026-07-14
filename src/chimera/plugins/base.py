from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from chimera.core.models import (
    Challenge,
    ChallengeCategory,
    PluginManifest,
    ToolResult,
)


class BasePlugin(ABC):
    manifest: PluginManifest

    @abstractmethod
    def detect(self, challenge: Challenge) -> float:
        ...

    @abstractmethod
    async def analyze(self, challenge: Challenge) -> Challenge:
        ...

    @abstractmethod
    async def solve(self, challenge: Challenge) -> Challenge:
        ...

    @abstractmethod
    async def verify(self, challenge: Challenge) -> bool:
        ...

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def categories(self) -> list[ChallengeCategory]:
        return self.manifest.categories

    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.name}>"
