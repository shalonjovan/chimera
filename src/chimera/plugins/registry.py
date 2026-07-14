from __future__ import annotations

from pathlib import Path

from chimera.core.exceptions import PluginNotFoundError
from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory
from chimera.plugins.base import BasePlugin
from chimera.plugins.loader import PluginLoader

log = get_logger(__name__)


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        self._plugins[plugin.name] = plugin
        log.info("Registered plugin: %s (categories: %s)", plugin.name, plugin.categories)

    def get(self, name: str) -> BasePlugin:
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin not found: {name}")
        return plugin

    def list_plugins(self) -> list[BasePlugin]:
        return list(self._plugins.values())

    def get_for_category(self, category: ChallengeCategory) -> list[BasePlugin]:
        return [p for p in self._plugins.values() if category in p.categories]

    def detect_category(self, challenge: Challenge) -> ChallengeCategory | None:
        best_score = 0.0
        best_category: ChallengeCategory | None = None
        for plugin in self._plugins.values():
            score = plugin.detect(challenge)
            if score > best_score:
                best_score = score
                best_category = plugin.categories[0] if plugin.categories else None
        return best_category

    def load_from_directory(self, directory: Path) -> int:
        count = 0
        loader = PluginLoader()
        for plugin in loader.discover(directory):
            self.register(plugin)
            count += 1
        log.info("Loaded %d plugins from %s", count, directory)
        return count


registry = PluginRegistry()
