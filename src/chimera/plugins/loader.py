from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

from chimera.core.exceptions import PluginError
from chimera.core.logging import get_logger
from chimera.core.models import PluginManifest
from chimera.plugins.base import BasePlugin

log = get_logger(__name__)

MANIFEST_FILENAME = "manifest.yaml"


class PluginLoader:
    def discover(self, directory: Path) -> list[BasePlugin]:
        plugins: list[BasePlugin] = []
        if not directory.is_dir():
            log.warning("Plugin directory not found: %s", directory)
            return plugins

        for subdir in sorted(directory.iterdir()):
            if not subdir.is_dir():
                continue
            manifest_path = subdir / MANIFEST_FILENAME
            if not manifest_path.exists():
                log.debug("Skipping %s: no %s", subdir, MANIFEST_FILENAME)
                continue
            try:
                plugin = self._load_plugin(subdir, manifest_path)
                if plugin is not None:
                    plugins.append(plugin)
            except Exception as e:
                log.error("Failed to load plugin from %s: %s", subdir, e)

        return plugins

    def _load_plugin(self, directory: Path, manifest_path: Path) -> BasePlugin | None:
        manifest = self._load_manifest(manifest_path)
        main_module = directory / f"{manifest.name}.py"
        if not main_module.exists():
            main_module = directory / "__init__.py"
        if not main_module.exists():
            log.warning("No plugin module found in %s", directory)
            return None

        spec = importlib.util.spec_from_file_location(
            f"chimera.plugins.{manifest.name}", main_module
        )
        if spec is None or spec.loader is None:
            raise PluginError(f"Could not load spec for {main_module}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                instance = attr()
                instance.manifest = manifest
                return instance

        raise PluginError(f"No BasePlugin subclass found in {main_module}")

    def _load_manifest(self, path: Path) -> PluginManifest:
        with open(path) as f:
            data = yaml.safe_load(f)
        return PluginManifest(**data)
