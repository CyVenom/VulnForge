"""
VulnForge Plugin Manager
Dynamically loads and executes scanner plugins from the plugins/ directory.
Each plugin must implement the VulnForgePlugin interface.
"""
import asyncio
import importlib.util
import inspect
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult

logger = logging.getLogger("vulnforge.plugin_manager")

# A relative plugins dir means "inside the VulnForge install", never "whatever
# folder the command happened to be run from": plugin files are executed, so
# loading them from the current directory would run code from any directory
# you happen to be standing in.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class VulnForgePlugin(ABC):
    """Base class for all VulnForge plugins."""

    name: str = "unnamed_plugin"
    description: str = ""
    version: str = "1.0.0"
    author: str = ""

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    async def run(self, target: str, scan_result: "ScanResult") -> dict:
        """
        Execute the plugin against target.

        Returns a dict with at minimum:
          {
            "findings": [ { title, severity, description, remediation } ],
            "data": { ... any extra data ... }
          }
        """


class PluginManager:
    """Load, validate, and execute VulnForge plugins."""

    def __init__(self, config: dict):
        self.config = config
        self.plugin_cfg = config.get("plugins", {})
        self.plugins: dict[str, VulnForgePlugin] = {}
        self._loaded = False

    async def load_plugins(self) -> None:
        """Discover and load all plugin modules from the plugins directory."""
        if not self.plugin_cfg.get("enabled", True):
            logger.info("Plugin system disabled in config.")
            return

        plugin_dir = Path(self.plugin_cfg.get("dir", "plugins"))
        if not plugin_dir.is_absolute():
            plugin_dir = PROJECT_ROOT / plugin_dir
        if not plugin_dir.exists():
            logger.info(f"Plugin directory {plugin_dir} not found — skipping.")
            return

        for plugin_file in sorted(plugin_dir.glob("plugin_*.py")):
            await self._load_plugin_file(plugin_file)

        logger.info(f"Loaded {len(self.plugins)} plugin(s): {list(self.plugins.keys())}")
        self._loaded = True

    async def _load_plugin_file(self, path: Path) -> None:
        """Import a single plugin file and register valid plugin classes."""
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if not spec or not spec.loader:
                return

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[attr-defined]

            for attr_name in dir(module):
                cls = getattr(module, attr_name)
                if (
                    inspect.isclass(cls)
                    and issubclass(cls, VulnForgePlugin)
                    and cls is not VulnForgePlugin
                ):
                    instance = cls(self.config)
                    self.plugins[instance.name] = instance
                    logger.debug(f"Registered plugin: {instance.name} v{instance.version}")

        except Exception as exc:
            logger.error(f"Failed to load plugin {path.name}: {exc}", exc_info=True)

    async def run_all(self, target: str, scan_result: "ScanResult") -> dict:
        """Run all loaded plugins concurrently."""
        if not self.plugins:
            return {}

        tasks = {
            name: asyncio.create_task(self._run_plugin(name, plugin, target, scan_result))
            for name, plugin in self.plugins.items()
        }

        results = {}
        done = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), done):
            if isinstance(result, Exception):
                logger.error(f"Plugin {name} raised: {result}")
                results[name] = {"error": str(result), "findings": []}
            else:
                results[name] = result

        return results

    async def _run_plugin(
        self, name: str, plugin: VulnForgePlugin, target: str, scan_result: "ScanResult"
    ) -> dict:
        logger.debug(f"Running plugin: {name}")
        try:
            result = await asyncio.wait_for(
                plugin.run(target, scan_result),
                timeout=60,
            )
            findings_count = len(result.get("findings", []))
            logger.info(f"Plugin {name} completed: {findings_count} finding(s)")
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Plugin {name} timed out")
            return {"error": "Plugin timed out", "findings": []}
