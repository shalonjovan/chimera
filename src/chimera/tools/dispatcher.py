from __future__ import annotations

import time
from typing import Any

from chimera.core.exceptions import ToolExecutionError, ValidationError
from chimera.core.logging import get_logger
from chimera.core.models import ToolResult
from chimera.plugins.registry import registry

log = get_logger(__name__)


class ToolDispatcher:
    def __init__(self) -> None:
        self._builtin_tools: dict[str, Any] = {}

    def register_builtin(self, name: str, fn: Any) -> None:
        self._builtin_tools[name] = fn
        log.debug("Registered builtin tool: %s", name)

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> ToolResult:
        args = arguments or {}
        start = time.monotonic()

        if tool_name in self._builtin_tools:
            fn = self._builtin_tools[tool_name]
            return await self._run_tool(fn, tool_name, args, start)

        for plugin in registry.list_plugins():
            if tool_name in plugin.manifest.tools or tool_name == plugin.name:
                return await self._run_plugin_tool(plugin, tool_name, args, start)

        raise ToolExecutionError(f"Unknown tool: {tool_name}")

    async def analyze_with_plugins(
        self,
        challenge: Any,
    ) -> list[ToolResult]:
        results: list[ToolResult] = []
        for plugin in registry.get_for_category(challenge.category):
            start = time.monotonic()
            try:
                await plugin.analyze(challenge)
                results.append(
                    ToolResult(
                        tool_name=plugin.name,
                        arguments={"action": "analyze"},
                        success=True,
                        duration_ms=int((time.monotonic() - start) * 1000),
                    )
                )
            except Exception as e:
                log.error("Plugin %s analyze failed: %s", plugin.name, e)
                results.append(
                    ToolResult(
                        tool_name=plugin.name,
                        arguments={"action": "analyze"},
                        success=False,
                        error=str(e),
                        duration_ms=int((time.monotonic() - start) * 1000),
                    )
                )
        return results

    async def _run_tool(
        self,
        fn: Any,
        tool_name: str,
        args: dict[str, Any],
        start: float,
    ) -> ToolResult:
        try:
            result = fn(**args)
            if hasattr(result, "__await__"):
                result = await result
            duration = int((time.monotonic() - start) * 1000)
            return ToolResult(
                tool_name=tool_name,
                arguments=args,
                stdout=str(result) if result is not None else "",
                success=True,
                duration_ms=duration,
            )
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            log.error("Tool %s failed: %s", tool_name, e)
            return ToolResult(
                tool_name=tool_name,
                arguments=args,
                success=False,
                error=str(e),
                duration_ms=duration,
            )

    async def _run_plugin_tool(
        self,
        plugin: Any,
        tool_name: str,
        args: dict[str, Any],
        start: float,
    ) -> ToolResult:
        try:
            action = args.get("action", "analyze")
            challenge = args.get("challenge")
            if challenge is None:
                raise ValidationError("Missing 'challenge' argument for plugin tool")

            if action == "detect":
                score = plugin.detect(challenge)
                duration = int((time.monotonic() - start) * 1000)
                return ToolResult(
                    tool_name=tool_name,
                    arguments=args,
                    stdout=str(score),
                    success=True,
                    duration_ms=duration,
                )
            elif action == "analyze":
                await plugin.analyze(challenge)
            elif action == "solve":
                await plugin.solve(challenge)
            elif action == "verify":
                result = await plugin.verify(challenge)

            duration = int((time.monotonic() - start) * 1000)
            return ToolResult(
                tool_name=tool_name,
                arguments=args,
                success=True,
                duration_ms=duration,
            )
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            log.error("Plugin tool %s failed: %s", tool_name, e)
            return ToolResult(
                tool_name=tool_name,
                arguments=args,
                success=False,
                error=str(e),
                duration_ms=duration,
            )


dispatcher = ToolDispatcher()
