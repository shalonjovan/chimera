from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from chimera.config.settings import settings
from chimera.core.logging import get_logger

log = get_logger(__name__)

ToolFunc = Callable[..., Any]


class ChimeraServer:
    def __init__(self) -> None:
        self.mcp = FastMCP(
            name=settings.project_name,
            log_level=settings.log_level.upper(),
            host=settings.mcp_host,
            port=settings.mcp_port,
        )
        self._tools: dict[str, ToolFunc] = {}

    def tool(
        self,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[[ToolFunc], ToolFunc]:
        def decorator(fn: ToolFunc) -> ToolFunc:
            tool_name = name or fn.__name__
            self.mcp.add_tool(fn, name=tool_name, description=description)
            self._tools[tool_name] = fn
            log.debug("Registered tool: %s", tool_name)
            return fn

        return decorator

    def register_tool(
        self,
        fn: ToolFunc,
        name: str | None = None,
        description: str | None = None,
    ) -> ToolFunc:
        tool_name = name or fn.__name__
        self.mcp.add_tool(fn, name=tool_name, description=description)
        self._tools[tool_name] = fn
        log.debug("Registered tool: %s", tool_name)
        return fn

    def get_tool(self, name: str) -> ToolFunc | None:
        return self._tools.get(name)

    def run_stdio(self) -> None:
        log.info(
            "Starting Chimera MCP server (stdio transport, log_level=%s)",
            settings.log_level,
        )
        self.mcp.run(transport="stdio")
        log.info("MCP server stopped")

    async def run_sse(self) -> None:
        log.info(
            "Starting Chimera MCP server on %s:%s (SSE transport)",
            settings.mcp_host,
            settings.mcp_port,
        )
        await self.mcp.run_sse_async()


server = ChimeraServer()
