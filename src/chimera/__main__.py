import asyncio
import sys
from pathlib import Path

from chimera.config.settings import settings
from chimera.core.logging import setup_logging
from chimera.core.server import server
from chimera.plugins.registry import registry
from chimera.tools.builtin import register_builtin_tools


def main() -> int:
    setup_logging()
    register_builtin_tools()

    import chimera.core.tools

    plugins_dir = Path("plugins")
    if plugins_dir.is_dir():
        registry.load_from_directory(plugins_dir)

    if settings.mcp_transport == "sse":
        asyncio.run(server.run_sse())
        return 0
    else:
        server.run_stdio()
        return 0


if __name__ == "__main__":
    sys.exit(main())
