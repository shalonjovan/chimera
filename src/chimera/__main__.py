import asyncio
import sys

from chimera.config.settings import settings
from chimera.core.logging import setup_logging
from chimera.core.server import server


def main() -> int:
    setup_logging()

    if settings.mcp_transport == "sse":
        server.run_sse()
        return 0
    else:
        asyncio.run(server.run_stdio())
        return 0


if __name__ == "__main__":
    sys.exit(main())
