from __future__ import annotations

from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.pipeline import pipeline
from chimera.core.server import server
from chimera.memory.engine import memory

log = get_logger(__name__)


@server.tool(description="Run the full challenge lifecycle on a CTF challenge")
async def solve_challenge(
    challenge_id: str,
    title: str,
    description: str,
    files: list[str] | None = None,
) -> str:
    challenge = await pipeline.run(
        challenge_id=challenge_id,
        title=title,
        description=description,
        files=[Path(f) for f in files] if files else None,
    )
    return challenge.model_dump_json(indent=2)


@server.tool(description="Search past challenge knowledge")
def search_knowledge(query: str) -> str:
    results = memory.long_term.search_knowledge(query)
    if not results:
        return "No results found."
    lines = [f"- {k.challenge_id}: {k.challenge_title} ({k.solved=})" for k in results]
    return "\n".join(lines)


@server.tool(description="List all registered plugins")
def list_plugins() -> str:
    from chimera.plugins.registry import registry

    plugins = registry.list_plugins()
    if not plugins:
        return "No plugins registered."
    lines = [f"- {p.name}: categories={[c.value for c in p.categories]}" for p in plugins]
    return "\n".join(lines)
