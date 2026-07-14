from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from chimera.core.metrics import metrics
from chimera.core.pipeline import pipeline
from chimera.knowledge.system import knowledge
from chimera.memory.engine import memory
from chimera.patterns.library import library
from chimera.plugins.registry import registry

console = Console()


@click.group()
def cli() -> None:
    """Chimera - Autonomous CTF Solver"""
    plugins_dir = Path("plugins")
    if plugins_dir.is_dir():
        registry.load_from_directory(plugins_dir)


@cli.command()
@click.argument("challenge_id")
@click.argument("title")
@click.argument("description")
@click.option("--files", "-f", multiple=True, help="Challenge file paths")
@click.option("--category", "-c", help="Challenge category hint")
def solve(challenge_id: str, title: str, description: str, files: tuple[str, ...], category: str | None) -> None:
    """Solve a CTF challenge through the full pipeline."""
    from chimera.core.models import ChallengeCategory

    cat = None
    if category:
        try:
            cat = ChallengeCategory(category.lower())
        except ValueError:
            console.print(f"[yellow]Unknown category: {category}[/yellow]")

    challenge = asyncio.run(
        pipeline.run(
            challenge_id=challenge_id,
            title=title,
            description=description,
            files=[Path(f) for f in files] if files else None,
            category=cat,
        )
    )

    if challenge.flag:
        console.print(f"\n[bold green]Flag: {challenge.flag}[/bold green]")
    console.print(f"[bold]Status:[/bold] {challenge.status.value}")


@cli.command()
def status() -> None:
    """Show current system status and metrics."""
    console.print(metrics.report())


@cli.command()
def plugins() -> None:
    """List all registered plugins."""
    table = Table(title="Registered Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Categories", style="green")
    table.add_column("Tools")

    for plugin in registry.list_plugins():
        table.add_row(
            plugin.name,
            ", ".join(c.value for c in plugin.categories),
            ", ".join(plugin.manifest.tools),
        )

    if table.rows:
        console.print(table)
    else:
        console.print("[yellow]No plugins registered[/yellow]")


@cli.command()
@click.argument("query")
def search(query: str) -> None:
    """Search through archived challenge knowledge."""
    results = memory.long_term.search_knowledge(query)
    if not results:
        console.print(f"[yellow]No results for '{query}'[/yellow]")
        return

    table = Table(title=f"Knowledge results for '{query}'")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Solved")

    for entry in results:
        table.add_row(
            entry.challenge_id,
            entry.challenge_title,
            entry.category.value if entry.category else "?",
            "✓" if entry.solved else "✗",
        )
    console.print(table)


@cli.command()
def patterns() -> None:
    """List all patterns in the pattern library."""
    patterns = library.list_patterns()
    if not patterns:
        console.print("[yellow]No patterns loaded[/yellow]")
        return

    table = Table(title="Pattern Library")
    table.add_column("Name", style="cyan")
    table.add_column("Conditions")
    table.add_column("Confidence")
    table.add_column("Source")

    for pat in patterns:
        table.add_row(
            pat.name,
            ", ".join(pat.conditions[:3]),
            f"{pat.confidence:.0%}",
            pat.source,
        )
    console.print(table)


@cli.command()
@click.argument("challenge_id")
def show(challenge_id: str) -> None:
    """Show archived knowledge for a challenge."""
    ch = knowledge.load_challenge(challenge_id)
    if ch is None:
        console.print(f"[red]Challenge '{challenge_id}' not found in knowledge[/red]")
        return

    console.print(f"[bold]Title:[/bold] {ch.title}")
    console.print(f"[bold]Category:[/bold] {ch.category.value if ch.category else '?'}")
    console.print(f"[bold]Status:[/bold] {ch.status.value}")
    if ch.flag:
        console.print(f"[bold green]Flag:[/bold green] {ch.flag}")

    reasoning = knowledge.get_reasoning(challenge_id)
    if reasoning:
        console.print(f"\n[bold]Reasoning:[/bold]")
        console.print(reasoning[:500])


@cli.command()
@click.argument("name")
@click.argument("conditions", nargs=-1, required=True)
@click.option("--confidence", "-c", default=0.5, type=float, help="Pattern confidence")
@click.option("--category", "-cat", help="Challenge category")
def add_pattern(name: str, conditions: tuple[str, ...], confidence: float, category: str | None) -> None:
    """Add a new pattern to the pattern library."""
    from chimera.core.models import ChallengeCategory, Pattern

    cat = None
    if category:
        try:
            cat = ChallengeCategory(category.lower())
        except ValueError:
            pass

    pattern = Pattern(
        name=name,
        conditions=list(conditions),
        confidence=confidence,
        category=cat,
        source="cli",
    )

    path = library.add_pattern(pattern)
    console.print(f"[green]Pattern saved to {path}[/green]")


if __name__ == "__main__":
    cli()
