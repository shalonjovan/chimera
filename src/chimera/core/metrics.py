from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from chimera.memory.engine import memory
from chimera.patterns.library import library


class Metrics:
    @property
    def total_challenges(self) -> int:
        return len(memory.long_term._knowledge)

    @property
    def solved_challenges(self) -> int:
        return sum(1 for k in memory.long_term._knowledge if k.solved)

    @property
    def failed_challenges(self) -> int:
        return self.total_challenges - self.solved_challenges

    @property
    def solve_rate(self) -> float:
        if self.total_challenges == 0:
            return 0.0
        return self.solved_challenges / self.total_challenges

    @property
    def total_failures(self) -> int:
        return len(memory.long_term._failures)

    @property
    def total_patterns(self) -> int:
        return len(library.list_patterns())

    @property
    def total_plugins(self) -> int:
        from chimera.plugins.registry import registry
        return len(registry.list_plugins())

    @property
    def knowledge_growth(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for k in memory.long_term._knowledge:
            cat = k.category.value if k.category else "unknown"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def recent_activity(self, days: int = 7) -> int:
        cutoff = datetime.utcnow() - timedelta(days=days)
        return sum(
            1 for k in memory.long_term._knowledge
            if k.created_at > cutoff
        )

    def report(self) -> str:
        lines = [
            "=== Chimera Metrics ===",
            f"",
            f"Challenges: {self.total_challenges} total, {self.solved_challenges} solved, {self.failed_challenges} failed",
            f"Solve rate: {self.solve_rate:.1%}",
            f"Failures recorded: {self.total_failures}",
            f"Patterns in library: {self.total_patterns}",
            f"Plugins loaded: {self.total_plugins}",
            f"Recent activity (7d): {self.recent_activity()}",
            f"",
            f"Knowledge by category:",
        ]
        for cat, count in sorted(self.knowledge_growth.items()):
            lines.append(f"  {cat}: {count}")
        return "\n".join(lines)


metrics = Metrics()
