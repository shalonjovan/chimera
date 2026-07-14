from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from chimera.config.settings import settings
from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeStatus

log = get_logger(__name__)


class KnowledgeSystem:
    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or settings.knowledge_dir

    def store_challenge(self, challenge: Challenge) -> Path:
        dir_path = self._base_dir / challenge.id
        dir_path.mkdir(parents=True, exist_ok=True)

        (dir_path / "challenge.json").write_text(
            challenge.model_dump_json(indent=2, exclude_none=True)
        )

        tools = [
            {
                "tool": h.tools[0] if h.tools else "",
                "confidence": h.confidence,
                "evidence": h.evidence,
                "correct": h.is_correct,
            }
            for h in challenge.hypotheses
        ]
        (dir_path / "tools_used.json").write_text(
            json.dumps(tools, indent=2, default=str)
        )

        reasoning = self._build_reasoning(challenge)
        (dir_path / "reasoning.md").write_text(reasoning)

        mistakes = self._build_mistakes(challenge)
        (dir_path / "mistakes.md").write_text(mistakes)

        log.info("Stored knowledge for %s in %s", challenge.id, dir_path)
        return dir_path

    def load_challenge(self, challenge_id: str) -> Challenge | None:
        dir_path = self._base_dir / challenge_id
        json_path = dir_path / "challenge.json"
        if not json_path.exists():
            return None
        try:
            return Challenge.model_validate_json(json_path.read_text())
        except Exception as e:
            log.error("Failed to load knowledge %s: %s", challenge_id, e)
            return None

    def get_reasoning(self, challenge_id: str) -> str | None:
        path = self._base_dir / challenge_id / "reasoning.md"
        if path.exists():
            return path.read_text()
        return None

    def get_mistakes(self, challenge_id: str) -> str | None:
        path = self._base_dir / challenge_id / "mistakes.md"
        if path.exists():
            return path.read_text()
        return None

    def list_challenges(self) -> list[str]:
        if not self._base_dir.is_dir():
            return []
        return sorted(
            d.name for d in self._base_dir.iterdir() if d.is_dir()
        )

    def _build_reasoning(self, challenge: Challenge) -> str:
        lines = [
            f"# Reasoning: {challenge.title}",
            f"",
            f"**ID:** {challenge.id}",
            f"**Category:** {challenge.category.value if challenge.category else 'unknown'}",
            f"**Status:** {challenge.status.value}",
            f"**Flag:** {challenge.flag or 'not found'}",
            f"",
            f"## Description",
            f"{challenge.description}",
            f"",
            f"## Hypotheses",
        ]
        for h in challenge.hypotheses:
            lines.append(f"- {h.description} (confidence={h.confidence:.2f})")
            if h.evidence:
                lines.append(f"  - Evidence: {h.evidence[-1][:100] if h.evidence else 'none'}")
        lines.append("")
        lines.append(f"*Archived: {datetime.utcnow().isoformat()}*")
        return "\n".join(lines)

    def _build_mistakes(self, challenge: Challenge) -> str:
        lines = [
            f"# Mistakes: {challenge.title}",
            f"",
        ]
        failed = [h for h in challenge.hypotheses if h.is_correct is False]
        if failed:
            for h in failed:
                lines.append(f"- {h.description}")
        else:
            lines.append("No significant mistakes recorded.")
        return "\n".join(lines) + "\n"


knowledge = KnowledgeSystem()
