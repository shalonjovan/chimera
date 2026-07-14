from __future__ import annotations

from pathlib import Path

import yaml

from chimera.config.settings import settings
from chimera.core.logging import get_logger
from chimera.core.models import Challenge, Pattern

log = get_logger(__name__)


class PatternLibrary:
    def __init__(self, patterns_dir: Path | None = None) -> None:
        self._dir = patterns_dir or settings.patterns_dir
        self._patterns: list[Pattern] = []
        self._load()

    def _load(self) -> None:
        if not self._dir.is_dir():
            self._dir.mkdir(parents=True, exist_ok=True)
            return
        for fpath in sorted(self._dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(fpath.read_text())
                self._patterns.append(Pattern(**data))
                log.debug("Loaded pattern: %s", data.get("name"))
            except Exception as e:
                log.warning("Failed to load pattern %s: %s", fpath.name, e)
        log.info("Loaded %d patterns from %s", len(self._patterns), self._dir)

    def match(self, challenge: Challenge) -> list[tuple[Pattern, float]]:
        text_lower = f"{challenge.title} {challenge.description}".lower()
        matches: list[tuple[Pattern, float]] = []

        for pattern in self._patterns:
            matched_conditions = 0
            for condition in pattern.conditions:
                if condition.lower() in text_lower:
                    matched_conditions += 1

            if matched_conditions > 0:
                confidence = pattern.confidence * (
                    matched_conditions / len(pattern.conditions)
                )
                matches.append((pattern, confidence))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    def add_pattern(self, pattern: Pattern) -> Path:
        self._patterns.append(pattern)
        path = self._dir / f"{pattern.name.lower().replace(' ', '_')}.yaml"
        path.write_text(yaml.dump(pattern.model_dump(mode="json"), default_flow_style=False))
        log.info("Added pattern: %s", pattern.name)
        return path

    def list_patterns(self) -> list[Pattern]:
        return self._patterns.copy()

    def get_suggestions(
        self,
        challenge: Challenge,
        min_confidence: float = 0.3,
    ) -> list[tuple[Pattern, float]]:
        return [
            (p, c) for p, c in self.match(challenge) if c >= min_confidence
        ]


library = PatternLibrary()
