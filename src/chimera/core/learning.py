from __future__ import annotations

from pathlib import Path

import yaml

from chimera.core.exceptions import ChimeraError
from chimera.core.logging import get_logger
from chimera.core.models import Challenge, FailureRecord, Pattern
from chimera.knowledge.system import knowledge
from chimera.memory.engine import memory
from chimera.patterns.library import library

log = get_logger(__name__)


class LearningPipeline:
    async def process_failure(self, failure: FailureRecord) -> None:
        log.info("Processing failure: %s", failure.id)
        memory.long_term.add_failure(failure)

        suggestion = await self._suggest_pattern(failure)
        if suggestion:
            log.info("Suggested new pattern: %s", suggestion.name)

    async def process_challenge_outcome(
        self, challenge: Challenge
    ) -> list[Pattern]:
        suggestions: list[Pattern] = []

        if challenge.status.value == "failed":
            for hypothesis in challenge.hypotheses:
                if not hypothesis.is_correct:
                    failure = FailureRecord(
                        hypothesis_id=hypothesis.id,
                        tool_name=hypothesis.tools[0] if hypothesis.tools else "",
                        command="",
                        error=f"Hypothesis failed: {hypothesis.description}",
                        lesson=f"Confidence {hypothesis.confidence:.2f} was insufficient",
                    )
                    memory.long_term.add_failure(failure)
                    suggestion = await self._suggest_pattern(failure)
                    if suggestion:
                        suggestions.append(suggestion)

            existing = library.match(challenge)
            if not existing:
                auto_pattern = self._generate_pattern(challenge)
                if auto_pattern:
                    suggestions.append(auto_pattern)

        return suggestions

    async def _suggest_pattern(
        self, failure: FailureRecord
    ) -> Pattern | None:
        similar_failures = [
            f
            for f in memory.long_term._failures
            if f.tool_name == failure.tool_name and f.id != failure.id
        ]

        if len(similar_failures) >= 3:
            return Pattern(
                name=f"Watch: {failure.tool_name} failures",
                conditions=[failure.tool_name, failure.error[:50]],
                confidence=0.5,
                source="learning_pipeline",
            )
        return None

    def _generate_pattern(self, challenge: Challenge) -> Pattern | None:
        keywords = set()
        text = f"{challenge.title} {challenge.description}".lower()
        important_words = [
            "rsa", "aes", "xor", "base64", "hash",
            "overflow", "format", "injection", "sqli",
            "stego", "lsb", "forensic", "revers",
            "osint", "domain", "dns",
        ]
        for word in important_words:
            if word in text:
                keywords.add(word)

        if not keywords:
            return None

        return Pattern(
            name=f"Auto: {challenge.category.value if challenge.category else 'unknown'} pattern",
            conditions=list(keywords)[:5],
            confidence=0.4,
            category=challenge.category,
            source="auto_generated",
        )

    def generate_report(self) -> str:
        lines = [
            "## Learning Pipeline Report",
            "",
            f"**Total failures:** {len(memory.long_term._failures)}",
            f"**Total patterns:** {len(library.list_patterns())}",
            f"**Total knowledge entries:** {len(memory.long_term._knowledge)}",
            "",
            "### Recent Failures",
        ]
        for f in memory.long_term._failures[-5:]:
            lines.append(f"- [{f.tool_name}] {f.error[:80]}")
        return "\n".join(lines)


learning = LearningPipeline()
