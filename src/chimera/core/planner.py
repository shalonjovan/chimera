from __future__ import annotations

import time
from typing import Any

from chimera.core.exceptions import PlannerError
from chimera.core.logging import get_logger
from chimera.core.models import (
    Challenge,
    ChallengeStatus,
    Hypothesis,
    PlannerStep,
    ToolResult,
)
from chimera.plugins.registry import registry
from chimera.tools.dispatcher import dispatcher

log = get_logger(__name__)

MAX_RETRIES = 3
CONFIDENCE_THRESHOLD = 0.8


class Planner:
    def __init__(self) -> None:
        self._current_plan: list[PlannerStep] = []

    async def plan_and_execute(
        self,
        challenge: Challenge,
    ) -> Challenge:
        challenge.status = ChallengeStatus.analyzing
        challenge.category = challenge.category or registry.detect_category(challenge)

        if challenge.category is None:
            raise PlannerError(f"Cannot detect category for challenge: {challenge.id}")

        log.info(
            "Planning solve for %s (category: %s)",
            challenge.id,
            challenge.category.value,
        )

        hypotheses = self._generate_hypotheses(challenge)

        for hypothesis in hypotheses:
            challenge.hypotheses.append(hypothesis)
            result = await self._execute_hypothesis(challenge, hypothesis)

            if result.success and hypothesis.confidence >= CONFIDENCE_THRESHOLD:
                challenge.status = ChallengeStatus.solving
                solve_result = await self._solve(challenge, hypothesis)
                if solve_result.success:
                    challenge.status = ChallengeStatus.solved
                    return challenge

        challenge.status = ChallengeStatus.failed
        return challenge

    def _generate_hypotheses(self, challenge: Challenge) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        plugins = registry.get_for_category(challenge.category)

        for plugin in plugins:
            score = plugin.detect(challenge)
            hypotheses.append(
                Hypothesis(
                    description=f"Analyze with {plugin.name} plugin",
                    category=challenge.category,
                    tools=[plugin.name],
                    confidence=score,
                )
            )

        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        log.info(
            "Generated %d hypotheses, best: %.2f",
            len(hypotheses),
            hypotheses[0].confidence if hypotheses else 0,
        )
        return hypotheses

    async def _execute_hypothesis(
        self,
        challenge: Challenge,
        hypothesis: Hypothesis,
    ) -> ToolResult:
        for attempt in range(MAX_RETRIES):
            log.info(
                "Executing hypothesis '%s' (attempt %d/%d, confidence=%.2f)",
                hypothesis.description[:60],
                attempt + 1,
                MAX_RETRIES,
                hypothesis.confidence,
            )

            for tool_name in hypothesis.tools:
                result = await dispatcher.execute(
                    tool_name,
                    {"action": "analyze", "challenge": challenge},
                )
                if result.success:
                    hypothesis.evidence.append(result.stdout)
                    return result

            if attempt < MAX_RETRIES - 1:
                log.info("Retrying hypothesis (attempt %d failed)", attempt + 1)

        return ToolResult(
            tool_name="planner",
            arguments={"hypothesis": hypothesis.description},
            success=False,
            error="All retries exhausted",
        )

    async def _solve(
        self,
        challenge: Challenge,
        hypothesis: Hypothesis,
    ) -> ToolResult:
        for tool_name in hypothesis.tools:
            result = await dispatcher.execute(
                tool_name,
                {"action": "solve", "challenge": challenge},
            )
            if result.success:
                return result

        return ToolResult(
            tool_name="planner",
            success=False,
            error="Solve failed",
        )

    async def verify_flag(
        self,
        challenge: Challenge,
        flag: str,
    ) -> bool:
        for plugin in registry.get_for_category(challenge.category):
            try:
                challenge.flag = flag
                if await plugin.verify(challenge):
                    return True
            except Exception:
                continue
        return False


planner = Planner()
