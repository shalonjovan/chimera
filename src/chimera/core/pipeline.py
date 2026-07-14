from __future__ import annotations

import time
from pathlib import Path

from chimera.core.logging import get_logger
from chimera.core.models import Challenge, ChallengeCategory, ChallengeStatus
from chimera.core.planner import planner
from chimera.memory.engine import memory
from chimera.plugins.registry import registry

log = get_logger(__name__)


class ChallengePipeline:
    async def run(
        self,
        challenge_id: str,
        title: str,
        description: str,
        files: list[Path] | None = None,
        category: ChallengeCategory | None = None,
        source: str = "",
    ) -> Challenge:
        challenge = Challenge(
            id=challenge_id,
            title=title,
            description=description,
            files=files or [],
            category=category,
            source=source,
        )

        start = time.monotonic()
        log.info("Starting pipeline for challenge: %s (%s)", challenge.id, challenge.title)

        challenge = await self._detect(challenge)
        if challenge.category:
            challenge = await self._analyze(challenge)
            challenge = await self._solve(challenge)
            challenge = await self._verify(challenge)
        else:
            log.warning("Could not detect category for %s, marking failed", challenge.id)
            challenge.status = ChallengeStatus.failed

        self._archive(challenge)
        duration = time.monotonic() - start
        log.info(
            "Pipeline finished: %s status=%s duration=%.1fs",
            challenge.id,
            challenge.status.value,
            duration,
        )
        return challenge

    async def _detect(self, challenge: Challenge) -> Challenge:
        log.info("Phase: detect — %s", challenge.id)
        detected = registry.detect_category(challenge)
        if detected:
            challenge.category = detected
            log.info("Detected category: %s", detected.value)
        return challenge

    async def _analyze(self, challenge: Challenge) -> Challenge:
        log.info("Phase: analyze — %s (%s)", challenge.id, challenge.category)
        challenge.status = ChallengeStatus.analyzing
        challenge = await planner.plan_and_execute(challenge)
        return challenge

    async def _solve(self, challenge: Challenge) -> Challenge:
        log.info("Phase: solve — %s", challenge.id)
        challenge.status = ChallengeStatus.solving
        return challenge

    async def _verify(self, challenge: Challenge) -> Challenge:
        log.info("Phase: verify — %s", challenge.id)
        if challenge.flag:
            verified = await planner.verify_flag(challenge, challenge.flag)
            if verified:
                challenge.status = ChallengeStatus.solved
                log.info("Flag verified for %s", challenge.id)
            else:
                log.warning("Flag verification failed for %s", challenge.id)
        return challenge

    def _archive(self, challenge: Challenge) -> None:
        log.info("Phase: archive — %s", challenge.id)
        memory.save_session(challenge)
        solved = challenge.status == ChallengeStatus.solved
        memory.archive_knowledge(challenge, solved=solved)


pipeline = ChallengePipeline()
