from __future__ import annotations

import asyncio
from typing import Any

from chimera.core.logging import get_logger
from chimera.core.models import (
    Challenge,
    ChallengeCategory,
    ChallengeStatus,
    Hypothesis,
    ToolResult,
)
from chimera.plugins.registry import registry
from chimera.tools.dispatcher import dispatcher

log = get_logger(__name__)

MAX_CONCURRENT_HYPOTHESES = 5


class Agent:
    def __init__(self, name: str, plugin_name: str, category: ChallengeCategory) -> None:
        self.name = name
        self.plugin_name = plugin_name
        self.category = category

    async def analyze(self, challenge: Challenge) -> ToolResult:
        return await dispatcher.execute(
            self.plugin_name,
            {"action": "analyze", "challenge": challenge},
        )

    async def solve(self, challenge: Challenge) -> ToolResult:
        return await dispatcher.execute(
            self.plugin_name,
            {"action": "solve", "challenge": challenge},
        )


class MultiAgentPlanner:
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register_agents(self) -> None:
        for plugin in registry.list_plugins():
            for cat in plugin.categories:
                agent = Agent(
                    name=f"{plugin.name}_agent",
                    plugin_name=plugin.name,
                    category=cat,
                )
                self._agents[agent.name] = agent
        log.info("Registered %d agents", len(self._agents))

    async def plan_and_execute(self, challenge: Challenge) -> Challenge:
        challenge.status = ChallengeStatus.analyzing
        if challenge.category is None:
            challenge.category = registry.detect_category(challenge)

        if challenge.category is None:
            log.warning("Cannot detect category for %s", challenge.id)
            challenge.status = ChallengeStatus.failed
            return challenge

        agents = self._get_agents_for_category(challenge.category)
        if not agents:
            log.warning("No agents available for %s", challenge.category)
            challenge.status = ChallengeStatus.failed
            return challenge

        log.info(
            "Multi-agent planning: %d agents for %s",
            len(agents), challenge.category.value,
        )

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_HYPOTHESES)

        async def run_agent(agent: Agent) -> tuple[Agent, bool]:
            async with semaphore:
                plugin = next(
                    (p for p in registry.list_plugins() if p.name == agent.plugin_name),
                    None,
                )
                confidence = getattr(plugin, "detect", lambda _: 0.3)(challenge) if plugin else 0.3
                hypothesis = Hypothesis(
                    description=f"{agent.name}: {challenge.title}",
                    category=challenge.category,
                    tools=[agent.plugin_name],
                    confidence=confidence,
                )
                challenge.hypotheses.append(hypothesis)

                result = await agent.analyze(challenge)
                if result.success:
                    hypothesis.evidence.append(result.stdout)
                    hypothesis.is_correct = True

                    solve_result = await agent.solve(challenge)
                    if solve_result.success:
                        return agent, True

                hypothesis.is_correct = False
                return agent, False

        tasks = [run_agent(agent) for agent in agents]
        results = await asyncio.gather(*tasks)

        solved = any(solved for _, solved in results)
        challenge.status = ChallengeStatus.solved if solved else ChallengeStatus.failed

        if challenge.status == ChallengeStatus.solved:
            log.info("Challenge %s solved by multi-agent planner!", challenge.id)
        else:
            log.warning("Challenge %s not solved by any agent", challenge.id)

        return challenge

    def _get_agents_for_category(self, category: ChallengeCategory) -> list[Agent]:
        return [
            agent for agent in self._agents.values() if agent.category == category
        ]

    def _get_plugin_confidence(self, plugin_name: str) -> float:
        try:
            plugin = registry.get(plugin_name)
            return getattr(plugin.manifest, "confidence", 0.3) or 0.3
        except Exception:
            return 0.3


multi_agent_planner = MultiAgentPlanner()
