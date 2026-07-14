from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from chimera.config.settings import settings
from chimera.core.logging import get_logger
from chimera.core.models import (
    Challenge,
    FailureRecord,
    KnowledgeEntry,
    Pattern,
)

log = get_logger(__name__)


class ShortTermMemory:
    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def set(self, key: str, value: Any) -> None:
        self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        return self._store.get(f"challenge:{challenge_id}")

    def set_challenge(self, challenge: Challenge) -> None:
        self._store[f"challenge:{challenge.id}"] = challenge

    def clear(self) -> None:
        self._store.clear()


class MediumTermMemory:
    def __init__(self, storage_dir: Path | None = None) -> None:
        self._dir = storage_dir or settings.data_dir / "sessions"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    def save(self, challenge: Challenge) -> Path:
        path = self._dir / f"{challenge.id}_{self._session_id}.json"
        data = challenge.model_dump(mode="json", exclude_none=True)
        path.write_text(json.dumps(data, indent=2, default=str))
        return path

    def list_sessions(self) -> list[Path]:
        return sorted(self._dir.glob("*.json"))


class LongTermMemory:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or settings.data_dir / "chimera.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._knowledge: list[KnowledgeEntry] = []
        self._patterns: list[Pattern] = []
        self._failures: list[FailureRecord] = []
        self._load()

    def _load(self) -> None:
        if self._db_path.exists():
            try:
                data = json.loads(self._db_path.read_text())
                self._knowledge = [KnowledgeEntry(**k) for k in data.get("knowledge", [])]
                self._patterns = [Pattern(**p) for p in data.get("patterns", [])]
                self._failures = [FailureRecord(**f) for f in data.get("failures", [])]
            except Exception as e:
                log.warning("Failed to load long-term memory: %s", e)

    def _save(self) -> None:
        data = {
            "knowledge": [k.model_dump(mode="json") for k in self._knowledge],
            "patterns": [p.model_dump(mode="json") for p in self._patterns],
            "failures": [f.model_dump(mode="json") for f in self._failures],
        }
        self._db_path.write_text(json.dumps(data, indent=2, default=str))

    def add_knowledge(self, entry: KnowledgeEntry) -> None:
        self._knowledge.append(entry)
        self._save()

    def add_pattern(self, pattern: Pattern) -> None:
        self._patterns.append(pattern)
        self._save()

    def add_failure(self, failure: FailureRecord) -> None:
        self._failures.append(failure)
        self._save()

    def get_knowledge(self, challenge_id: str) -> KnowledgeEntry | None:
        for k in self._knowledge:
            if k.challenge_id == challenge_id:
                return k
        return None

    def get_patterns_by_category(self, category: str) -> list[Pattern]:
        return [p for p in self._patterns if p.category and p.category.value == category]

    def search_knowledge(self, query: str) -> list[KnowledgeEntry]:
        query = query.lower()
        return [
            k
            for k in self._knowledge
            if query in k.challenge_title.lower()
            or query in k.reasoning.lower()
        ]


class MemoryEngine:
    def __init__(self) -> None:
        self.short_term = ShortTermMemory()
        self.medium_term = MediumTermMemory()
        self.long_term = LongTermMemory()

    def save_session(self, challenge: Challenge) -> Path:
        self.short_term.set_challenge(challenge)
        return self.medium_term.save(challenge)

    def archive_knowledge(self, challenge: Challenge, solved: bool = False) -> None:
        if challenge.category is None:
            log.warning("Cannot archive knowledge for %s: no category", challenge.id)
            return
        entry = KnowledgeEntry(
            challenge_id=challenge.id,
            challenge_title=challenge.title,
            category=challenge.category,
            flag=challenge.flag,
            tools_used=[h.tools[0] if h.tools else "" for h in challenge.hypotheses],
            solved=solved,
        )
        self.long_term.add_knowledge(entry)

    def record_failure(
        self,
        tool_name: str,
        command: str,
        error: str,
        lesson: str = "",
    ) -> None:
        failure = FailureRecord(
            tool_name=tool_name,
            command=command,
            error=error,
            lesson=lesson,
        )
        self.long_term.add_failure(failure)


memory = MemoryEngine()
