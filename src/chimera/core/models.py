from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ChallengeCategory(str, Enum):
    crypto = "crypto"
    reverse = "reverse"
    pwn = "pwn"
    web = "web"
    forensics = "forensics"
    stego = "stego"
    osint = "osint"
    mobile = "mobile"
    blockchain = "blockchain"
    hardware = "hardware"
    wireless = "wireless"
    misc = "misc"


class ChallengeStatus(str, Enum):
    imported = "imported"
    analyzing = "analyzing"
    solving = "solving"
    solved = "solved"
    failed = "failed"
    archived = "archived"


class Hypothesis(BaseModel):
    id: str = Field(default_factory=lambda: f"hyp_{datetime.utcnow().timestamp():.0f}")
    description: str
    category: ChallengeCategory
    tools: list[str] = []
    confidence: float = 0.0
    evidence: list[str] = []
    is_correct: bool | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Challenge(BaseModel):
    id: str
    title: str
    description: str
    category: ChallengeCategory | None = None
    status: ChallengeStatus = ChallengeStatus.imported
    source: str = ""
    files: list[Path] = []
    hypotheses: list[Hypothesis] = []
    flag: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ToolResult(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = False
    duration_ms: int = 0
    artifacts: list[Path] = []
    error: str | None = None


class PluginManifest(BaseModel):
    name: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    tools: list[str] = []
    dependencies: list[str] = []
    categories: list[ChallengeCategory] = []


class Pattern(BaseModel):
    name: str
    conditions: list[str]
    confidence: float = 0.0
    required_tools: list[str] = []
    category: ChallengeCategory | None = None
    playbook: list[str] = []
    source: str = ""


class KnowledgeEntry(BaseModel):
    challenge_id: str
    challenge_title: str
    category: ChallengeCategory
    flag: str | None = None
    tools_used: list[str] = []
    patterns_matched: list[str] = []
    reasoning: str = ""
    mistakes: list[str] = []
    solved: bool = False
    duration_seconds: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FailureRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"fail_{datetime.utcnow().timestamp():.0f}")
    hypothesis_id: str = ""
    tool_name: str = ""
    command: str = ""
    error: str = ""
    context: dict[str, Any] = {}
    lesson: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)


class PlannerStep(BaseModel):
    step_number: int
    action: str
    tool: str = ""
    arguments: dict[str, Any] = {}
    hypothesis_id: str = ""
    status: str = "pending"
    result: ToolResult | None = None
    reasoning: str = ""
