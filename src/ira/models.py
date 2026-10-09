"""Core schemas. Hard rules from CLAUDE.md are enforced here where a schema can enforce them:

- every Hypothesis cites at least one piece of Evidence (tool call id + excerpt)
- remediation is only ever a SuggestedAction that requires approval
- an Investigation always states what was NOT checked
- AuditEvents are immutable
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid.uuid4().hex


NonEmptyStr = Field(min_length=1)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _Frozen(_Model):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertSource(StrEnum):
    PAGERDUTY = "pagerduty"
    ALERTMANAGER = "alertmanager"
    MANUAL = "manual"


class ConfidenceLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class InvestigationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BUDGET_EXHAUSTED = "budget_exhausted"


class AuditEventType(StrEnum):
    INVESTIGATION_STARTED = "investigation_started"
    TOOL_CALL = "tool_call"
    HYPOTHESIS = "hypothesis"
    DRAFT = "draft"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    INVESTIGATION_FINISHED = "investigation_finished"
    ALERT_RECEIVED = "alert_received"
    ALERT_DEDUPED = "alert_deduped"
    ALERT_RESOLVED = "alert_resolved"


class Alert(_Frozen):
    """Normalized alert. `title`, `description`, `labels` and `raw` are UNTRUSTED input."""

    id: str = Field(default_factory=_new_id)
    source: AlertSource
    service: str = NonEmptyStr
    title: str = NonEmptyStr
    description: str = ""
    severity: Severity
    fired_at: datetime
    labels: dict[str, str] = Field(default_factory=dict)
    dedupe_key: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Evidence(_Frozen):
    tool_call_id: str = NonEmptyStr
    tool_name: str = NonEmptyStr
    excerpt: str = NonEmptyStr
    retrieved_at: datetime = Field(default_factory=_utcnow)


def level_for_score(score: float) -> ConfidenceLevel:
    if score >= 0.7:
        return ConfidenceLevel.HIGH
    if score >= 0.4:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


class Confidence(_Frozen):
    level: ConfidenceLevel
    score: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _level_matches_score(self) -> Confidence:
        if self.level != level_for_score(self.score):
            raise ValueError(f"confidence level {self.level} inconsistent with score {self.score}")
        return self

    @classmethod
    def from_score(cls, score: float) -> Confidence:
        return cls(level=level_for_score(score), score=score)


class Hypothesis(_Frozen):
    rank: int = Field(ge=1)
    title: str = NonEmptyStr
    explanation: str = NonEmptyStr
    confidence: Confidence
    evidence: list[Evidence] = Field(min_length=1)


class SuggestedAction(_Frozen):
    """A remediation *suggestion*. Never executed without a recorded human approval."""

    id: str = Field(default_factory=_new_id)
    description: str = NonEmptyStr
    rationale: str = NonEmptyStr
    risk: Risk
    requires_approval: Literal[True] = True


class ToolCallRecord(_Frozen):
    """One tool call made during an investigation. `output` is the redacted text the model saw."""

    tool_call_id: str = NonEmptyStr
    tool_name: str = NonEmptyStr
    args: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    output: str
    truncated: bool = False
    redactions: dict[str, int] = Field(default_factory=dict)
    duration_ms: float = Field(default=0.0, ge=0)


class Investigation(_Model):
    id: str = Field(default_factory=_new_id)
    alert: Alert
    status: InvestigationStatus = InvestigationStatus.PENDING
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    not_checked: list[str] = Field(default_factory=list)
    suggested_actions: list[SuggestedAction] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    rejected_claims: list[str] = Field(default_factory=list)
    steps_used: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    error: str | None = None
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None

    @field_validator("hypotheses")
    @classmethod
    def _ranked(cls, v: list[Hypothesis]) -> list[Hypothesis]:
        ranks = [h.rank for h in v]
        if len(set(ranks)) != len(ranks):
            raise ValueError("hypothesis ranks must be unique")
        return sorted(v, key=lambda h: h.rank)

    @model_validator(mode="after")
    def _completed_requires_not_checked(self) -> Investigation:
        if self.status == InvestigationStatus.COMPLETED and not self.not_checked:
            raise ValueError("a completed investigation must list what was NOT checked")
        return self


class KnownFact(_Frozen):
    """An observation stated as fact. Must cite evidence: tool call ids, or "alert"."""

    statement: str = NonEmptyStr
    evidence_ids: list[str] = Field(min_length=1)


class StatusDraft(_Frozen):
    """Stakeholder update. `known_facts` must be backed by evidence; guesses go in
    `under_investigation`."""

    id: str = Field(default_factory=_new_id)
    investigation_id: str = NonEmptyStr
    audience: str = "stakeholders"
    summary: str = NonEmptyStr
    known_facts: list[KnownFact] = Field(default_factory=list)
    under_investigation: list[str] = Field(default_factory=list)
    next_update_at: datetime | None = None
    generated_by: Literal["llm", "template"] = "template"
    created_at: datetime = Field(default_factory=_utcnow)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class AuditEvent(_Frozen):
    id: str = Field(default_factory=_new_id)
    ts: datetime = Field(default_factory=_utcnow)
    actor: str = NonEmptyStr
    event_type: AuditEventType
    investigation_id: str = NonEmptyStr
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("audit timestamps must be timezone-aware")
        return v.astimezone(UTC)
