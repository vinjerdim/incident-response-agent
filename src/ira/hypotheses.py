"""Turn the model's `submit_findings` payload into validated Hypotheses.

"No evidence, no claim": each citation must reference a real, successful tool call and quote
text that actually appears in that call's (redacted) output. Anything else is rejected and
recorded so evals can measure hallucination rate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ira.models import (
    Confidence,
    Evidence,
    Hypothesis,
    Risk,
    SuggestedAction,
    ToolCallRecord,
)

SCOPE_DISCLAIMER = (
    "Anything outside the read-only tools used here (traces, live dashboards, customer "
    "reports, infrastructure/network state) was not inspected."
)
MAX_EXCERPT_CHARS = 500


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SubmittedEvidence(_Lenient):
    tool_call_id: str = ""
    excerpt: str = ""


class SubmittedHypothesis(_Lenient):
    title: str = ""
    explanation: str = ""
    confidence_score: float = 0.0
    evidence: list[SubmittedEvidence] = Field(default_factory=list)


class SubmittedAction(_Lenient):
    description: str = ""
    rationale: str = ""
    risk: str = "medium"


class Submission(_Lenient):
    hypotheses: list[SubmittedHypothesis] = Field(default_factory=list)
    not_checked: list[str] = Field(default_factory=list)
    suggested_actions: list[SubmittedAction] = Field(default_factory=list)


@dataclass
class Findings:
    hypotheses: list[Hypothesis] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    suggested_actions: list[SuggestedAction] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in items:
        key = item.strip().lower()
        if item.strip() and key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out


def build_findings(
    raw: dict[str, Any],
    tool_calls: list[ToolCallRecord],
    available_tools: list[str],
) -> Findings:
    findings = Findings()
    try:
        sub = Submission.model_validate(raw)
    except ValidationError as e:
        findings.rejected.append(f"submission malformed: {e.error_count()} errors")
        sub = Submission()

    calls = {c.tool_call_id: c for c in tool_calls}
    accepted: list[tuple[float, int, SubmittedHypothesis, list[Evidence]]] = []

    for i, h in enumerate(sub.hypotheses):
        label = h.title.strip() or f"hypothesis #{i + 1}"
        evidence: list[Evidence] = []
        for ev in h.evidence:
            call = calls.get(ev.tool_call_id.strip())
            excerpt = _norm(ev.excerpt)
            if call is None:
                findings.rejected.append(f"{label}: unknown tool_call_id {ev.tool_call_id!r}")
            elif not call.ok:
                findings.rejected.append(f"{label}: cites failed call {call.tool_call_id}")
            elif not excerpt:
                findings.rejected.append(f"{label}: empty excerpt for {call.tool_call_id}")
            elif excerpt not in _norm(call.output):
                findings.rejected.append(
                    f"{label}: excerpt not found in {call.tool_call_id}: {excerpt[:80]!r}"
                )
            else:
                evidence.append(
                    Evidence(
                        tool_call_id=call.tool_call_id,
                        tool_name=call.tool_name,
                        excerpt=excerpt[:MAX_EXCERPT_CHARS],
                    )
                )
        if not h.title.strip() or not h.explanation.strip():
            findings.rejected.append(f"{label}: missing title or explanation")
            continue
        if not evidence:
            findings.rejected.append(f"{label}: dropped, no valid evidence")
            continue
        score = min(1.0, max(0.0, h.confidence_score))
        accepted.append((score, i, h, evidence))

    accepted.sort(key=lambda x: (-x[0], x[1]))
    findings.hypotheses = [
        Hypothesis(
            rank=rank,
            title=h.title.strip(),
            explanation=h.explanation.strip(),
            confidence=Confidence.from_score(score),
            evidence=evidence,
        )
        for rank, (score, _, h, evidence) in enumerate(accepted, start=1)
    ]

    called = {c.tool_name for c in tool_calls if c.ok}
    auto = [f"Tool '{t}' was never called." for t in available_tools if t not in called]
    findings.not_checked = _dedupe([*sub.not_checked, *auto, SCOPE_DISCLAIMER])

    for a in sub.suggested_actions:
        if not a.description.strip() or not a.rationale.strip():
            findings.rejected.append("suggested action missing description or rationale")
            continue
        risk = a.risk if a.risk in {r.value for r in Risk} else Risk.HIGH
        findings.suggested_actions.append(
            SuggestedAction(description=a.description, rationale=a.rationale, risk=risk)
        )
    return findings
