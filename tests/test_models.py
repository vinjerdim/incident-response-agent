from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ira.models import (
    Alert,
    AlertSource,
    AuditEvent,
    AuditEventType,
    Confidence,
    ConfidenceLevel,
    Evidence,
    Hypothesis,
    Investigation,
    InvestigationStatus,
    Risk,
    Severity,
    StatusDraft,
    SuggestedAction,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def make_alert(**kw) -> Alert:
    base = dict(
        source=AlertSource.ALERTMANAGER,
        service="checkout",
        title="High 5xx rate",
        severity=Severity.HIGH,
        fired_at=NOW,
    )
    return Alert(**(base | kw))


def make_evidence(**kw) -> Evidence:
    base = dict(tool_call_id="call_1", tool_name="search_logs", excerpt="ERROR pool exhausted")
    return Evidence(**(base | kw))


def make_hypothesis(rank: int = 1, **kw) -> Hypothesis:
    base = dict(
        rank=rank,
        title="DB connection pool exhausted",
        explanation="Pool saturation errors began at 11:58",
        confidence=Confidence.from_score(0.8),
        evidence=[make_evidence()],
    )
    return Hypothesis(**(base | kw))


# --- Alert -------------------------------------------------------------------


def test_alert_valid_and_frozen():
    a = make_alert()
    assert a.id
    with pytest.raises(ValidationError):
        a.title = "changed"


@pytest.mark.parametrize("field,value", [("service", ""), ("title", "   "), ("severity", "sev0")])
def test_alert_rejects_bad_fields(field, value):
    with pytest.raises(ValidationError):
        make_alert(**{field: value})


def test_alert_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        make_alert(unexpected="x")


# --- Evidence / Hypothesis -----------------------------------------------------


@pytest.mark.parametrize("field", ["tool_call_id", "tool_name", "excerpt"])
def test_evidence_requires_non_empty(field):
    with pytest.raises(ValidationError):
        make_evidence(**{field: ""})


def test_hypothesis_requires_evidence():
    with pytest.raises(ValidationError, match="at least 1"):
        make_hypothesis(evidence=[])


@pytest.mark.parametrize("score", [-0.1, 1.01])
def test_confidence_score_bounds(score):
    with pytest.raises(ValidationError):
        Confidence(level=ConfidenceLevel.LOW, score=score)


@pytest.mark.parametrize(
    "score,level",
    [(0.0, "low"), (0.39, "low"), (0.4, "medium"), (0.69, "medium"), (0.7, "high"), (1.0, "high")],
)
def test_confidence_from_score(score, level):
    assert Confidence.from_score(score).level == level


def test_confidence_level_must_match_score():
    with pytest.raises(ValidationError, match="inconsistent"):
        Confidence(level=ConfidenceLevel.HIGH, score=0.1)


def test_hypothesis_rank_positive():
    with pytest.raises(ValidationError):
        make_hypothesis(rank=0)


# --- SuggestedAction ---------------------------------------------------------


def test_suggested_action_always_requires_approval():
    a = SuggestedAction(
        description="Roll back deploy 42", rationale="errors began", risk=Risk.MEDIUM
    )
    assert a.requires_approval is True
    with pytest.raises(ValidationError):
        SuggestedAction(description="x", rationale="y", risk=Risk.LOW, requires_approval=False)


# --- Investigation -----------------------------------------------------------


def test_investigation_sorts_hypotheses_by_rank():
    inv = Investigation(alert=make_alert(), hypotheses=[make_hypothesis(2), make_hypothesis(1)])
    assert [h.rank for h in inv.hypotheses] == [1, 2]


def test_investigation_rejects_duplicate_ranks():
    with pytest.raises(ValidationError, match="unique"):
        Investigation(alert=make_alert(), hypotheses=[make_hypothesis(1), make_hypothesis(1)])


def test_completed_investigation_must_list_not_checked():
    with pytest.raises(ValidationError, match="NOT checked"):
        Investigation(alert=make_alert(), status=InvestigationStatus.COMPLETED)
    inv = Investigation(
        alert=make_alert(),
        status=InvestigationStatus.COMPLETED,
        not_checked=["network metrics"],
    )
    assert inv.not_checked == ["network metrics"]


def test_investigation_json_round_trip():
    inv = Investigation(
        alert=make_alert(labels={"env": "prod"}),
        status=InvestigationStatus.COMPLETED,
        hypotheses=[make_hypothesis(1)],
        not_checked=["traces"],
        suggested_actions=[
            SuggestedAction(description="Raise pool size", rationale="saturation", risk=Risk.LOW)
        ],
        steps_used=5,
        tokens_used=1234,
    )
    assert Investigation.model_validate_json(inv.model_dump_json()) == inv


# --- StatusDraft / AuditEvent --------------------------------------------------


def test_status_draft_requires_summary():
    with pytest.raises(ValidationError):
        StatusDraft(investigation_id="inv1", summary="")
    d = StatusDraft(investigation_id="inv1", summary="Checkout errors elevated; investigating.")
    assert d.audience == "stakeholders"


def test_audit_event_frozen_and_utc():
    e = AuditEvent(actor="agent", event_type=AuditEventType.TOOL_CALL, investigation_id="inv1")
    assert e.ts.tzinfo is not None
    with pytest.raises(ValidationError):
        e.actor = "someone-else"


def test_audit_event_rejects_naive_timestamp():
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuditEvent(
            actor="agent",
            event_type=AuditEventType.APPROVED,
            investigation_id="inv1",
            ts=datetime(2026, 1, 1),  # noqa: DTZ001
        )


def test_audit_event_rejects_unknown_type():
    with pytest.raises(ValidationError):
        AuditEvent(actor="agent", event_type="restarted_prod", investigation_id="inv1")
