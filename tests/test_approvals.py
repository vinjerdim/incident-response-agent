from datetime import UTC, datetime

import pytest

from ira.approvals import ApprovalError, Approvals, DryRunExecutor
from ira.audit import Store
from ira.models import (
    Alert,
    AlertSource,
    ApprovalStatus,
    AuditEventType,
    Investigation,
    Risk,
    Severity,
    SuggestedAction,
)


class SpyExecutor(DryRunExecutor):
    def __init__(self):
        self.calls = []

    def execute(self, action):
        self.calls.append(action.id)
        return super().execute(action)


@pytest.fixture
def setup():
    store = Store(":memory:")
    spy = SpyExecutor()
    approvals = Approvals(store, executor=spy)
    inv = Investigation(
        alert=Alert(
            source=AlertSource.MANUAL,
            service="checkout-api",
            title="5xx",
            severity=Severity.HIGH,
            fired_at=datetime(2026, 9, 14, tzinfo=UTC),
        ),
        suggested_actions=[
            SuggestedAction(
                description="Roll back to v2.13.2", rationale="errors", risk=Risk.MEDIUM
            ),
            SuggestedAction(description="Page DB team", rationale="cpu", risk=Risk.LOW),
        ],
    )
    states = approvals.request(inv)
    yield store, approvals, spy, inv, [s.action.id for s in states]
    store.close()


def test_request_is_idempotent_and_pending(setup):
    store, approvals, _, inv, _ids = setup
    approvals.request(inv)
    assert len(store.events(event_type=AuditEventType.APPROVAL_REQUESTED)) == 2
    assert [s.status for s in approvals.list(inv.id)] == [ApprovalStatus.PENDING] * 2


def test_execute_without_approval_is_denied(setup):
    store, approvals, spy, _, ids = setup
    with pytest.raises(ApprovalError, match="only approved actions"):
        approvals.execute(ids[0], "alice")
    assert spy.calls == []
    assert store.events(event_type=AuditEventType.EXECUTED) == []


def test_approve_then_execute_records_everything(setup):
    store, approvals, spy, _inv, ids = setup
    s = approvals.approve(ids[0], "alice", "errors started right after v2.14.0")
    assert s.status == ApprovalStatus.APPROVED and s.decided_by == "alice"
    s = approvals.execute(ids[0], "bob")
    assert s.status == ApprovalStatus.EXECUTED and s.executed_by == "bob"
    assert s.result.startswith("DRY RUN") and "No changes were made" in s.result
    assert spy.calls == [ids[0]]
    executed = store.events(event_type=AuditEventType.EXECUTED)[0]
    assert executed.payload["approved_by"] == "alice" and executed.payload["dry_run"] is True
    assert store.verify_chain() == []


def test_cannot_execute_twice(setup):
    _, approvals, spy, _, ids = setup
    approvals.approve(ids[0], "alice", "ok")
    approvals.execute(ids[0], "alice")
    with pytest.raises(ApprovalError, match="executed"):
        approvals.execute(ids[0], "alice")
    assert len(spy.calls) == 1


def test_rejected_cannot_be_executed_or_reapproved(setup):
    _, approvals, spy, _, ids = setup
    approvals.reject(ids[0], "alice", "too risky during peak")
    with pytest.raises(ApprovalError):
        approvals.execute(ids[0], "alice")
    with pytest.raises(ApprovalError, match="not pending"):
        approvals.approve(ids[0], "bob", "changed my mind")
    assert spy.calls == []


def test_approval_is_per_action(setup):
    _, approvals, spy, _, ids = setup
    approvals.approve(ids[1], "alice", "ok")
    with pytest.raises(ApprovalError):
        approvals.execute(ids[0], "alice")
    assert spy.calls == []


@pytest.mark.parametrize("actor", ["", "  ", "agent", "System", "ira"])
def test_agent_or_anonymous_cannot_approve(setup, actor):
    _, approvals, _, _, ids = setup
    with pytest.raises(ApprovalError, match="named human"):
        approvals.approve(ids[0], actor, "self-approve")


def test_reason_required(setup):
    _, approvals, _, _, ids = setup
    with pytest.raises(ApprovalError, match="reason"):
        approvals.approve(ids[0], "alice", "  ")


def test_unknown_action(setup):
    _, approvals, _, _, _ = setup
    with pytest.raises(ApprovalError, match="unknown action"):
        approvals.approve("nope", "alice", "x")


def test_state_comes_from_audit_log_not_memory(setup):
    store, approvals, _, _inv, ids = setup
    approvals.approve(ids[0], "alice", "ok")
    fresh = Approvals(store)  # new instance, no in-memory state
    assert fresh.state(ids[0]).status == ApprovalStatus.APPROVED
