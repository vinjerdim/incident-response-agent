"""Human approval flow for suggested actions.

The audit log is the single source of truth: an action's state is derived by replaying its
APPROVAL_REQUESTED / APPROVED / REJECTED / EXECUTED events. Nothing is executed unless an
APPROVED event by a named human exists for that exact action id. The only executor shipped is
a dry run that changes nothing.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from ira.audit import Store
from ira.models import (
    ApprovalStatus,
    AuditEvent,
    AuditEventType,
    Investigation,
    SuggestedAction,
)

SYSTEM_ACTOR = "system"
RESERVED_ACTORS = frozenset({"", "agent", "system", "ira", "bot"})


class ApprovalError(Exception):
    pass


class Executor(Protocol):
    dry_run: bool

    def execute(self, action: SuggestedAction) -> str: ...


class DryRunExecutor:
    """Records what *would* happen. Never touches any system."""

    dry_run = True

    def execute(self, action: SuggestedAction) -> str:
        return f"DRY RUN: would perform: {action.description}. No changes were made."


@dataclass(frozen=True)
class ApprovalState:
    action: SuggestedAction
    investigation_id: str
    status: ApprovalStatus
    decided_by: str | None = None
    reason: str | None = None
    executed_by: str | None = None
    result: str | None = None


def _validate_human(actor: str, role: str) -> str:
    name = (actor or "").strip()
    if name.lower() in RESERVED_ACTORS:
        raise ApprovalError(f"{role} must be a named human, not {actor!r}")
    return name


class Approvals:
    def __init__(self, store: Store, executor: Executor | None = None):
        self.store = store
        self.executor = executor or DryRunExecutor()
        self._lock = threading.Lock()

    def _emit(self, event_type: AuditEventType, actor: str, inv_id: str, **payload) -> None:
        self.store.append(
            AuditEvent(actor=actor, event_type=event_type, investigation_id=inv_id, payload=payload)
        )

    def request(self, inv: Investigation) -> list[ApprovalState]:
        """Open an approval request for every suggested action (idempotent)."""
        existing = {s.action.id for s in self.list(inv.id)}
        for action in inv.suggested_actions:
            if action.id not in existing:
                self._emit(
                    AuditEventType.APPROVAL_REQUESTED,
                    SYSTEM_ACTOR,
                    inv.id,
                    action_id=action.id,
                    action=action.model_dump(mode="json"),
                )
        return self.list(inv.id)

    def list(self, investigation_id: str) -> list[ApprovalState]:
        return list(self._replay(self.store.events(investigation_id=investigation_id)).values())

    def state(self, action_id: str) -> ApprovalState:
        requested = [
            e
            for e in self.store.events(event_type=AuditEventType.APPROVAL_REQUESTED)
            if e.payload.get("action_id") == action_id
        ]
        if not requested:
            raise ApprovalError(f"unknown action id {action_id!r}")
        states = self._replay(self.store.events(investigation_id=requested[0].investigation_id))
        return states[action_id]

    @staticmethod
    def _replay(events: list[AuditEvent]) -> dict[str, ApprovalState]:
        states: dict[str, ApprovalState] = {}
        for e in events:
            aid = e.payload.get("action_id")
            if aid is None:
                continue
            if e.event_type == AuditEventType.APPROVAL_REQUESTED:
                states[aid] = ApprovalState(
                    action=SuggestedAction.model_validate(e.payload["action"]),
                    investigation_id=e.investigation_id,
                    status=ApprovalStatus.PENDING,
                )
            elif aid in states and e.event_type in (
                AuditEventType.APPROVED,
                AuditEventType.REJECTED,
            ):
                s = states[aid]
                status = (
                    ApprovalStatus.APPROVED
                    if e.event_type == AuditEventType.APPROVED
                    else ApprovalStatus.REJECTED
                )
                states[aid] = ApprovalState(
                    s.action, s.investigation_id, status, e.actor, e.payload.get("reason")
                )
            elif aid in states and e.event_type == AuditEventType.EXECUTED:
                s = states[aid]
                states[aid] = ApprovalState(
                    s.action, s.investigation_id, ApprovalStatus.EXECUTED, s.decided_by,
                    s.reason, e.actor, e.payload.get("result"),
                )  # fmt: skip
        return states

    def _decide(self, action_id: str, actor: str, reason: str, approve: bool) -> ApprovalState:
        actor = _validate_human(actor, "approver")
        if not (reason or "").strip():
            raise ApprovalError("a reason is required")
        with self._lock:
            s = self.state(action_id)
            if s.status != ApprovalStatus.PENDING:
                raise ApprovalError(f"action {action_id} is {s.status}, not pending")
            self._emit(
                AuditEventType.APPROVED if approve else AuditEventType.REJECTED,
                actor,
                s.investigation_id,
                action_id=action_id,
                reason=reason.strip(),
            )
            return self.state(action_id)

    def approve(self, action_id: str, approver: str, reason: str) -> ApprovalState:
        return self._decide(action_id, approver, reason, approve=True)

    def reject(self, action_id: str, approver: str, reason: str) -> ApprovalState:
        return self._decide(action_id, approver, reason, approve=False)

    def execute(self, action_id: str, actor: str) -> ApprovalState:
        actor = _validate_human(actor, "executor")
        with self._lock:
            s = self.state(action_id)  # replayed from the audit log
            if s.status != ApprovalStatus.APPROVED:
                raise ApprovalError(
                    f"action {action_id} is {s.status}; only approved actions can be executed"
                )
            result = self.executor.execute(s.action)
            self._emit(
                AuditEventType.EXECUTED,
                actor,
                s.investigation_id,
                action_id=action_id,
                approved_by=s.decided_by,
                dry_run=self.executor.dry_run,
                result=result,
            )
            return self.state(action_id)
