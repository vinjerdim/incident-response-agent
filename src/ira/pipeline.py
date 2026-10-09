"""End-to-end flow: investigate -> persist -> draft status update -> open approval requests.

Every step lands in the audit log. Used by the CLI and (Phase 5) the webhook.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import anthropic

from ira.agent import Investigator
from ira.approvals import Approvals, ApprovalState
from ira.audit import Store
from ira.config import Settings, get_settings
from ira.drafts import Drafter
from ira.models import Alert, AuditEvent, AuditEventType, Investigation, StatusDraft
from ira.tools.registry import ToolRegistry


@dataclass
class PipelineResult:
    investigation: Investigation
    draft: StatusDraft
    approvals: list[ApprovalState]


def run_investigation(
    alert: Alert,
    registry: ToolRegistry,
    store: Store,
    *,
    client: Any | None = None,
    settings: Settings | None = None,
    llm_drafts: bool = True,
    investigation_id: str | None = None,
) -> PipelineResult:
    settings = settings or get_settings()
    client = client if client is not None else anthropic.Anthropic()

    inv = Investigator(registry, client=client, settings=settings, on_event=store.append).run(
        alert, investigation_id
    )
    store.save_investigation(inv)

    drafter = Drafter(client if llm_drafts else None, settings)
    draft = drafter.draft(inv)
    store.save_draft(draft)
    store.append(
        AuditEvent(
            actor="agent",
            event_type=AuditEventType.DRAFT,
            investigation_id=inv.id,
            payload={
                "draft_id": draft.id,
                "generated_by": draft.generated_by,
                "summary": draft.summary,
                "rejected_problems": drafter.problems,
            },
        )
    )
    approvals = Approvals(store).request(inv)
    return PipelineResult(inv, draft, approvals)
