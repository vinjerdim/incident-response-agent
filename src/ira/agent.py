"""Bounded investigation agent: a manual Anthropic tool-use loop over read-only tools.

Bounds: `max_steps` model turns (+1 finalization turn that only offers submit_findings),
`max_tokens_total` across the run (soft: checked between turns), `max_tokens_per_call` per
request, and the registry's per-tool timeout. Every tool call is recorded and emitted as an
AuditEvent via `on_event`.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import anthropic

from ira.config import Settings, get_settings
from ira.hypotheses import build_findings
from ira.injection import scan
from ira.models import (
    Alert,
    AuditEvent,
    AuditEventType,
    Investigation,
    InvestigationStatus,
    ToolCallRecord,
)
from ira.prompts import (
    FINALIZE_PROMPT,
    REMIND_PROMPT,
    SUBMIT_TOOL,
    SUBMIT_TOOL_NAME,
    SYSTEM_PROMPT,
    alert_text,
    initial_user_message,
    neutralize,
    wrap_tool_output,
)
from ira.tools.registry import ToolRegistry

log = logging.getLogger("ira.agent")

FALLBACK_BETA = "server-side-fallback-2026-07-01"
ACTOR = "agent"

EventSink = Callable[[AuditEvent], None]


class Investigator:
    def __init__(
        self,
        registry: ToolRegistry,
        client: Any | None = None,
        settings: Settings | None = None,
        on_event: EventSink | None = None,
    ):
        self.registry = registry
        self.client = client if client is not None else anthropic.Anthropic()
        self.settings = settings or get_settings()
        self.on_event = on_event

    # -- plumbing -----------------------------------------------------------------------

    def _emit(self, inv: Investigation, event_type: AuditEventType, **payload: Any) -> None:
        if self.on_event is not None:
            self.on_event(
                AuditEvent(
                    actor=ACTOR, event_type=event_type, investigation_id=inv.id, payload=payload
                )
            )

    def _create(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]):
        s = self.settings
        kwargs: dict[str, Any] = {
            "model": s.model,
            "max_tokens": s.max_tokens_per_call,
            "system": SYSTEM_PROMPT,
            "tools": tools,
            "messages": messages,
            "output_config": {"effort": s.effort},
            "cache_control": {"type": "ephemeral"},
        }
        if s.refusal_fallback:
            return self.client.beta.messages.create(
                betas=[FALLBACK_BETA], fallbacks="default", **kwargs
            )
        return self.client.messages.create(**kwargs)

    def _budget_exhausted(self, inv: Investigation) -> bool:
        return (
            inv.steps_used >= self.settings.max_steps
            or inv.tokens_used >= self.settings.max_tokens_total
        )

    def _run_tool(self, inv: Investigation, block: Any) -> dict[str, Any]:
        args = block.input if isinstance(block.input, dict) else {}
        r = self.registry.call(block.name, args)
        suspicious = scan(r.content)
        record = ToolCallRecord(
            tool_call_id=r.tool_call_id,
            tool_name=r.tool_name,
            args=r.args,
            ok=r.ok,
            output=neutralize(r.content),  # exactly what the model sees inside the wrapper
            truncated=r.truncated,
            redactions=r.redactions,
            duration_ms=r.duration_ms,
            suspicious=suspicious,
        )
        inv.tool_calls.append(record)
        self._emit(
            inv,
            AuditEventType.TOOL_CALL,
            tool_call_id=r.tool_call_id,
            tool=r.tool_name,
            args=r.args,
            ok=r.ok,
            error=r.error,
            duration_ms=r.duration_ms,
            truncated=r.truncated,
            redactions=r.redactions,
        )
        if suspicious:
            self._emit(
                inv,
                AuditEventType.PROMPT_INJECTION_SUSPECTED,
                source="tool_output",
                tool_call_id=r.tool_call_id,
                tool=r.tool_name,
                rules=suspicious,
            )
        return {
            "type": "tool_result",
            "tool_use_id": block.id,
            "content": wrap_tool_output(
                r.tool_call_id, r.tool_name, r.content, ok=r.ok, suspicious=bool(suspicious)
            ),
            "is_error": not r.ok,
        }

    # -- main loop ------------------------------------------------------------------------

    def run(self, alert: Alert, investigation_id: str | None = None) -> Investigation:
        inv = Investigation(alert=alert, status=InvestigationStatus.RUNNING)
        if investigation_id:
            inv.id = investigation_id
        self._emit(
            inv, AuditEventType.INVESTIGATION_STARTED, alert_id=alert.id, model=self.settings.model
        )

        alert_flags = scan(alert_text(alert))
        if alert_flags:
            self._emit(
                inv, AuditEventType.PROMPT_INJECTION_SUSPECTED, source="alert", rules=alert_flags
            )
        all_tools = [*self.registry.specs(), SUBMIT_TOOL]
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": initial_user_message(alert, bool(alert_flags))}
        ]
        submission: dict[str, Any] | None = None
        finalizing = False
        reminded = False

        while True:
            try:
                response = self._create(messages, [SUBMIT_TOOL] if finalizing else all_tools)
            except anthropic.APIError as e:
                inv.status, inv.error = InvestigationStatus.FAILED, f"api_error: {type(e).__name__}"
                break

            inv.steps_used += 1
            usage = response.usage
            inv.input_tokens += (
                usage.input_tokens
                + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
                + (getattr(usage, "cache_read_input_tokens", 0) or 0)
            )
            inv.output_tokens += usage.output_tokens
            inv.tokens_used = inv.input_tokens + inv.output_tokens
            # Append unchanged so thinking blocks are preserved for the next turn.
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "refusal":
                inv.status, inv.error = InvestigationStatus.FAILED, "model_refused"
                break

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            submit = next((b for b in tool_uses if b.name == SUBMIT_TOOL_NAME), None)
            if submit is not None:
                submission = submit.input if isinstance(submit.input, dict) else {}
                break
            if finalizing:
                break

            if not tool_uses:
                if reminded:
                    inv.status, inv.error = InvestigationStatus.FAILED, "no_submission"
                    break
                reminded = True
                messages.append({"role": "user", "content": REMIND_PROMPT})
                continue

            # All results from one turn go back in a single user message.
            content: list[dict[str, Any]] = [self._run_tool(inv, b) for b in tool_uses]
            if self._budget_exhausted(inv):
                finalizing = True
                content.append({"type": "text", "text": FINALIZE_PROMPT})
            messages.append({"role": "user", "content": content})

        return self._finish(inv, submission, finalizing)

    def _finish(
        self, inv: Investigation, submission: dict[str, Any] | None, finalizing: bool
    ) -> Investigation:
        findings = build_findings(submission or {}, inv.tool_calls, self.registry.names)
        inv.hypotheses = findings.hypotheses
        inv.not_checked = findings.not_checked
        inv.suggested_actions = findings.suggested_actions
        inv.rejected_claims = findings.rejected
        inv.citations_submitted = findings.citations_submitted
        inv.citations_accepted = findings.citations_accepted
        inv.hypotheses_dropped = findings.hypotheses_dropped
        if inv.status == InvestigationStatus.RUNNING:
            inv.status = (
                InvestigationStatus.BUDGET_EXHAUSTED
                if finalizing or submission is None
                else InvestigationStatus.COMPLETED
            )
        inv.finished_at = datetime.now(UTC)
        for h in inv.hypotheses:
            self._emit(
                inv,
                AuditEventType.HYPOTHESIS,
                rank=h.rank,
                title=h.title,
                confidence=h.confidence.score,
                evidence=[e.tool_call_id for e in h.evidence],
            )
        self._emit(
            inv,
            AuditEventType.INVESTIGATION_FINISHED,
            status=inv.status,
            steps_used=inv.steps_used,
            tokens_used=inv.tokens_used,
            rejected_claims=len(inv.rejected_claims),
            error=inv.error,
        )
        log.info(
            "investigation id=%s status=%s steps=%s tokens=%s hypotheses=%s rejected=%s",
            inv.id,
            inv.status,
            inv.steps_used,
            inv.tokens_used,
            len(inv.hypotheses),
            len(inv.rejected_claims),
        )
        return Investigation.model_validate(inv.model_dump())


def main(argv: list[str] | None = None) -> None:
    from ira.fixtures import load_incident
    from ira.tools.registry import build_fixture_registry

    parser = argparse.ArgumentParser(description="Run one investigation against a fixture.")
    parser.add_argument("incident", help="fixture name, e.g. bad_deploy")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    settings = get_settings()
    alert = load_incident(args.incident, settings.fixtures_dir).alert
    registry = build_fixture_registry(args.incident, settings)
    try:
        inv = Investigator(registry, settings=settings).run(alert)
    finally:
        registry.close()
    print(inv.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
