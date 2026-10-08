"""Command-line interface: investigate, review drafts, and approve/reject/execute actions.

Execution is a dry run and requires a recorded human approval in the audit log.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import Any, TextIO

from ira.approvals import ApprovalError, Approvals, ApprovalState
from ira.audit import Store
from ira.config import Settings, get_settings
from ira.fixtures import load_incident
from ira.models import ApprovalStatus, AuditEventType, Investigation, StatusDraft
from ira.pipeline import run_investigation
from ira.tools.registry import build_fixture_registry

EXIT_OK, EXIT_NOT_FOUND, EXIT_DENIED = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ira", description="Incident Response Assistant")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("investigate", help="investigate a fixture incident")
    s.add_argument("incident")
    s.add_argument("--template-draft", action="store_true", help="skip the LLM status draft")

    sub.add_parser("list", help="list investigations")

    s = sub.add_parser("show", help="show an investigation, its draft and actions")
    s.add_argument("investigation_id")

    s = sub.add_parser("review", help="interactively approve/reject pending actions")
    s.add_argument("investigation_id")
    s.add_argument("--as", dest="actor", required=True, help="your name (recorded in audit log)")

    for name in ("approve", "reject"):
        s = sub.add_parser(name, help=f"{name} a suggested action")
        s.add_argument("action_id")
        s.add_argument("--as", dest="actor", required=True)
        s.add_argument("--reason", required=True)

    s = sub.add_parser("execute", help="execute an APPROVED action (dry run)")
    s.add_argument("action_id")
    s.add_argument("--as", dest="actor", required=True)

    s = sub.add_parser("audit", help="print the audit log")
    s.add_argument("investigation_id", nargs="?")
    s.add_argument("--verify", action="store_true", help="verify the hash chain")
    return p


def _resolve(prefix: str, candidates: list[str], kind: str) -> str:
    matches = [c for c in candidates if c.startswith(prefix)]
    if len(matches) != 1:
        raise LookupError(f"{kind} {prefix!r} " + ("not found" if not matches else "is ambiguous"))
    return matches[0]


def _action_ids(store: Store) -> list[str]:
    events = store.events(event_type=AuditEventType.APPROVAL_REQUESTED)
    return [e.payload["action_id"] for e in events]


def format_report(
    inv: Investigation, draft: StatusDraft | None, states: list[ApprovalState]
) -> str:
    lines = [
        f"Investigation {inv.id}  [{inv.status}]",
        f"Alert: {inv.alert.title} ({inv.alert.service}, {inv.alert.severity})",
        f"Steps: {inv.steps_used}  Tokens: {inv.tokens_used}  Tool calls: {len(inv.tool_calls)}"
        f"  Rejected claims: {len(inv.rejected_claims)}",
    ]
    if inv.error:
        lines.append(f"Error: {inv.error}")
    lines.append("\nHypotheses:")
    for h in inv.hypotheses or []:
        lines.append(f"  {h.rank}. {h.title}  [{h.confidence.level} {h.confidence.score:.2f}]")
        lines.append(f"     {h.explanation}")
        for e in h.evidence:
            lines.append(f"     - {e.tool_call_id} {e.tool_name}: {e.excerpt[:120]}")
    if not inv.hypotheses:
        lines.append("  (none with valid evidence)")
    lines.append("\nNot checked:")
    lines.extend(f"  - {x}" for x in inv.not_checked)
    if draft is not None:
        lines.append(f"\nStatus update draft ({draft.generated_by}):")
        lines.append(f"  {draft.summary}")
        lines.append("  Known:")
        lines.extend(f"   - {f.statement} [{', '.join(f.evidence_ids)}]" for f in draft.known_facts)
        lines.append("  Under investigation:")
        lines.extend(f"   - {x}" for x in draft.under_investigation)
        if draft.next_update_at:
            lines.append(f"  Next update by: {draft.next_update_at:%H:%M UTC}")
    lines.append("\nSuggested actions (nothing runs without approval):")
    for s in states:
        lines.append(
            f"  [{s.status}] {s.action.id[:8]}  ({s.action.risk} risk) {s.action.description}"
        )
        lines.append(f"     why: {s.action.rationale}")
        if s.decided_by:
            lines.append(f"     decided by {s.decided_by}: {s.reason}")
        if s.result:
            lines.append(f"     result: {s.result}")
    if not states:
        lines.append("  (none)")
    return "\n".join(lines)


def main(
    argv: list[str] | None = None,
    *,
    client: Any | None = None,
    store: Store | None = None,
    settings: Settings | None = None,
    input_fn: Callable[[str], str] = input,
    out: TextIO | None = None,
) -> int:
    args = _parser().parse_args(argv)
    settings = settings or get_settings()
    out = out or sys.stdout
    own_store = store is None
    store = store or Store(settings.db_path)
    approvals = Approvals(store)

    def say(*parts: Any) -> None:
        print(*parts, file=out)

    try:
        if args.cmd == "investigate":
            alert = load_incident(args.incident, settings.fixtures_dir).alert
            registry = build_fixture_registry(args.incident, settings)
            try:
                r = run_investigation(
                    alert, registry, store, client=client, settings=settings,
                    llm_drafts=not args.template_draft,
                )  # fmt: skip
            finally:
                registry.close()
            say(format_report(r.investigation, r.draft, r.approvals))
            say(f"\nNext: ira review {r.investigation.id[:8]} --as <your name>")

        elif args.cmd == "list":
            for inv in store.list_investigations():
                top = inv.hypotheses[0].title if inv.hypotheses else "-"
                say(f"{inv.id[:8]}  {inv.status:<16} {inv.alert.service:<18} {top}")

        elif args.cmd in ("show", "review"):
            ids = [i.id for i in store.list_investigations()]
            inv_id = _resolve(args.investigation_id, ids, "investigation")
            inv = store.get_investigation(inv_id)
            if inv is None:
                raise LookupError(f"investigation {inv_id} not found")
            if args.cmd == "show":
                say(format_report(inv, store.latest_draft(inv_id), approvals.list(inv_id)))
            else:
                pending = [s for s in approvals.list(inv_id) if s.status == ApprovalStatus.PENDING]
                if not pending:
                    say("No pending actions.")
                for s in pending:
                    say(
                        f"\nAction {s.action.id[:8]} ({s.action.risk} risk): {s.action.description}"
                    )
                    say(f"  why: {s.action.rationale}")
                    choice = input_fn("[a]pprove / [r]eject / [s]kip? ").strip().lower()[:1]
                    if choice in ("a", "r"):
                        reason = input_fn("reason: ")
                        decide = approvals.approve if choice == "a" else approvals.reject
                        result = decide(s.action.id, args.actor, reason)
                        say(f"  -> {result.status} by {result.decided_by}")
                    else:
                        say("  -> skipped")

        elif args.cmd in ("approve", "reject", "execute"):
            action_id = _resolve(args.action_id, _action_ids(store), "action")
            if args.cmd == "approve":
                s = approvals.approve(action_id, args.actor, args.reason)
            elif args.cmd == "reject":
                s = approvals.reject(action_id, args.actor, args.reason)
            else:
                s = approvals.execute(action_id, args.actor)
            say(f"{s.action.id[:8]} -> {s.status}" + (f": {s.result}" if s.result else ""))

        elif args.cmd == "audit":
            inv_id = None
            if args.investigation_id:
                ids = [i.id for i in store.list_investigations()]
                inv_id = _resolve(args.investigation_id, ids, "investigation")
            for e in store.events(investigation_id=inv_id):
                say(f"{e.ts:%Y-%m-%dT%H:%M:%SZ} {e.investigation_id[:8]} {e.actor:<12} "
                    f"{e.event_type:<24} {_brief(e.payload)}")  # fmt: skip
            if args.verify:
                problems = store.verify_chain()
                say("audit chain: OK" if not problems else "audit chain: BROKEN")
                for p in problems:
                    say(f"  {p}")
                if problems:
                    return EXIT_NOT_FOUND
        return EXIT_OK
    except ApprovalError as e:
        say(f"DENIED: {e}")
        return EXIT_DENIED
    except (LookupError, FileNotFoundError) as e:
        say(f"error: {e}")
        return EXIT_NOT_FOUND
    finally:
        if own_store:
            store.close()


def _brief(payload: dict[str, Any]) -> str:
    keys = ("tool_call_id", "tool", "ok", "action_id", "reason", "status", "title", "result")
    parts = [f"{k}={payload[k]}" for k in keys if k in payload]
    text = " ".join(parts)
    return text if len(text) <= 160 else text[:157] + "..."


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
