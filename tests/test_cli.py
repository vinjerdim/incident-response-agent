import io

import pytest

from fake_llm import FakeClient, msg, parsed, tool_use
from ira.audit import Store
from ira.cli import EXIT_DENIED, EXIT_NOT_FOUND, EXIT_OK, main
from ira.models import AuditEventType
from ira.prompts import SUBMIT_TOOL_NAME

ACTION = {
    "description": "Roll back checkout-api to v2.13.2",
    "rationale": "errors began right after v2.14.0",
    "risk": "medium",
}


def agent_script():
    return [
        msg(tool_use("list_deploys"), tool_use("search_logs", min_level="ERROR", limit=3)),
        msg(
            tool_use(
                SUBMIT_TOOL_NAME,
                hypotheses=[
                    {
                        "title": "Deploy v2.14.0 introduced a KeyError",
                        "explanation": "timing",
                        "confidence_score": 0.85,
                        "evidence": [
                            {"tool_call_id": "call_001", "excerpt": "version=v2.14.0"},
                            {"tool_call_id": "call_002", "excerpt": "KeyError: 'promo_code'"},
                        ],
                    }
                ],
                not_checked=["traces"],
                suggested_actions=[ACTION],
            )
        ),
    ]


@pytest.fixture
def cli(settings):
    store = Store(":memory:")

    def run(*argv, client=None, answers=()):
        out = io.StringIO()
        it = iter(answers)
        code = main(
            list(argv),
            client=client,
            store=store,
            settings=settings,
            input_fn=lambda _prompt: next(it),
            out=out,
        )
        return code, out.getvalue()

    yield run, store
    store.close()


def investigate(run):
    client = FakeClient(agent_script())
    code, out = run("investigate", "bad_deploy", "--template-draft", client=client)
    assert code == EXIT_OK, out
    return out


def test_end_to_end_investigate_approve_execute_audit(cli):
    run, store = cli
    out = investigate(run)
    assert "Deploy v2.14.0 introduced a KeyError" in out
    assert "[pending]" in out and "Roll back checkout-api" in out
    assert "Status update draft (template)" in out

    action_id = store.events(event_type=AuditEventType.APPROVAL_REQUESTED)[0].payload["action_id"]

    code, out = run("execute", action_id[:8], "--as", "alice")
    assert code == EXIT_DENIED and "DENIED" in out

    code, out = run("approve", action_id[:8], "--as", "alice", "--reason", "matches deploy time")
    assert code == EXIT_OK and "approved" in out

    code, out = run("execute", action_id[:8], "--as", "alice")
    assert code == EXIT_OK and "executed" in out and "DRY RUN" in out

    code, out = run("audit", "--verify")
    assert code == EXIT_OK and "audit chain: OK" in out
    types = [e.event_type for e in store.events()]
    assert types[0] == AuditEventType.INVESTIGATION_STARTED
    assert types.count(AuditEventType.TOOL_CALL) == 2
    assert types[-4:] == [
        AuditEventType.DRAFT,
        AuditEventType.APPROVAL_REQUESTED,
        AuditEventType.APPROVED,
        AuditEventType.EXECUTED,
    ]


def test_review_interactive(cli):
    run, store = cli
    investigate(run)
    inv_id = store.list_investigations()[0].id
    code, out = run("review", inv_id[:8], "--as", "carol", answers=["r", "not during peak"])
    assert code == EXIT_OK and "rejected by carol" in out
    code, out = run("show", inv_id[:8])
    assert "[rejected]" in out and "decided by carol: not during peak" in out
    code, out = run("review", inv_id[:8], "--as", "carol")
    assert "No pending actions." in out


def test_agent_cannot_approve_via_cli(cli):
    run, store = cli
    investigate(run)
    action_id = store.events(event_type=AuditEventType.APPROVAL_REQUESTED)[0].payload["action_id"]
    code, _out = run("approve", action_id, "--as", "agent", "--reason", "I am sure")
    assert code == EXIT_DENIED


def test_llm_draft_through_pipeline(cli):
    from test_drafts import GOOD

    run, store = cli
    client = FakeClient(agent_script(), parse_script=[parsed(GOOD)])
    code, out = run("investigate", "bad_deploy", client=client)
    assert code == EXIT_OK
    assert "Status update draft (llm)" in out
    inv = store.list_investigations()[0]
    assert store.latest_draft(inv.id).generated_by == "llm"


def test_list_and_not_found(cli):
    run, _ = cli
    investigate(run)
    code, out = run("list")
    assert code == EXIT_OK and "bad_deploy" not in out and "checkout-api" in out
    assert run("show", "zzzz")[0] == EXIT_NOT_FOUND
    assert run("approve", "zzzz", "--as", "a", "--reason", "b")[0] == EXIT_NOT_FOUND
    assert run("investigate", "no_such_fixture", client=FakeClient([]))[0] == EXIT_NOT_FOUND
