import anthropic
import httpx2
import pytest

from fake_llm import FakeClient, last_user_content, msg, text, tool_use
from ira.agent import FALLBACK_BETA, Investigator
from ira.fixtures import load_incident
from ira.models import AuditEventType, ConfidenceLevel, InvestigationStatus
from ira.prompts import FINALIZE_PROMPT, REMIND_PROMPT, SUBMIT_TOOL, SUBMIT_TOOL_NAME
from ira.tools.registry import build_fixture_registry


@pytest.fixture
def run(settings):
    registries = []

    def _run(script, incident="bad_deploy", **overrides):
        s = settings.model_copy(update=overrides)
        reg = build_fixture_registry(incident, s)
        registries.append(reg)
        client = FakeClient(script)
        events = []
        inv = Investigator(reg, client=client, settings=s, on_event=events.append).run(
            load_incident(incident, s.fixtures_dir).alert
        )
        return inv, client, events

    yield _run
    for r in registries:
        r.close()


def submit(*hypotheses, not_checked=(), actions=()):
    return tool_use(
        SUBMIT_TOOL_NAME,
        hypotheses=list(hypotheses),
        not_checked=list(not_checked),
        suggested_actions=list(actions),
    )


def hyp(title, score, *evidence):
    return {
        "title": title,
        "explanation": f"{title} explanation",
        "confidence_score": score,
        "evidence": [{"tool_call_id": c, "excerpt": e} for c, e in evidence],
    }


def test_happy_path_with_citation_verification(run):
    script = [
        msg(tool_use("search_logs", min_level="ERROR", limit=5), tool_use("list_deploys")),
        msg(
            submit(
                hyp(
                    "Bad deploy v2.14.0",
                    0.85,
                    ("call_001", "KeyError: 'promo_code'"),
                    ("call_002", "version=v2.14.0"),
                ),
                hyp("DB overload", 0.3, ("call_999", "db cpu 48%")),
                hyp("Invented", 0.5, ("call_001", "this text is not in the output")),
                not_checked=["traces"],
                actions=[
                    {
                        "description": "Roll back to v2.13.2",
                        "rationale": "errors began after v2.14.0",
                        "risk": "medium",
                    }
                ],
            )
        ),
    ]
    inv, client, _ = run(script)

    assert inv.status == InvestigationStatus.COMPLETED
    assert [h.title for h in inv.hypotheses] == ["Bad deploy v2.14.0"]
    top = inv.hypotheses[0]
    assert top.rank == 1 and top.confidence.level == ConfidenceLevel.HIGH
    assert {e.tool_call_id for e in top.evidence} == {"call_001", "call_002"}
    assert {e.tool_name for e in top.evidence} == {"search_logs", "list_deploys"}
    assert any("call_999" in r for r in inv.rejected_claims)
    assert any("not found" in r for r in inv.rejected_claims)
    assert "traces" in inv.not_checked
    assert "Tool 'query_metrics' was never called." in inv.not_checked
    assert inv.suggested_actions[0].requires_approval is True
    assert inv.steps_used == 2 and inv.tokens_used == 300
    assert [c.tool_call_id for c in inv.tool_calls] == ["call_001", "call_002"]

    # Parallel tool results go back in one user message, delimited as untrusted data.
    results = last_user_content(client.calls[1])
    assert [r["type"] for r in results] == ["tool_result", "tool_result"]
    assert results[0]["content"].startswith('<tool_output call_id="call_001" tool="search_logs"')
    assert results[0]["content"].endswith("</tool_output>")
    assert results[0]["is_error"] is False


def test_request_shape(run):
    _, client, _ = run([msg(text("thinking out loud")), msg(text("still no tool"))])
    first = client.calls[0]
    assert "UNTRUSTED DATA" in first["system"]
    assert first["betas"] == [FALLBACK_BETA] and first["fallbacks"] == "default"
    assert first["output_config"] == {"effort": "high"}
    assert first["model"] == "claude-opus-5-5"
    assert "tool_choice" not in first  # forced tool choice is rejected by current models
    assert {t["name"] for t in first["tools"]} >= {"search_logs", SUBMIT_TOOL_NAME}
    assert "<alert_data>" in first["messages"][0]["content"]


def test_no_fallback_path_uses_plain_messages(run):
    _, client, _ = run([msg(text("a")), msg(text("b"))], refusal_fallback=False)
    assert "betas" not in client.calls[0] and "fallbacks" not in client.calls[0]


def test_tool_output_is_redacted_before_model_sees_it(run):
    script = [
        msg(tool_use("search_logs", query="payment request payload")),
        msg(submit()),
    ]
    inv, client, _ = run(script)
    content = last_user_content(client.calls[1])[0]["content"]
    assert "jane.doe@example.com" not in content and "4111111111111111" not in content
    assert "[REDACTED:email]" in content and "[REDACTED:card]" in content
    assert inv.tool_calls[0].redactions == {"email": 1, "card": 1}


def test_step_budget_forces_finalize_turn(run):
    def finalize(kwargs):
        assert kwargs["tools"] == [SUBMIT_TOOL]
        assert last_user_content(kwargs)[-1] == {"type": "text", "text": FINALIZE_PROMPT}
        return msg(submit(hyp("Deploy", 0.5, ("call_002", "v2.14.0"))))

    script = [msg(tool_use("list_metrics")), msg(tool_use("list_deploys")), finalize]
    inv, _, _ = run(script, max_steps=2)
    assert inv.status == InvestigationStatus.BUDGET_EXHAUSTED
    assert inv.steps_used == 3
    assert inv.hypotheses and inv.hypotheses[0].confidence.level == ConfidenceLevel.MEDIUM


def test_budget_exhausted_without_submission(run):
    script = [msg(tool_use("list_metrics")), msg(text("I need more time"))]
    inv, _, _ = run(script, max_steps=1)
    assert inv.status == InvestigationStatus.BUDGET_EXHAUSTED
    assert inv.hypotheses == [] and inv.not_checked


def test_token_budget(run):
    script = [msg(tool_use("list_metrics"), inp=2_000), msg(submit())]
    inv, client, _ = run(script, max_tokens_total=1_000)
    assert client.calls[1]["tools"] == [SUBMIT_TOOL]
    assert inv.status == InvestigationStatus.BUDGET_EXHAUSTED


def test_refusal_fails(run):
    inv, _, _ = run([msg(text(""), stop="refusal")])
    assert inv.status == InvestigationStatus.FAILED and inv.error == "model_refused"


def test_reminds_once_then_fails(run):
    inv, client, _ = run([msg(text("Root cause is the deploy.")), msg(text("Yes, the deploy."))])
    assert client.calls[1]["messages"][-1] == {"role": "user", "content": REMIND_PROMPT}
    assert inv.status == InvestigationStatus.FAILED and inv.error == "no_submission"
    assert inv.hypotheses == []  # plain-text conclusions are never accepted


def test_reminder_then_submit_completes(run):
    script = [
        msg(tool_use("list_deploys")),
        msg(text("It is the deploy.")),
        msg(submit(hyp("Deploy", 0.9, ("call_001", "v2.14.0")))),
    ]
    inv, _, _ = run(script)
    assert inv.status == InvestigationStatus.COMPLETED and len(inv.hypotheses) == 1


def test_tool_errors_flagged_and_not_citable(run):
    script = [
        msg(tool_use("restart_service", name="checkout"), tool_use("search_logs", limit=0)),
        msg(submit(hyp("Restarted", 0.9, ("call_001", "Unknown tool")))),
    ]
    inv, client, _ = run(script)
    results = last_user_content(client.calls[1])
    assert all(r["is_error"] for r in results)
    assert 'status="error"' in results[0]["content"]
    assert [c.ok for c in inv.tool_calls] == [False, False]
    assert inv.hypotheses == [] and any("failed call" in r for r in inv.rejected_claims)


def test_api_error_fails_cleanly(run):
    err = anthropic.APIConnectionError(request=httpx2.Request("POST", "https://example.invalid"))
    inv, _, _ = run([err])
    assert inv.status == InvestigationStatus.FAILED and inv.error == "api_error: APIConnectionError"
    assert inv.not_checked


def test_audit_events_emitted(run):
    script = [
        msg(tool_use("list_deploys")),
        msg(submit(hyp("Deploy", 0.9, ("call_001", "v2.14.0")))),
    ]
    inv, _, events = run(script)
    types = [e.event_type for e in events]
    assert types == [
        AuditEventType.INVESTIGATION_STARTED,
        AuditEventType.TOOL_CALL,
        AuditEventType.HYPOTHESIS,
        AuditEventType.INVESTIGATION_FINISHED,
    ]
    assert all(e.investigation_id == inv.id and e.actor == "agent" for e in events)
    assert events[1].payload["tool_call_id"] == "call_001"
