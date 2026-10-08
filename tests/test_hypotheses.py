from ira.hypotheses import SCOPE_DISCLAIMER, build_findings
from ira.models import ConfidenceLevel, Risk, ToolCallRecord

CALLS = [
    ToolCallRecord(
        tool_call_id="call_001",
        tool_name="search_logs",
        ok=True,
        output="2026-09-14T14:25:10Z ERROR checkout-api h1 KeyError: 'promo_code'\n"
        "second   line   with   spaces",
    ),
    ToolCallRecord(
        tool_call_id="call_002",
        tool_name="list_deploys",
        ok=True,
        output="d-1042 ... version=v2.14.0",
    ),
    ToolCallRecord(tool_call_id="call_003", tool_name="get_runbook", ok=False, output="No runbook"),
]
TOOLS = ["search_logs", "list_deploys", "get_runbook", "query_metrics"]


def h(title, score, *ev, explanation="because"):
    return {
        "title": title,
        "explanation": explanation,
        "confidence_score": score,
        "evidence": [{"tool_call_id": c, "excerpt": e} for c, e in ev],
    }


def test_valid_citations_kept_and_ranked_by_score():
    f = build_findings(
        {
            "hypotheses": [
                h("B", 0.3, ("call_002", "v2.14.0")),
                h("A", 0.9, ("call_001", "KeyError: 'promo_code'")),
            ]
        },
        CALLS,
        TOOLS,
    )
    assert [(x.rank, x.title) for x in f.hypotheses] == [(1, "A"), (2, "B")]
    assert f.hypotheses[0].confidence.level == ConfidenceLevel.HIGH
    assert f.hypotheses[1].confidence.level == ConfidenceLevel.LOW
    assert f.rejected == []


def test_whitespace_normalized_matching():
    f = build_findings(
        {"hypotheses": [h("A", 0.5, ("call_001", "second line with spaces"))]}, CALLS, TOOLS
    )
    assert len(f.hypotheses) == 1


def test_bad_citations_dropped_and_recorded():
    f = build_findings(
        {
            "hypotheses": [
                h("A", 0.8, ("call_001", "KeyError: 'promo_code'"), ("call_404", "x")),
                h("Ghost", 0.9, ("call_404", "anything")),
                h("Paraphrase", 0.9, ("call_001", "a KeyError happened")),
                h("Failed", 0.9, ("call_003", "No runbook")),
                h("Empty", 0.9, ("call_001", "   ")),
                h("NoEvidence", 0.9),
            ]
        },
        CALLS,
        TOOLS,
    )
    assert [x.title for x in f.hypotheses] == ["A"]
    assert len(f.hypotheses[0].evidence) == 1
    joined = "\n".join(f.rejected)
    for needle in [
        "unknown tool_call_id 'call_404'",
        "excerpt not found",
        "failed call",
        "empty excerpt",
        "NoEvidence: dropped",
    ]:
        assert needle in joined, needle


def test_not_checked_always_populated():
    f = build_findings({"not_checked": ["traces", "Traces "]}, CALLS, TOOLS)
    assert f.not_checked[0] == "traces"
    assert "Tool 'query_metrics' was never called." in f.not_checked
    assert "Tool 'get_runbook' was never called." in f.not_checked  # only a failed call
    assert f.not_checked[-1] == SCOPE_DISCLAIMER
    assert len([x for x in f.not_checked if x.lower() == "traces"]) == 1


def test_score_clamped_and_actions_normalized():
    f = build_findings(
        {
            "hypotheses": [h("A", 7.0, ("call_002", "v2.14.0"))],
            "suggested_actions": [
                {"description": "Roll back", "rationale": "deploy", "risk": "catastrophic"},
                {"description": "", "rationale": "x", "risk": "low"},
            ],
        },
        CALLS,
        TOOLS,
    )
    assert f.hypotheses[0].confidence.score == 1.0
    assert len(f.suggested_actions) == 1
    assert f.suggested_actions[0].risk == Risk.HIGH  # unknown risk treated as high
    assert f.suggested_actions[0].requires_approval is True


def test_malformed_submission_does_not_crash():
    f = build_findings({"hypotheses": "not a list"}, CALLS, TOOLS)
    assert f.hypotheses == [] and f.not_checked and "malformed" in f.rejected[0]
