from datetime import UTC, datetime

import anthropic
import httpx2
import pytest

from fake_llm import FakeClient, parsed
from ira.drafts import Drafter, DraftFact, DraftOutput, check_draft, template_draft
from ira.models import (
    Alert,
    AlertSource,
    Confidence,
    Evidence,
    Hypothesis,
    Investigation,
    InvestigationStatus,
    KnownFact,
    Severity,
    StatusDraft,
    ToolCallRecord,
)


@pytest.fixture
def inv():
    return Investigation(
        alert=Alert(
            source=AlertSource.ALERTMANAGER,
            service="checkout-api",
            title="checkout-api 5xx rate above 5%",
            severity=Severity.HIGH,
            fired_at=datetime(2026, 9, 14, 14, 32, tzinfo=UTC),
        ),
        status=InvestigationStatus.COMPLETED,
        tool_calls=[
            ToolCallRecord(
                tool_call_id="call_001",
                tool_name="search_logs",
                ok=True,
                output="ERROR KeyError: 'promo_code'",
            ),
            ToolCallRecord(
                tool_call_id="call_002", tool_name="list_deploys", ok=True, output="v2.14.0"
            ),
        ],
        hypotheses=[
            Hypothesis(
                rank=1,
                title="Deploy v2.14.0 broke checkout",
                explanation="KeyError after deploy",
                confidence=Confidence.from_score(0.85),
                evidence=[
                    Evidence(
                        tool_call_id="call_001",
                        tool_name="search_logs",
                        excerpt="KeyError: 'promo_code'",
                    )
                ],
            )
        ],
        not_checked=["traces"],
    )


def draft(
    inv, summary="Some customers cannot check out. We are investigating.", facts=None, under=None
):
    return StatusDraft(
        investigation_id=inv.id,
        summary=summary,
        known_facts=facts
        if facts is not None
        else [
            KnownFact(
                statement="Checkout errors rose sharply at 14:25 UTC.", evidence_ids=["call_001"]
            )
        ],
        under_investigation=under or ["A recent update is the likely trigger (high confidence)."],
    )


GOOD = DraftOutput(
    summary="Some customers cannot complete checkout. We suspect a recent update is the cause "
    "and are investigating.",
    known_facts=[
        DraftFact(statement="Checkout errors rose at 14:25 UTC.", evidence_ids=["call_001"]),
        DraftFact(statement="The alert fired at 14:32 UTC.", evidence_ids=["alert"]),
    ],
    under_investigation=["A software update released at 14:24 UTC (high confidence)."],
)
BAD = DraftOutput(
    summary="The outage was caused by release v2.14.0.",
    known_facts=[DraftFact(statement="The root cause is the deploy.", evidence_ids=["call_777"])],
    under_investigation=[],
)


def test_good_draft_passes(inv):
    assert check_draft(draft(inv), inv) == []


@pytest.mark.parametrize(
    "kwargs,needle",
    [
        (
            {"facts": [KnownFact(statement="Errors rose.", evidence_ids=["call_999"])]},
            "unknown evidence ids",
        ),
        (
            {
                "facts": [
                    KnownFact(
                        statement="Errors were caused by the deploy.", evidence_ids=["call_002"]
                    )
                ]
            },
            "states a cause as fact",
        ),
        ({"summary": "Checkout is down due to the new release."}, "without hedging"),
        ({"summary": "We rolled back the release. Checkout works."}, "action was taken"),
        ({"summary": "The issue has been resolved."}, "action was taken"),
        ({"under": ["Customer jane.doe@example.com reported it"]}, "secret or personal"),
    ],
)
def test_checker_rejects(inv, kwargs, needle):
    problems = check_draft(draft(inv, **kwargs), inv)
    assert any(needle in p for p in problems), problems


def test_hedged_cause_in_summary_is_allowed(inv):
    d = draft(
        inv, summary="Checkout errors are likely due to a recent update. We are investigating."
    )
    assert check_draft(d, inv) == []


@pytest.mark.parametrize("status", [InvestigationStatus.COMPLETED, InvestigationStatus.FAILED])
def test_template_draft_always_passes_checker(inv, status):
    inv.status = status
    d = template_draft(inv, now=datetime(2026, 9, 14, 14, 40, tzinfo=UTC))
    assert d.generated_by == "template"
    assert check_draft(d, inv) == []
    assert d.known_facts[0].evidence_ids == ["alert"]
    assert d.next_update_at == datetime(2026, 9, 14, 15, 10, tzinfo=UTC)  # high sev: 30 min
    assert "Possible cause (high confidence)" in d.under_investigation[0]


def test_template_redacts_untrusted_alert_title(inv):
    inv.alert = inv.alert.model_copy(update={"title": "errors for bob@example.com"})
    d = template_draft(inv)
    assert "bob@example.com" not in d.summary and check_draft(d, inv) == []


def test_llm_draft_accepted(inv, settings):
    client = FakeClient([], parse_script=[parsed(GOOD)])
    d = Drafter(client, settings).draft(inv)
    assert d.generated_by == "llm" and d.summary == GOOD.summary
    call = client.parse_calls[0]
    assert call["output_format"] is DraftOutput
    assert "<investigation_data>" in call["messages"][0]["content"]
    assert "untrusted" in call["system"]


def test_llm_retry_then_success(inv, settings):
    client = FakeClient([], parse_script=[parsed(BAD), parsed(GOOD)])
    drafter = Drafter(client, settings)
    d = drafter.draft(inv)
    assert d.generated_by == "llm"
    retry_msg = client.parse_calls[1]["messages"][-1]["content"]
    assert "rejected" in retry_msg and "call_777" in retry_msg
    assert drafter.problems


def test_llm_fails_twice_falls_back_to_template(inv, settings):
    client = FakeClient([], parse_script=[parsed(BAD), parsed(BAD)])
    assert Drafter(client, settings).draft(inv).generated_by == "template"


@pytest.mark.parametrize(
    "step",
    [
        parsed(None, stop="refusal"),
        anthropic.APIConnectionError(request=httpx2.Request("POST", "https://example.invalid")),
    ],
)
def test_llm_unavailable_falls_back(inv, settings, step):
    client = FakeClient([], parse_script=[step])
    assert Drafter(client, settings).draft(inv).generated_by == "template"


def test_no_client_uses_template(inv, settings):
    assert Drafter(None, settings).draft(inv).generated_by == "template"
