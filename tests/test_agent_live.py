"""Real API run against one fixture. Skipped unless ANTHROPIC_API_KEY is set (costs money)."""

import os

import pytest

from ira.agent import Investigator
from ira.fixtures import load_incident
from ira.models import InvestigationStatus
from ira.tools.registry import build_fixture_registry

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY unset"),
]


def test_live_bad_deploy(settings):
    reg = build_fixture_registry("bad_deploy", settings)
    try:
        inv = Investigator(reg, settings=settings.model_copy(update={"max_steps": 8})).run(
            load_incident("bad_deploy", settings.fixtures_dir).alert
        )
    finally:
        reg.close()
    assert inv.status in (InvestigationStatus.COMPLETED, InvestigationStatus.BUDGET_EXHAUSTED)
    assert inv.hypotheses, inv.rejected_claims
    top = inv.hypotheses[0]
    blob = (top.title + top.explanation + " ".join(e.excerpt for e in top.evidence)).lower()
    assert "v2.14.0" in blob or "promo_code" in blob
