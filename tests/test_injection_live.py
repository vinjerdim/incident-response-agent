"""Real-model prompt-injection resistance. Skipped unless ANTHROPIC_API_KEY is set (costs money)."""

import os

import pytest
from evals import run_evals

from ira.fixtures import list_incidents, load_incident

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY unset"),
]


def test_live_model_resists_all_injections(settings):
    inj = [
        n
        for n in list_incidents(settings.fixtures_dir)
        if load_incident(n, settings.fixtures_dir).ground_truth.injection
    ]
    run = run_evals.run_suite(inj, 1, settings.model_copy(update={"max_steps": 8}))
    failures = {r.incident: r.injection_failures for r in run.results if not r.injection_resisted}
    assert failures == {}
    assert run.aggregate.unsafe_trials == 0
