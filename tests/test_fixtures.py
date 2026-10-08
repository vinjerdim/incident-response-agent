import json

import pytest

from conftest import FIXTURES
from ira.fixtures import list_incidents, load_incident

EXPECTED = {
    "bad_deploy",
    "config_change",
    "db_conn_exhaustion",
    "expired_cert",
    "memory_leak",
    "noisy_false_alarm",
    "traffic_spike",
    "upstream_outage",
}


def test_all_incidents_present():
    assert set(list_incidents(FIXTURES)) == EXPECTED


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_loads_and_is_well_formed(name):
    f = load_incident(name, FIXTURES)
    assert f.alert.service
    assert len(f.logs) >= 60
    assert 3 <= len(f.metrics) <= 5
    assert 1 <= len(f.deploys) <= 4
    assert f.runbooks
    assert f.ground_truth.red_herrings
    assert f.ground_truth.planted_sensitive
    window = (f.logs[0].ts, f.logs[-1].ts)
    assert window[0] < f.alert.fired_at < window[1]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_ground_truth_key_evidence_exists_in_source(name):
    """Eval validity: every key evidence string must really be findable by the tools."""
    f = load_incident(name, FIXTURES)
    haystacks = {
        "logs": "\n".join(x.message for x in f.logs),
        "metrics": "\n".join(m.name for m in f.metrics),
        "deploys": "\n".join(f"{d.id} {d.version} {d.summary}\n{d.diff}" for d in f.deploys),
        "runbooks": "\n".join(r.body for r in f.runbooks),
    }
    for ev in f.ground_truth.key_evidence:
        assert ev.contains in haystacks[ev.source], (name, ev)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_planted_sensitive_values_are_present(name):
    """Phase 3 redaction tests rely on these appearing in tool-visible data."""
    f = load_incident(name, FIXTURES)
    visible = "\n".join(x.message for x in f.logs)
    for value in f.ground_truth.planted_sensitive:
        assert value in visible, (name, value)


def test_only_one_false_alarm():
    flags = {n: load_incident(n, FIXTURES).ground_truth.is_false_alarm for n in EXPECTED}
    assert [n for n, v in flags.items() if v] == ["noisy_false_alarm"]


def test_unknown_incident_raises():
    with pytest.raises(FileNotFoundError):
        load_incident("does_not_exist", FIXTURES)


def test_logs_are_chronological():
    for name in EXPECTED:
        lines = (FIXTURES / name / "logs.jsonl").read_text().splitlines()
        ts = [json.loads(line)["ts"] for line in lines]
        assert ts == sorted(ts), name
