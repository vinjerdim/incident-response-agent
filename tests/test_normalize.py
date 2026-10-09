import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ira.models import AlertSource, Severity
from ira.normalize import (
    MAX_TITLE,
    NormalizationError,
    from_alertmanager,
    from_pagerduty,
    map_severity,
)

PAYLOADS = Path(__file__).parent / "payloads"


def load(name):
    return json.loads((PAYLOADS / f"{name}.json").read_text())


def test_alertmanager_batch():
    out = from_alertmanager(load("alertmanager_firing"))
    assert [n.state for n in out] == ["firing", "firing"]
    a = out[0].alert
    assert a.source == AlertSource.ALERTMANAGER
    assert a.service == "checkout-api" and a.title == "checkout-api 5xx rate above 5%"
    assert a.severity == Severity.CRITICAL
    assert a.fired_at == datetime(2026, 9, 14, 14, 32, tzinfo=UTC)
    assert out[0].dedupe_key == a.dedupe_key == "a1b2c3d4e5f60718"
    assert a.labels["env"] == "prod" and a.raw["fingerprint"] == "a1b2c3d4e5f60718"
    b = out[1].alert
    assert b.service == "billing-batch"  # falls back to job label
    assert b.title == "DiskFillingUp"  # falls back to alertname
    assert b.severity == Severity.MEDIUM


def test_alertmanager_resolved():
    out = from_alertmanager(load("alertmanager_resolved"))
    assert len(out) == 1 and out[0].state == "resolved" and out[0].alert is None
    assert out[0].dedupe_key == "a1b2c3d4e5f60718"


def test_alertmanager_dedupe_key_hash_when_no_fingerprint():
    p = load("alertmanager_firing")
    for a in p["alerts"]:
        a.pop("fingerprint")
    k1 = from_alertmanager(p)[0].dedupe_key
    k2 = from_alertmanager(p)[0].dedupe_key
    assert k1 == k2 and len(k1) == 32


def test_pagerduty_v3():
    out = from_pagerduty(load("pagerduty_v3_triggered"))
    n = out[0]
    assert n.state == "firing" and n.dedupe_key == "orders-service/errors"
    assert n.alert.source == AlertSource.PAGERDUTY
    assert n.alert.service == "orders-service"
    assert n.alert.severity == Severity.CRITICAL  # priority P1 beats urgency
    assert n.alert.labels["pd_incident_id"] == "Q2AZ8Y1X4PB7KN"


@pytest.mark.parametrize(
    "event_type,state",
    [("incident.resolved", "resolved"), ("incident.acknowledged", "ignored")],
)
def test_pagerduty_v3_other_events(event_type, state):
    p = load("pagerduty_v3_triggered")
    p["event"]["event_type"] = event_type
    assert from_pagerduty(p)[0].state == state


def test_pagerduty_v3_urgency_without_priority():
    p = load("pagerduty_v3_triggered")
    p["event"]["data"]["priority"] = None
    p["event"]["data"]["urgency"] = "low"
    assert from_pagerduty(p)[0].alert.severity == Severity.LOW


def test_pagerduty_events_v2():
    n = from_pagerduty(load("pagerduty_events_v2"))[0]
    assert n.state == "firing" and n.dedupe_key == "auth-service/login"
    assert n.alert.service == "auth-service" and n.alert.severity == Severity.CRITICAL
    assert n.alert.labels == {
        "source": "prometheus-prod",
        "component": "auth-service",
        "group": "identity",
        "class": "slo",
    }


def test_pagerduty_events_v2_resolve_without_payload():
    out = from_pagerduty({"event_action": "resolve", "dedup_key": "auth-service/login"})
    assert out[0].state == "resolved" and out[0].dedupe_key == "auth-service/login"


@pytest.mark.parametrize(
    "fn,payload",
    [
        (from_alertmanager, {"alerts": []}),
        (from_alertmanager, {"alerts": [{"status": "exploded"}]}),
        (from_alertmanager, ["not", "a", "dict"]),
        (from_pagerduty, {"hello": "world"}),
        (from_pagerduty, {"event": {"event_type": "incident.triggered"}}),
        (from_pagerduty, {"event_action": "trigger"}),
        (from_pagerduty, {"event_action": "explode", "payload": {}}),
    ],
)
def test_malformed(fn, payload):
    with pytest.raises(NormalizationError):
        fn(payload)


def test_untrusted_text_is_capped_and_cleaned():
    p = load("alertmanager_firing")
    p["alerts"][0]["annotations"]["summary"] = "x\x00\x1b[31m" + "A" * 1000
    p["alerts"][0]["labels"].update({f"l{i}": "v" for i in range(100)})
    a = from_alertmanager(p)[0].alert
    assert "\x00" not in a.title and "\x1b" not in a.title
    assert len(a.title) == MAX_TITLE
    assert len(a.labels) == 50


@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", Severity.CRITICAL),
        ("P2", Severity.HIGH),
        ("Warning", Severity.MEDIUM),
        ("minor", Severity.LOW),
        ("info", Severity.INFO),
        ("weird", Severity.MEDIUM),
        (None, Severity.MEDIUM),
    ],
)
def test_severity_map(value, expected):
    assert map_severity(value) == expected
