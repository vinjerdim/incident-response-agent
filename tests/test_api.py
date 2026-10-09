import hashlib
import hmac
import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from fake_llm import FakeClient, msg, parsed, tool_use
from ira.api import NO_DATA_SOURCE, create_app
from ira.audit import Store
from ira.models import AuditEventType, InvestigationStatus
from ira.prompts import SUBMIT_TOOL_NAME

PAYLOADS = Path(__file__).parent / "payloads"


def payload(name):
    return json.loads((PAYLOADS / f"{name}.json").read_text())


class StubRunner:
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self, alert, inv_id):
        with self.lock:
            self.calls.append((alert.service, inv_id))


@pytest.fixture
def api(settings):
    stores = []

    def make(runner=None, client=None, **overrides):
        store = Store(":memory:")
        stores.append(store)
        s = settings.model_copy(update=overrides)
        runner = runner if runner is not None or client is not None else StubRunner()
        app = create_app(store=store, client=client, settings=s, runner=runner)
        return TestClient(app), store, runner

    yield make
    for s in stores:
        s.close()


def test_alertmanager_starts_investigations(api):
    client, store, runner = api()
    with client:
        r = client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
    assert r.status_code == 202
    results = r.json()["results"]
    assert [x["outcome"] for x in results] == ["started", "started"]
    assert sorted(s for s, _ in runner.calls) == ["billing-batch", "checkout-api"]
    received = store.events(event_type=AuditEventType.ALERT_RECEIVED)
    assert {e.investigation_id for e in received} == {x["investigation_id"] for x in results}


def test_repeat_alert_is_deduplicated(api):
    client, store, runner = api()
    with client:
        client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
        r = client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
    assert [x["outcome"] for x in r.json()["results"]] == ["deduplicated", "deduplicated"]
    assert r.json()["results"][0]["count"] == 2
    assert len(runner.calls) == 2  # only the first delivery started investigations
    assert len(store.events(event_type=AuditEventType.ALERT_DEDUPED)) == 2


def test_resolve_then_refire(api):
    client, _, runner = api()
    with client:
        first = client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
        res = client.post("/webhooks/alertmanager", json=payload("alertmanager_resolved"))
        again = client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
    inv_id = first.json()["results"][0]["investigation_id"]
    assert res.json()["results"] == [
        {"dedupe_key": "a1b2c3d4e5f60718", "investigation_id": inv_id, "outcome": "resolved"}
    ]
    assert [x["outcome"] for x in again.json()["results"]] == ["started", "deduplicated"]
    assert len(runner.calls) == 3


def test_pagerduty_both_formats(api):
    client, _, runner = api()
    with client:
        r1 = client.post("/webhooks/pagerduty", json=payload("pagerduty_v3_triggered"))
        r2 = client.post("/webhooks/pagerduty", json=payload("pagerduty_events_v2"))
        ack = payload("pagerduty_v3_triggered")
        ack["event"]["event_type"] = "incident.acknowledged"
        r3 = client.post("/webhooks/pagerduty", json=ack)
    assert r1.json()["results"][0]["outcome"] == "started"
    assert r2.json()["results"][0]["outcome"] == "started"
    assert r3.json()["results"][0]["outcome"] == "ignored"
    assert sorted(s for s, _ in runner.calls) == ["auth-service", "orders-service"]


@pytest.mark.parametrize(
    "body,status",
    [(b"{not json", 400), (b'{"alerts": []}', 422), (b'{"alerts": [{"status": "x"}]}', 422)],
)
def test_bad_payloads(api, body, status):
    client, _, runner = api()
    with client:
        r = client.post(
            "/webhooks/alertmanager", content=body, headers={"content-type": "application/json"}
        )
    assert r.status_code == status and runner.calls == []


def test_body_too_large(api):
    client, _, runner = api(max_body_bytes=1024)
    big = payload("alertmanager_firing")
    big["alerts"][0]["annotations"]["description"] = "x" * 5000
    with client:
        r = client.post("/webhooks/alertmanager", json=big)
    assert r.status_code == 413 and runner.calls == []


def test_bearer_token(api):
    client, _, runner = api(webhook_token=SecretStr("s3cret"))
    with client:
        assert (
            client.post("/webhooks/alertmanager", json=payload("alertmanager_firing")).status_code
            == 401
        )
        bad = client.post(
            "/webhooks/alertmanager",
            json=payload("alertmanager_firing"),
            headers={"Authorization": "Bearer nope"},
        )
        ok = client.post(
            "/webhooks/alertmanager",
            json=payload("alertmanager_firing"),
            headers={"Authorization": "Bearer s3cret"},
        )
        assert client.get("/investigations/x").status_code == 401
    assert bad.status_code == 401 and ok.status_code == 202 and len(runner.calls) == 2


def test_pagerduty_signature(api):
    client, _, runner = api(pagerduty_signing_secret=SecretStr("pd-secret"))
    body = json.dumps(payload("pagerduty_v3_triggered")).encode()
    sig = "v1=" + hmac.new(b"pd-secret", body, hashlib.sha256).hexdigest()
    headers = {"content-type": "application/json"}
    with client:
        unsigned = client.post("/webhooks/pagerduty", content=body, headers=headers)
        wrong = client.post(
            "/webhooks/pagerduty",
            content=body,
            headers={**headers, "X-PagerDuty-Signature": "v1=deadbeef"},
        )
        rotated = client.post(
            "/webhooks/pagerduty",
            content=body,
            headers={**headers, "X-PagerDuty-Signature": f"v1=old, {sig}"},
        )
    assert unsigned.status_code == 401 and wrong.status_code == 401
    assert rotated.status_code == 202 and len(runner.calls) == 1


def test_get_investigation_404_and_running(api):
    client, _, _ = api()
    with client:
        assert client.get("/investigations/nope").status_code == 404
        r = client.post("/webhooks/alertmanager", json=payload("alertmanager_firing"))
        inv_id = r.json()["results"][0]["investigation_id"]
        got = client.get(f"/investigations/{inv_id}")  # stub runner never saves it
    assert got.status_code == 200 and got.json()["status"] == "running"
    assert client.get("/healthz").json() == {"ok": True}


def test_runner_crash_recorded_as_failed(api):
    def boom(alert, inv_id):
        raise RuntimeError("kaboom")

    client, store, _ = api(runner=boom)
    with client:
        r = client.post("/webhooks/pagerduty", json=payload("pagerduty_events_v2"))
    inv = store.get_investigation(r.json()["results"][0]["investigation_id"])
    assert inv.status == InvestigationStatus.FAILED and inv.error == "runner_error: RuntimeError"


def test_end_to_end_with_fixture_runner_and_fake_model(api):
    script = [
        msg(tool_use("list_deploys")),
        msg(
            tool_use(
                SUBMIT_TOOL_NAME,
                not_checked=["traces"],
                suggested_actions=[
                    {"description": "Roll back to v2.13.2", "rationale": "timing", "risk": "medium"}
                ],
                hypotheses=[
                    {
                        "title": "Deploy v2.14.0",
                        "explanation": "errors after deploy",
                        "confidence_score": 0.8,
                        "evidence": [{"tool_call_id": "call_001", "excerpt": "v2.14.0"}],
                    }
                ],
            )
        ),
    ]
    fake = FakeClient(script, parse_script=[parsed(None, stop="refusal")])  # template draft
    client, store, _ = api(client=fake)
    am = payload("alertmanager_firing")
    with client:  # exiting waits for background investigations
        r = client.post("/webhooks/alertmanager", json=am)
    checkout_id, billing_id = (x["investigation_id"] for x in r.json()["results"])

    inv = store.get_investigation(checkout_id)
    assert inv.status == InvestigationStatus.COMPLETED
    assert inv.hypotheses[0].title == "Deploy v2.14.0"
    types = [e.event_type for e in store.events(investigation_id=checkout_id)]
    assert types[0] == AuditEventType.ALERT_RECEIVED
    assert types[1] == AuditEventType.INVESTIGATION_STARTED
    assert types[-1] == AuditEventType.APPROVAL_REQUESTED
    assert store.verify_chain() == []

    other = store.get_investigation(billing_id)
    assert other.status == InvestigationStatus.FAILED and other.error == NO_DATA_SOURCE

    with client:
        detail = client.get(f"/investigations/{checkout_id}").json()
    assert detail["investigation"]["status"] == "completed"
    assert "raw" not in detail["investigation"]["alert"]
    assert detail["approvals"][0]["status"] == "pending"
