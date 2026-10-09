import threading
from datetime import UTC, datetime

import pytest

from ira.audit import Store
from ira.dedupe import Deduper
from ira.models import Alert, AlertSource, AuditEventType, Severity
from ira.normalize import NormalizedAlert


def firing(key="k1"):
    alert = Alert(
        source=AlertSource.MANUAL,
        service="svc",
        title="t",
        severity=Severity.LOW,
        fired_at=datetime(2026, 1, 1, tzinfo=UTC),
        dedupe_key=key,
    )
    return NormalizedAlert("firing", key, alert)


@pytest.fixture
def dd(settings):
    store = Store(":memory:")
    yield Deduper(store, settings.model_copy(update={"dedupe_window_s": 600})), store
    store.close()


def test_repeat_within_window_is_deduped(dd):
    d, store = dd
    first = d.claim(firing(), now=1000)
    second = d.claim(firing(), now=1300)
    assert first.is_new and not second.is_new
    assert second.investigation_id == first.investigation_id and second.count == 2
    ev = store.events(event_type=AuditEventType.ALERT_DEDUPED)
    assert len(ev) == 1 and ev[0].investigation_id == first.investigation_id
    assert ev[0].payload["count"] == 2


def test_after_window_starts_new(dd):
    d, _ = dd
    first = d.claim(firing(), now=1000)
    later = d.claim(firing(), now=1000 + 601)
    assert later.is_new and later.investigation_id != first.investigation_id


def test_different_keys_independent(dd):
    d, _ = dd
    assert d.claim(firing("a"), now=1).is_new and d.claim(firing("b"), now=1).is_new


def test_resolve_then_refire_starts_new(dd):
    d, store = dd
    first = d.claim(firing(), now=1000)
    assert d.resolve("k1") == first.investigation_id
    assert store.events(event_type=AuditEventType.ALERT_RESOLVED)[0].investigation_id == (
        first.investigation_id
    )
    again = d.claim(firing(), now=1010)
    assert again.is_new and again.investigation_id != first.investigation_id
    assert d.resolve("unknown") is None


def test_concurrent_claims_start_exactly_one(dd):
    d, _ = dd
    results, barrier = [], threading.Barrier(20)

    def worker():
        barrier.wait()
        results.append(d.claim(firing(), now=5000))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r.is_new for r in results) == 1
    assert len({r.investigation_id for r in results}) == 1
    assert max(r.count for r in results) == 20
