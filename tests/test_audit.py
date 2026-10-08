import sqlite3

import pytest

from ira.audit import GENESIS, Store
from ira.models import AuditEvent, AuditEventType


def ev(inv="inv1", t=AuditEventType.TOOL_CALL, **payload):
    return AuditEvent(actor="agent", event_type=t, investigation_id=inv, payload=payload)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_append_and_query(store):
    store.append(ev(n=1))
    store.append(ev("inv2", AuditEventType.APPROVED, n=2))
    store.append(ev(n=3))
    assert [e.payload["n"] for e in store.events()] == [1, 2, 3]
    assert [e.payload["n"] for e in store.events(investigation_id="inv1")] == [1, 3]
    assert [e.payload["n"] for e in store.events(event_type=AuditEventType.APPROVED)] == [2]


def test_chain_links_and_verifies(store):
    h1 = store.append(ev(n=1))
    h2 = store.append(ev(n=2))
    assert h1 != h2 and len(h1) == 64
    rows = store._db.execute("SELECT prev_hash, hash FROM audit_events ORDER BY seq").fetchall()
    assert rows[0][0] == GENESIS and rows[1][0] == rows[0][1]
    assert store.verify_chain() == []


def test_update_and_delete_are_blocked(store):
    store.append(ev(n=1))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE audit_events SET actor = 'mallory'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM audit_events")


def test_tampering_detected_even_if_triggers_dropped(store):
    for n in range(3):
        store.append(ev(n=n))
    store._db.executescript("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")
    store._db.execute(
        "UPDATE audit_events SET event_json = replace(event_json, '\"n\":1', '\"n\":9') "
        "WHERE seq = 2"
    )
    assert any("hash mismatch" in p for p in store.verify_chain())


def test_deleted_middle_row_detected(store):
    for n in range(3):
        store.append(ev(n=n))
    store._db.execute("DROP TRIGGER audit_no_delete")
    store._db.execute("DELETE FROM audit_events WHERE seq = 2")
    assert any("prev_hash" in p for p in store.verify_chain())


def test_persists_across_connections(tmp_path):
    path = tmp_path / "ira.sqlite"
    s = Store(path)
    s.append(ev(n=1))
    s.close()
    s2 = Store(path)
    assert len(s2.events()) == 1 and s2.verify_chain() == []
    s2.close()
