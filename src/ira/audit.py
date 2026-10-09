"""Append-only, hash-chained audit log plus investigation/draft storage (SQLite).

- `audit_events` rejects UPDATE and DELETE via triggers.
- Each row stores `hash = sha256(prev_hash + canonical_event_json)`, so any edit or removal of
  a non-final row breaks the chain and is reported by `verify_chain()`. (Truncating the tail is
  only detectable by anchoring the head hash elsewhere, e.g. shipping it to a log sink.)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

from ira.models import AuditEvent, AuditEventType, Investigation, StatusDraft

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    event_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_inv ON audit_events(investigation_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_dedupe (
    dedupe_key TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL,
    open INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS drafts (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    json TEXT NOT NULL
);
"""


def canonical(event: AuditEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def chain_hash(prev_hash: str, event_json: str) -> str:
    return hashlib.sha256((prev_hash + event_json).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Claim:
    is_new: bool
    investigation_id: str
    count: int


class Store:
    def __init__(self, db_path: str | Path = ":memory:"):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- audit log ------------------------------------------------------------------------

    def append(self, event: AuditEvent) -> str:
        event_json = canonical(event)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = row[0] if row else GENESIS
                h = chain_hash(prev, event_json)
                self._db.execute(
                    "INSERT INTO audit_events (id, ts, actor, event_type, investigation_id, "
                    "event_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.id,
                        event.ts.isoformat(),
                        event.actor,
                        event.event_type,
                        event.investigation_id,
                        event_json,
                        prev,
                        h,
                    ),
                )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return h

    def events(
        self,
        investigation_id: str | None = None,
        event_type: AuditEventType | None = None,
    ) -> list[AuditEvent]:
        sql, args = "SELECT event_json FROM audit_events WHERE 1=1", []
        if investigation_id is not None:
            sql += " AND investigation_id = ?"
            args.append(investigation_id)
        if event_type is not None:
            sql += " AND event_type = ?"
            args.append(str(event_type))
        with self._lock:
            rows = self._db.execute(sql + " ORDER BY seq", args).fetchall()
        return [AuditEvent.model_validate_json(r[0]) for r in rows]

    def verify_chain(self) -> list[str]:
        """Recompute the whole chain. Returns a list of problems; empty means intact."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, event_json, prev_hash, hash FROM audit_events ORDER BY seq"
            ).fetchall()
        problems: list[str] = []
        expected_prev = GENESIS
        for seq, event_json, prev_hash, h in rows:
            if prev_hash != expected_prev:
                problems.append(f"seq {seq}: prev_hash does not link to previous event")
            if chain_hash(prev_hash, event_json) != h:
                problems.append(f"seq {seq}: hash mismatch (event modified)")
            expected_prev = h
        return problems

    # -- alert dedupe ---------------------------------------------------------------------

    def claim_alert(self, key: str, now: float, window_s: float, new_id: str) -> Claim:
        """Atomically decide whether an alert starts a new investigation or is a repeat."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT investigation_id, first_seen, count, open FROM alert_dedupe "
                    "WHERE dedupe_key = ?",
                    (key,),
                ).fetchone()
                if row and row[3] and now - row[1] < window_s:
                    self._db.execute(
                        "UPDATE alert_dedupe SET last_seen = ?, count = count + 1 "
                        "WHERE dedupe_key = ?",
                        (now, key),
                    )
                    claim = Claim(False, row[0], row[2] + 1)
                else:
                    self._db.execute(
                        "INSERT INTO alert_dedupe VALUES (?, ?, ?, ?, 1, 1) "
                        "ON CONFLICT(dedupe_key) DO UPDATE SET investigation_id = excluded."
                        "investigation_id, first_seen = excluded.first_seen, last_seen = "
                        "excluded.last_seen, count = 1, open = 1",
                        (key, new_id, now, now),
                    )
                    claim = Claim(True, new_id, 1)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return claim

    def resolve_alert(self, key: str) -> str | None:
        """Close an open dedupe entry. Returns its investigation id, or None if none open."""
        with self._lock:
            row = self._db.execute(
                "SELECT investigation_id FROM alert_dedupe WHERE dedupe_key = ? AND open = 1",
                (key,),
            ).fetchone()
            if row:
                self._db.execute("UPDATE alert_dedupe SET open = 0 WHERE dedupe_key = ?", (key,))
        return row[0] if row else None

    # -- investigations / drafts ----------------------------------------------------------

    def save_investigation(self, inv: Investigation) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigations (id, created_at, json) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET json = excluded.json",
                (inv.id, inv.started_at.isoformat(), inv.model_dump_json()),
            )

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        with self._lock:
            row = self._db.execute(
                "SELECT json FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
        return Investigation.model_validate_json(row[0]) if row else None

    def list_investigations(self) -> list[Investigation]:
        with self._lock:
            rows = self._db.execute(
                "SELECT json FROM investigations ORDER BY created_at DESC"
            ).fetchall()
        return [Investigation.model_validate_json(r[0]) for r in rows]

    def save_draft(self, draft: StatusDraft) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO drafts (id, investigation_id, created_at, json) VALUES (?, ?, ?, ?)",
                (
                    draft.id,
                    draft.investigation_id,
                    draft.created_at.isoformat(),
                    draft.model_dump_json(),
                ),
            )

    def latest_draft(self, investigation_id: str) -> StatusDraft | None:
        with self._lock:
            row = self._db.execute(
                "SELECT json FROM drafts WHERE investigation_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (investigation_id,),
            ).fetchone()
        return StatusDraft.model_validate_json(row[0]) if row else None
