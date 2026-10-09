"""Alert deduplication policy: one open investigation per dedupe key within a time window."""

from __future__ import annotations

import time
import uuid

from ira.audit import Claim, Store
from ira.config import Settings, get_settings
from ira.models import AuditEvent, AuditEventType
from ira.normalize import NormalizedAlert

SYSTEM_ACTOR = "system"


class Deduper:
    def __init__(self, store: Store, settings: Settings | None = None):
        self.store = store
        self.window_s = (settings or get_settings()).dedupe_window_s

    def claim(self, n: NormalizedAlert, now: float | None = None) -> Claim:
        """Return a Claim; `is_new` means the caller should start an investigation."""
        claim = self.store.claim_alert(
            n.dedupe_key, time.time() if now is None else now, self.window_s, uuid.uuid4().hex
        )
        if not claim.is_new:
            self.store.append(
                AuditEvent(
                    actor=SYSTEM_ACTOR,
                    event_type=AuditEventType.ALERT_DEDUPED,
                    investigation_id=claim.investigation_id,
                    payload={
                        "dedupe_key": n.dedupe_key,
                        "count": claim.count,
                        "title": n.alert.title if n.alert else None,
                    },
                )
            )
        return claim

    def resolve(self, dedupe_key: str) -> str | None:
        inv_id = self.store.resolve_alert(dedupe_key)
        if inv_id is not None:
            self.store.append(
                AuditEvent(
                    actor=SYSTEM_ACTOR,
                    event_type=AuditEventType.ALERT_RESOLVED,
                    investigation_id=inv_id,
                    payload={"dedupe_key": dedupe_key},
                )
            )
        return inv_id
