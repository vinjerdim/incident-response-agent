"""Normalize Alertmanager and PagerDuty webhook payloads into `Alert`s.

All payload text is untrusted: it is length-capped and stripped of control characters here,
then delimited as untrusted data when it reaches the model (prompts.wrap_alert).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ira.models import Alert, AlertSource, Severity

MAX_TITLE = 300
MAX_DESCRIPTION = 4_000
MAX_LABELS = 50
MAX_LABEL_VALUE = 200
MAX_ALERTS_PER_PAYLOAD = 100

AlertState = Literal["firing", "resolved", "ignored"]


class NormalizationError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedAlert:
    state: AlertState
    dedupe_key: str
    alert: Alert | None = None  # None for resolved/ignored events that carry no alert body


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "page": Severity.CRITICAL,
    "p1": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "p2": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "p3": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "p4": Severity.LOW,
    "info": Severity.INFO,
    "p5": Severity.INFO,
    "none": Severity.INFO,
}


def map_severity(value: str | None) -> Severity:
    return SEVERITY_MAP.get((value or "").strip().lower(), Severity.MEDIUM)


def clean(text: Any, limit: int) -> str:
    s = _CTRL.sub("", str(text if text is not None else "")).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def clean_labels(labels: dict[str, Any]) -> dict[str, str]:
    items = list(labels.items())[:MAX_LABELS]
    return {clean(k, 100): clean(v, MAX_LABEL_VALUE) for k, v in items if clean(k, 100)}


def _hash_key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _when(*candidates: datetime | None) -> datetime:
    for c in candidates:
        if c is not None and c.year >= 2000:
            return c if c.tzinfo else c.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _validate(model: type[BaseModel], payload: Any) -> Any:
    try:
        return model.model_validate(payload)
    except ValidationError as e:
        first = e.errors()[0]
        loc = ".".join(map(str, first["loc"]))
        raise NormalizationError(f"invalid {model.__name__}: {loc}: {first['msg']}") from e


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


# --- Alertmanager (webhook v4) ---------------------------------------------------------------


class AMAlert(_Lenient):
    status: Literal["firing", "resolved"]
    labels: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    startsAt: datetime | None = None
    fingerprint: str | None = None


class AMPayload(_Lenient):
    version: str | None = None
    alerts: list[AMAlert] = Field(min_length=1, max_length=MAX_ALERTS_PER_PAYLOAD)


def from_alertmanager(payload: Any) -> list[NormalizedAlert]:
    p: AMPayload = _validate(AMPayload, payload)
    out = []
    for a in p.alerts:
        labels = clean_labels(a.labels)
        service = labels.get("service") or labels.get("app") or labels.get("job") or "unknown"
        alertname = labels.get("alertname", "")
        key = clean(a.fingerprint, 128) or _hash_key("alertmanager", alertname, service)
        if a.status == "resolved":
            out.append(NormalizedAlert("resolved", key))
            continue
        title = clean(a.annotations.get("summary") or alertname or "Alertmanager alert", MAX_TITLE)
        alert = Alert(
            source=AlertSource.ALERTMANAGER,
            service=service,
            title=title,
            description=clean(a.annotations.get("description", ""), MAX_DESCRIPTION),
            severity=map_severity(labels.get("severity")),
            fired_at=_when(a.startsAt),
            labels=labels,
            dedupe_key=key,
            raw=a.model_dump(mode="json"),
        )
        out.append(NormalizedAlert("firing", key, alert))
    return out


# --- PagerDuty ---------------------------------------------------------------------------


class PDService(_Lenient):
    id: str | None = None
    summary: str | None = None


class PDPriority(_Lenient):
    summary: str | None = None


class PDIncident(_Lenient):
    id: str
    title: str | None = None
    urgency: str | None = None
    incident_key: str | None = None
    created_at: datetime | None = None
    service: PDService | None = None
    priority: PDPriority | None = None


class PDEvent(_Lenient):
    id: str | None = None
    event_type: str
    occurred_at: datetime | None = None
    data: PDIncident


class PDV3(_Lenient):
    event: PDEvent


class PDEv2Payload(_Lenient):
    summary: str
    source: str
    severity: str
    timestamp: datetime | None = None
    component: str | None = None
    group: str | None = None
    class_: str | None = Field(default=None, alias="class")
    custom_details: Any = None


class PDEv2(_Lenient):
    event_action: Literal["trigger", "acknowledge", "resolve"]
    dedup_key: str | None = None
    payload: PDEv2Payload | None = None


def _from_pd_v3(payload: Any) -> list[NormalizedAlert]:
    ev: PDEvent = _validate(PDV3, payload).event
    inc = ev.data
    key = clean(inc.incident_key or inc.id, 128)
    if ev.event_type == "incident.resolved":
        return [NormalizedAlert("resolved", key)]
    if ev.event_type != "incident.triggered":
        return [NormalizedAlert("ignored", key)]
    service = clean((inc.service and inc.service.summary) or "unknown", 100)
    prio = inc.priority.summary if inc.priority else None
    severity = (
        map_severity(prio) if prio else (Severity.HIGH if inc.urgency == "high" else Severity.LOW)
    )
    alert = Alert(
        source=AlertSource.PAGERDUTY,
        service=service,
        title=clean(inc.title or "PagerDuty incident", MAX_TITLE),
        severity=severity,
        fired_at=_when(inc.created_at, ev.occurred_at),
        labels=clean_labels({"pd_incident_id": inc.id, "pd_urgency": inc.urgency or ""}),
        dedupe_key=key,
        raw=payload if isinstance(payload, dict) else {},
    )
    return [NormalizedAlert("firing", key, alert)]


def _from_pd_events_v2(payload: Any) -> list[NormalizedAlert]:
    p: PDEv2 = _validate(PDEv2, payload)
    body = p.payload
    if p.event_action == "trigger" and body is None:
        raise NormalizationError("invalid PDEv2: payload: required for trigger")
    service = clean((body.component or body.source) if body else "unknown", 100)
    key = clean(p.dedup_key, 128) or _hash_key("pagerduty", body.summary if body else "", service)
    if p.event_action == "resolve":
        return [NormalizedAlert("resolved", key)]
    if p.event_action != "trigger" or body is None:
        return [NormalizedAlert("ignored", key)]
    labels = {
        "source": body.source,
        "component": body.component,
        "group": body.group,
        "class": body.class_,
    }
    alert = Alert(
        source=AlertSource.PAGERDUTY,
        service=service,
        title=clean(body.summary, MAX_TITLE),
        description=clean(body.custom_details or "", MAX_DESCRIPTION),
        severity=map_severity(body.severity),
        fired_at=_when(body.timestamp),
        labels=clean_labels({k: v for k, v in labels.items() if v}),
        dedupe_key=key,
        raw=payload if isinstance(payload, dict) else {},
    )
    return [NormalizedAlert("firing", key, alert)]


def from_pagerduty(payload: Any) -> list[NormalizedAlert]:
    """Accepts PagerDuty v3 webhooks ({"event": ...}) and Events API v2 ({"event_action": ...})."""
    if isinstance(payload, dict) and "event" in payload:
        return _from_pd_v3(payload)
    if isinstance(payload, dict) and "event_action" in payload:
        return _from_pd_events_v2(payload)
    raise NormalizationError("unrecognized PagerDuty payload (expected v3 webhook or Events v2)")
