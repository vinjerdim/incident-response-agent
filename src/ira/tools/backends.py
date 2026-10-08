"""Backend protocols. Real integrations (Loki, Prometheus, deploy API, wiki) implement the same
protocols. Protocols expose READ methods only; tests assert no mutating method names exist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ira.fixtures import Deploy, IncidentFixture, LogLine, MetricSeries, Runbook

LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "FATAL")


@runtime_checkable
class LogsBackend(Protocol):
    def search_logs(
        self,
        *,
        service: str | None,
        query: str | None,
        min_level: str | None,
        since: datetime,
        until: datetime,
    ) -> list[LogLine]: ...


@runtime_checkable
class MetricsBackend(Protocol):
    def list_metrics(self, *, service: str | None) -> list[MetricSeries]: ...

    def get_series(
        self, *, name: str, service: str | None, since: datetime, until: datetime
    ) -> MetricSeries | None: ...


@runtime_checkable
class DeploysBackend(Protocol):
    def list_deploys(
        self, *, service: str | None, since: datetime, until: datetime
    ) -> list[Deploy]: ...

    def get_deploy(self, *, deploy_id: str) -> Deploy | None: ...


@runtime_checkable
class RunbooksBackend(Protocol):
    def search_runbooks(self, *, query: str | None) -> list[Runbook]: ...

    def get_runbook(self, *, slug: str) -> Runbook | None: ...


@runtime_checkable
class Backend(LogsBackend, MetricsBackend, DeploysBackend, RunbooksBackend, Protocol):
    pass


class FixtureBackend:
    """Serves one incident fixture. Deliberately does NOT keep the ground truth."""

    def __init__(self, fixture: IncidentFixture):
        self._logs = sorted(fixture.logs, key=lambda x: x.ts)
        self._metrics = fixture.metrics
        self._deploys = sorted(fixture.deploys, key=lambda x: x.ts)
        self._runbooks = fixture.runbooks

    def search_logs(self, *, service, query, min_level, since, until) -> list[LogLine]:
        floor = LEVELS.index(min_level) if min_level else 0
        q = query.lower() if query else None
        return [
            line
            for line in self._logs
            if since <= line.ts <= until
            and (service is None or line.service == service)
            and LEVELS.index(line.level) >= floor
            and (q is None or q in line.message.lower())
        ]

    def list_metrics(self, *, service) -> list[MetricSeries]:
        return [m for m in self._metrics if service is None or m.service == service]

    def get_series(self, *, name, service, since, until) -> MetricSeries | None:
        for m in self._metrics:
            if m.name == name and (service is None or m.service == service):
                pts = [p for p in m.points if since <= p.ts <= until]
                return m.model_copy(update={"points": pts})
        return None

    def list_deploys(self, *, service, since, until) -> list[Deploy]:
        return [
            d
            for d in self._deploys
            if since <= d.ts <= until and (service is None or d.service == service)
        ]

    def get_deploy(self, *, deploy_id) -> Deploy | None:
        return next((d for d in self._deploys if d.id == deploy_id), None)

    def search_runbooks(self, *, query) -> list[Runbook]:
        if not query:
            return list(self._runbooks)
        terms = [t for t in query.lower().split() if t]
        scored = [
            (sum(t in (r.title + " " + r.body).lower() for t in terms), r) for r in self._runbooks
        ]
        return [r for score, r in sorted(scored, key=lambda x: -x[0]) if score > 0]

    def get_runbook(self, *, slug) -> Runbook | None:
        return next((r for r in self._runbooks if r.slug == slug), None)
