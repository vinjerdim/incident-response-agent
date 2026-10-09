"""Alert webhook: normalize PagerDuty/Alertmanager payloads, dedupe, start investigations.

Investigations run in a bounded background pool; webhooks return 202 immediately. There is
deliberately no approve/execute endpoint: approvals are CLI-only for now.

Run: `make serve` (uvicorn --factory ira.api:create_app).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from ira.approvals import Approvals
from ira.audit import Store
from ira.config import Settings, get_settings
from ira.dedupe import SYSTEM_ACTOR, Deduper
from ira.fixtures import list_incidents, load_incident
from ira.models import Alert, AuditEvent, AuditEventType, Investigation, InvestigationStatus
from ira.normalize import NormalizationError, NormalizedAlert, from_alertmanager, from_pagerduty
from ira.pipeline import run_investigation
from ira.tools.registry import build_fixture_registry

log = logging.getLogger("ira.api")

Runner = Callable[[Alert, str], None]
NO_DATA_SOURCE = "no_data_source_for_service"


def _fail(store: Store, alert: Alert, inv_id: str, error: str) -> None:
    store.save_investigation(
        Investigation(
            id=inv_id,
            alert=alert,
            status=InvestigationStatus.FAILED,
            error=error,
            not_checked=["Nothing was checked: the investigation did not run."],
            finished_at=datetime.now(UTC),
        )
    )
    store.append(
        AuditEvent(
            actor=SYSTEM_ACTOR,
            event_type=AuditEventType.INVESTIGATION_FINISHED,
            investigation_id=inv_id,
            payload={"status": InvestigationStatus.FAILED, "error": error},
        )
    )


def fixture_runner(store: Store, client: Any | None, settings: Settings) -> Runner:
    """Fixture mode: pick the incident fixture whose alert service matches."""
    index = {
        load_incident(n, settings.fixtures_dir).alert.service: n
        for n in list_incidents(settings.fixtures_dir)
    }

    def run(alert: Alert, inv_id: str) -> None:
        name = index.get(alert.service)
        if name is None:
            _fail(store, alert, inv_id, NO_DATA_SOURCE)
            return
        registry = build_fixture_registry(name, settings)
        try:
            run_investigation(
                alert, registry, store, client=client, settings=settings, investigation_id=inv_id
            )
        finally:
            registry.close()

    return run


def create_app(
    store: Store | None = None,
    client: Any | None = None,
    settings: Settings | None = None,
    runner: Runner | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    store = store or Store(settings.db_path)
    runner = runner or fixture_runner(store, client, settings)
    deduper = Deduper(store, settings)
    executor = ThreadPoolExecutor(settings.webhook_workers, thread_name_prefix="ira-inv")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        executor.shutdown(wait=True)

    app = FastAPI(title="Incident Response Assistant", lifespan=lifespan)
    app.state.store = store
    app.state.executor = executor

    def safe_run(alert: Alert, inv_id: str) -> None:
        try:
            runner(alert, inv_id)
        except Exception as e:
            log.exception("investigation %s crashed", inv_id)
            _fail(store, alert, inv_id, f"runner_error: {type(e).__name__}")

    async def read_json(request: Request) -> tuple[bytes, Any]:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_body_bytes:
            raise HTTPException(413, "payload too large")
        body = await request.body()
        if len(body) > settings.max_body_bytes:
            raise HTTPException(413, "payload too large")
        try:
            return body, json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise HTTPException(400, "body is not valid JSON") from e

    def check_bearer(request: Request) -> None:
        if settings.webhook_token is None:
            return
        expected = f"Bearer {settings.webhook_token.get_secret_value()}"
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            raise HTTPException(401, "invalid or missing bearer token")

    def check_pd_signature(request: Request, body: bytes) -> None:
        if settings.pagerduty_signing_secret is None:
            return
        secret = settings.pagerduty_signing_secret.get_secret_value().encode()
        expected = "v1=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        provided = request.headers.get("x-pagerduty-signature", "").split(",")
        if not any(hmac.compare_digest(sig.strip(), expected) for sig in provided):
            raise HTTPException(401, "invalid PagerDuty signature")

    def handle(normalized: list[NormalizedAlert]) -> list[dict[str, Any]]:
        results = []
        for n in normalized:
            result: dict[str, Any] = {"dedupe_key": n.dedupe_key, "investigation_id": None}
            if n.state == "firing" and n.alert is not None:
                claim = deduper.claim(n)
                result["investigation_id"] = claim.investigation_id
                if claim.is_new:
                    store.append(
                        AuditEvent(
                            actor=SYSTEM_ACTOR,
                            event_type=AuditEventType.ALERT_RECEIVED,
                            investigation_id=claim.investigation_id,
                            payload={
                                "source": n.alert.source,
                                "service": n.alert.service,
                                "title": n.alert.title,
                                "severity": n.alert.severity,
                                "dedupe_key": n.dedupe_key,
                            },
                        )
                    )
                    executor.submit(safe_run, n.alert, claim.investigation_id)
                    result["outcome"] = "started"
                else:
                    result["outcome"] = "deduplicated"
                    result["count"] = claim.count
            elif n.state == "resolved":
                result["investigation_id"] = deduper.resolve(n.dedupe_key)
                result["outcome"] = "resolved"
            else:
                result["outcome"] = "ignored"
            results.append(result)
        return results

    async def accept(normalize: Callable[[Any], list[NormalizedAlert]], payload: Any):
        try:
            normalized = normalize(payload)
        except NormalizationError as e:
            raise HTTPException(422, str(e)) from e
        results = await run_in_threadpool(handle, normalized)
        return JSONResponse(status_code=202, content={"results": results})

    @app.post("/webhooks/alertmanager", status_code=202)
    async def alertmanager(request: Request):
        check_bearer(request)
        _, payload = await read_json(request)
        return await accept(from_alertmanager, payload)

    @app.post("/webhooks/pagerduty", status_code=202)
    async def pagerduty(request: Request):
        body, payload = await read_json(request)
        check_pd_signature(request, body)
        return await accept(from_pagerduty, payload)

    @app.get("/investigations/{investigation_id}")
    def get_investigation(investigation_id: str, request: Request):
        check_bearer(request)
        inv = store.get_investigation(investigation_id)
        if inv is None:
            if store.events(investigation_id=investigation_id):
                return {"investigation_id": investigation_id, "status": "running"}
            raise HTTPException(404, "investigation not found")
        draft = store.latest_draft(investigation_id)
        approvals = [
            {
                "action_id": s.action.id,
                "description": s.action.description,
                "risk": s.action.risk,
                "status": s.status,
                "decided_by": s.decided_by,
            }
            for s in Approvals(store).list(investigation_id)
        ]
        return {
            "investigation": inv.model_dump(mode="json", exclude={"alert": {"raw"}}),
            "draft": draft.model_dump(mode="json") if draft else None,
            "approvals": approvals,
        }

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
