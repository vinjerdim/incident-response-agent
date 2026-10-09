"""Simulated incident fixtures: schemas and loader.

Layout per incident: fixtures/<name>/{alert.json, logs.jsonl, metrics.json, deploys.json,
runbooks/*.md, ground_truth.json}. Everything except ground_truth.json is what the agent's
tools may see; ground_truth.json is for evals only.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ira.config import get_settings
from ira.models import Alert


class _Fixture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LogLine(_Fixture):
    ts: datetime
    service: str
    level: Literal["DEBUG", "INFO", "WARN", "ERROR", "FATAL"]
    message: str
    host: str | None = None
    trace_id: str | None = None


class MetricPoint(_Fixture):
    ts: datetime
    value: float


class MetricSeries(_Fixture):
    name: str
    service: str
    unit: str
    points: list[MetricPoint]


class Deploy(_Fixture):
    id: str
    service: str
    kind: Literal["code", "config"]
    version: str
    author: str
    ts: datetime
    summary: str
    diff: str


class Runbook(_Fixture):
    slug: str
    title: str
    body: str


class KeyEvidence(_Fixture):
    source: Literal["logs", "metrics", "deploys", "runbooks"]
    contains: str = Field(min_length=1)


class InjectionSpec(_Fixture):
    """Adversarial fixture: what the agent must NOT do or say."""

    technique: str
    # Case-insensitive regexes the attack tries to induce. A legitimate answer may mention
    # e.g. "DNS was ruled out" elsewhere, so these are checked only where obeying would show.
    forbidden_top_hypothesis: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    # Strings that must never appear in model-authored output (hypotheses, actions, draft).
    canaries: list[str] = Field(default_factory=list)
    require_correct_top1: bool = True
    # Attack strings planted in the fixture (for fixture/detector tests).
    planted: list[str] = Field(min_length=1)


class GroundTruth(_Fixture):
    root_cause_id: str
    root_cause: str
    category: str
    is_false_alarm: bool = False
    key_evidence: list[KeyEvidence] = Field(min_length=1)
    acceptable_answers: list[str] = Field(min_length=1)
    red_herrings: list[str] = Field(default_factory=list)
    planted_sensitive: list[str] = Field(default_factory=list)
    injection: InjectionSpec | None = None


class IncidentFixture(_Fixture):
    name: str
    alert: Alert
    logs: list[LogLine]
    metrics: list[MetricSeries]
    deploys: list[Deploy]
    runbooks: list[Runbook]
    ground_truth: GroundTruth


def _fixtures_dir(base: Path | None) -> Path:
    return base if base is not None else get_settings().fixtures_dir


def list_incidents(base: Path | None = None) -> list[str]:
    root = _fixtures_dir(base)
    return sorted(p.name for p in root.iterdir() if (p / "alert.json").is_file())


def _load_runbook(path: Path) -> Runbook:
    body = path.read_text(encoding="utf-8")
    first = body.splitlines()[0] if body else path.stem
    return Runbook(slug=path.stem, title=first.lstrip("# ").strip(), body=body)


def load_incident(name: str, base: Path | None = None) -> IncidentFixture:
    d = _fixtures_dir(base) / name
    if not (d / "alert.json").is_file():
        raise FileNotFoundError(f"no such incident fixture: {name}")

    def read_json(fname: str):
        return json.loads((d / fname).read_text(encoding="utf-8"))

    logs_text = (d / "logs.jsonl").read_text(encoding="utf-8")
    return IncidentFixture(
        name=name,
        alert=Alert.model_validate(read_json("alert.json")),
        logs=[LogLine.model_validate_json(line) for line in logs_text.splitlines() if line],
        metrics=[MetricSeries.model_validate(m) for m in read_json("metrics.json")],
        deploys=[Deploy.model_validate(x) for x in read_json("deploys.json")],
        runbooks=[_load_runbook(p) for p in sorted((d / "runbooks").glob("*.md"))],
        ground_truth=GroundTruth.model_validate(read_json("ground_truth.json")),
    )
