import pytest

from conftest import FIXTURES
from ira.fixtures import list_incidents, load_incident
from ira.redact import Redactor
from ira.tools.registry import build_fixture_registry

R = Redactor()
INCIDENTS = list_incidents(FIXTURES)


@pytest.mark.parametrize("name", INCIDENTS)
def test_all_planted_values_redacted(name):
    f = load_incident(name, FIXTURES)
    redacted = "\n".join(R.redact(line.message).text for line in f.logs)
    for value in f.ground_truth.planted_sensitive:
        assert value not in redacted, (name, value)


@pytest.mark.parametrize("name", INCIDENTS)
def test_key_evidence_survives_redaction(name):
    f = load_incident(name, FIXTURES)
    logs = "\n".join(R.redact(x.message).text for x in f.logs)
    deploys = "\n".join(R.redact(f"{d.version} {d.summary}\n{d.diff}").text for d in f.deploys)
    for ev in f.ground_truth.key_evidence:
        if ev.source == "logs":
            assert ev.contains in logs, (name, ev)
        elif ev.source == "deploys":
            assert ev.contains in deploys, (name, ev)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("postgres://app:hunter2@db:5432/x", "postgres://app:[REDACTED:password]@db:5432/x"),
        ("password=hunter2 user=bob", "password=[REDACTED:secret] user=bob"),
        ("Authorization: Bearer abc.def-123", "Authorization: Bearer [REDACTED:token]"),
        ("key AKIAIOSFODNN7EXAMPLE end", "key [REDACTED:aws_key] end"),
        ("api_key=fc_live_9f8e7d6c5b4a", "api_key=[REDACTED:api_key]"),
        ("mail bob@example.org now", "mail [REDACTED:email] now"),
        ("card 4111 1111 1111 1111.", "card [REDACTED:card]."),
        ("jwt eyJhbGciOi.eyJzdWIi.c2ln", "jwt [REDACTED:jwt]"),
        ("DB_PASSWORD=Canary-Pa55 ok", "DB_PASSWORD=[REDACTED:secret] ok"),
        ("AWS_SECRET_ACCESS_KEY=abc/123", "AWS_SECRET_ACCESS_KEY=[REDACTED:secret]"),
    ],
)
def test_rules(raw, expected):
    assert R.redact(raw).text == expected


@pytest.mark.parametrize(
    "safe",
    [
        "2026-09-14T14:32:00Z deploy v2.14.0 rollout complete (6/6 pods)",
        "order 4111111111111112 failed",  # fails Luhn
        "HikariPool-1 - request timed out after 30000ms",
        "rate_limiter.rate_limit_per_min=10 (source=config-service rev c-311)",
        "trace 9f8e7d6c5b4a3f21",
    ],
)
def test_no_false_positives(safe):
    r = R.redact(safe)
    assert r.text == safe and not r.counts


def test_counts_and_no_double_redaction():
    r = R.redact("s3_access_key=AKIAIOSFODNN7EXAMPLE password=x")
    assert r.text == "s3_access_key=[REDACTED:aws_key] password=[REDACTED:secret]"
    assert dict(r.counts) == {"aws_key": 1, "key_value": 1}


def test_redact_obj_nested():
    counts = __import__("collections").Counter()
    out = R.redact_obj({"a": ["x@example.com", 3], "b": {"c": "password=p"}}, counts)
    assert out == {"a": ["[REDACTED:email]", 3], "b": {"c": "password=[REDACTED:secret]"}}
    assert counts == {"email": 1, "key_value": 1}


def test_registry_redacts_content_and_data(settings):
    reg = build_fixture_registry("db_conn_exhaustion", settings)
    r = reg.call("search_logs", {"query": "postgres://"})
    reg.close()
    assert "S3cr3tPassw0rd!" not in r.content
    assert "S3cr3tPassw0rd!" not in str(r.data)
    assert "orders-db.internal" in r.content
    assert r.redactions.get("dsn_password", 0) >= 1
