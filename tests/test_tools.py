import pytest

from ira.fixtures import load_incident
from ira.tools.registry import build_fixture_registry


@pytest.fixture
def reg(settings, request):
    r = build_fixture_registry(request.param, settings)
    yield r
    r.close()


def by_name(reg_, tool, **args):
    res = reg_.call(tool, args)
    assert res.ok, res.content
    return res


@pytest.mark.parametrize("reg", ["bad_deploy"], indirect=True)
def test_bad_deploy_tools(reg):
    deploys = by_name(reg, "list_deploys")
    assert "v2.14.0" in deploys.content
    assert "-8 min vs alert" in deploys.content
    diff = by_name(reg, "get_deploy_diff", deploy_id="d-1042")
    assert 'cart["promo_code"]' in diff.content
    errors = by_name(reg, "search_logs", min_level="ERROR", limit=5)
    assert "KeyError: 'promo_code'" in errors.content
    assert errors.data["total"] > 5 and len(errors.data["lines"]) == 5
    m = by_name(reg, "query_metrics", name="http_5xx_rate")
    step = m.data["summary"]["largest_step"]
    assert step["to"] > 10 and step["at"].startswith("2026-09-14T14:25")


@pytest.mark.parametrize("reg", ["noisy_false_alarm"], indirect=True)
def test_metrics_reports_scrape_gap_and_spike(reg):
    m = by_name(reg, "query_metrics", name="p99_latency_ms")
    s = m.data["summary"]
    assert s["max"] > 2000
    assert s["recent_mean_last5"] < 200
    assert s["gaps_after"] == ["2026-09-19T11:17:00Z"]
    assert "scrape gaps" in m.content


@pytest.mark.parametrize("reg", ["config_change"], indirect=True)
def test_config_changes_listed_as_deploys(reg):
    out = by_name(reg, "list_deploys")
    assert "kind=config" in out.content and "c-311" in out.content
    diff = by_name(reg, "get_deploy_diff", deploy_id="c-311")
    assert "rate_limit_per_min: 10" in diff.content


@pytest.mark.parametrize("reg", ["memory_leak"], indirect=True)
def test_runbooks_and_metrics_listing(reg):
    listing = by_name(reg, "list_metrics")
    assert "container_memory_mb" in listing.content
    found = by_name(reg, "search_runbooks", query="OOMKilled memory")
    assert "oom-kills" in found.content
    book = by_name(reg, "get_runbook", slug="oom-kills")
    assert "sawtooth" in book.content


@pytest.mark.parametrize("reg", ["upstream_outage"], indirect=True)
def test_log_filters(reg):
    out = by_name(reg, "search_logs", query="FASTCARRIER", min_level="ERROR")
    assert all("fastcarrier" in line["message"].lower() for line in out.data["lines"])
    assert all(line["level"] in ("ERROR", "FATAL") for line in out.data["lines"])
    none = by_name(reg, "search_logs", service="nonexistent")
    assert none.data["total"] == 0


@pytest.mark.parametrize("reg", ["bad_deploy"], indirect=True)
def test_explicit_window(reg):
    out = by_name(
        reg,
        "search_logs",
        min_level="ERROR",
        since="2026-09-14T13:00:00Z",
        until="2026-09-14T14:20:00Z",
    )
    assert out.data["total"] == 0


@pytest.mark.parametrize("reg", ["bad_deploy"], indirect=True)
def test_not_found_is_ok_with_message(reg):
    assert "No deploy" in by_name(reg, "get_deploy_diff", deploy_id="nope").content
    assert "No metric series" in by_name(reg, "query_metrics", name="nope").content
    assert "No runbook" in by_name(reg, "get_runbook", slug="nope").content


@pytest.mark.parametrize("name", ["bad_deploy", "expired_cert", "traffic_spike"])
def test_ground_truth_never_reachable_via_tools(settings, name):
    truth = load_incident(name, settings.fixtures_dir).ground_truth
    reg = build_fixture_registry(name, settings)
    outputs = [
        reg.call("search_logs", {"limit": 200}).content,
        reg.call("list_deploys", {}).content,
        reg.call("search_runbooks", {}).content,
    ]
    reg.close()
    assert not any(truth.root_cause in o for o in outputs)
    assert not any(truth.root_cause_id in o for o in outputs)
