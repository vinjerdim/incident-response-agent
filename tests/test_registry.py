import inspect
import time

import pytest

from ira.tools import backends
from ira.tools.base import MUTATING_VERBS, ReadOnlyTool, ToolContext, ToolInput, ToolOutput
from ira.tools.registry import ALL_TOOLS, ToolRegistry, build_fixture_registry


@pytest.fixture
def reg(settings):
    r = build_fixture_registry("bad_deploy", settings)
    yield r
    r.close()


def test_specs_are_anthropic_shaped(reg):
    specs = reg.specs()
    assert {s["name"] for s in specs} == {t.name for t in ALL_TOOLS}
    for s in specs:
        assert s["description"] and s["input_schema"]["type"] == "object"


def test_call_ids_are_sequential_and_unique(reg):
    ids = [reg.call("list_metrics", {}).tool_call_id for _ in range(3)]
    assert ids == ["call_001", "call_002", "call_003"]


def test_unknown_tool(reg):
    r = reg.call("restart_service", {})
    assert not r.ok and r.error == "unknown_tool"


def test_invalid_arguments(reg):
    r = reg.call("search_logs", {"limit": 10_000, "bogus": 1})
    assert not r.ok and r.error == "invalid_arguments"
    assert "limit" in r.content and "bogus" in r.content


def test_output_truncated(settings):
    reg = build_fixture_registry("bad_deploy", settings)
    reg._max_chars = 200
    r = reg.call("search_logs", {"limit": 200})
    reg.close()
    assert r.ok and r.truncated and r.content.endswith("[... output truncated ...]")


class _SlowInput(ToolInput):
    pass


class _SlowTool(ReadOnlyTool):
    name = "slow_probe"
    description = "test"
    Input = _SlowInput

    def run(self, args):
        time.sleep(1.0)
        return ToolOutput("late")


class _BoomTool(ReadOnlyTool):
    name = "boom_probe"
    description = "test"
    Input = _SlowInput

    def run(self, args):
        raise RuntimeError("secret internal detail")


def _ctx():
    from datetime import UTC, datetime

    return ToolContext(fired_at=datetime(2026, 1, 1, tzinfo=UTC))


def test_timeout(settings):
    s = settings.model_copy(update={"tool_timeout_s": 0.1})
    reg = ToolRegistry([_SlowTool(None, _ctx())], settings=s)
    r = reg.call("slow_probe")
    reg.close()
    assert not r.ok and r.error == "timeout"


def test_exception_is_contained_without_leaking_message(settings):
    reg = ToolRegistry([_BoomTool(None, _ctx())], settings=settings)
    r = reg.call("boom_probe")
    reg.close()
    assert not r.ok and r.error == "RuntimeError"
    assert "secret internal detail" not in r.content


# --- read-only guards --------------------------------------------------------


@pytest.mark.parametrize(
    "bad_name", ["restart_service", "rollback_deploy", "scale_up", "edit_config"]
)
def test_mutating_tool_names_rejected_at_class_creation(bad_name):
    with pytest.raises(TypeError, match="mutating"):
        type(
            "Bad",
            (ReadOnlyTool,),
            {
                "name": bad_name,
                "description": "",
                "Input": _SlowInput,
                "run": lambda self, a: ToolOutput(""),
            },
        )


def test_tool_cannot_opt_out_of_read_only():
    with pytest.raises(TypeError, match="read-only"):
        type(
            "Sneaky",
            (ReadOnlyTool,),
            {
                "name": "peek",
                "description": "",
                "Input": _SlowInput,
                "read_only": False,
                "run": lambda self, a: ToolOutput(""),
            },
        )


def test_registry_rejects_non_tools(settings):
    with pytest.raises(TypeError):
        ToolRegistry([object()], settings=settings)


def test_all_registered_tools_are_read_only():
    for t in ALL_TOOLS:
        assert t.read_only is True
        assert "read-only" in t.description.lower()
        assert not (set(t.name.split("_")) & MUTATING_VERBS)


def test_backend_protocols_expose_no_mutating_methods():
    for proto in (
        backends.LogsBackend,
        backends.MetricsBackend,
        backends.DeploysBackend,
        backends.RunbooksBackend,
        backends.FixtureBackend,
    ):
        methods = [
            n for n, _ in inspect.getmembers(proto, inspect.isfunction) if not n.startswith("_")
        ]
        assert methods
        for m in methods:
            assert m.split("_")[0] in {"search", "list", "get"}, (proto, m)


def test_fixture_backend_satisfies_protocol(settings):
    from ira.fixtures import load_incident

    assert isinstance(
        backends.FixtureBackend(load_incident("bad_deploy", settings.fixtures_dir)),
        backends.Backend,
    )
