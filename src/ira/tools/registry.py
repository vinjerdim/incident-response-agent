"""Tool registry: validates arguments, enforces per-tool timeouts and output caps, assigns call
ids, and logs every call. This is the only path by which the agent invokes tools.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from pydantic import ValidationError

from ira.config import Settings, get_settings
from ira.fixtures import load_incident
from ira.redact import Redactor
from ira.tools.backends import Backend, FixtureBackend
from ira.tools.base import ReadOnlyTool, ToolContext, ToolResult, mutating_verbs_in
from ira.tools.deploys import GetDeployDiff, ListDeploys
from ira.tools.logs import SearchLogs
from ira.tools.metrics import ListMetrics, QueryMetrics
from ira.tools.runbooks import GetRunbook, SearchRunbooks

log = logging.getLogger("ira.tools")

ALL_TOOLS: tuple[type[ReadOnlyTool], ...] = (
    SearchLogs,
    ListMetrics,
    QueryMetrics,
    ListDeploys,
    GetDeployDiff,
    SearchRunbooks,
    GetRunbook,
)

DEFAULT_MAX_OUTPUT_CHARS = 8_000


class ToolRegistry:
    def __init__(
        self,
        tools: list[ReadOnlyTool],
        settings: Settings | None = None,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        redactor: Redactor | None = None,
    ):
        for t in tools:
            if not isinstance(t, ReadOnlyTool) or t.read_only is not True:
                raise TypeError(f"{t!r} is not a read-only tool")
            if bad := mutating_verbs_in(t.name):
                raise TypeError(f"tool {t.name!r} contains mutating verb(s) {sorted(bad)}")
        self._tools = {t.name: t for t in tools}
        self._settings = settings or get_settings()
        self._max_chars = max_output_chars
        self._redactor = redactor or Redactor()
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ira-tool")

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def specs(self) -> list[dict[str, Any]]:
        return [t.spec() for t in self._tools.values()]

    def _next_id(self) -> str:
        with self._id_lock:
            return f"call_{next(self._ids):03d}"

    def call(self, name: str, args: dict[str, Any] | None = None) -> ToolResult:
        call_id = self._next_id()
        args = dict(args or {})
        start = time.perf_counter()

        def result(ok: bool, content: str, data: Any = None, **kw: Any) -> ToolResult:
            # Redact BEFORE truncation and before anything leaves the registry.
            redacted = self._redactor.redact(content)
            counts = redacted.counts
            data = self._redactor.redact_obj(data)  # counts reflect model-visible text only
            content = redacted.text
            truncated = False
            if len(content) > self._max_chars:
                content = content[: self._max_chars] + "\n[... output truncated ...]"
                truncated = True
            r = ToolResult(
                tool_call_id=call_id,
                tool_name=name,
                args=args,
                ok=ok,
                content=content,
                data=data,
                truncated=truncated,
                redactions=dict(counts),
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                **kw,
            )
            log.info(
                "tool_call id=%s tool=%s ok=%s ms=%s truncated=%s redactions=%s error=%s args=%s",
                r.tool_call_id,
                r.tool_name,
                r.ok,
                r.duration_ms,
                r.truncated,
                r.redactions,
                r.error,
                args,
            )
            return r

        tool = self._tools.get(name)
        if tool is None:
            return result(False, f"Unknown tool {name!r}.", error="unknown_tool")
        try:
            parsed = tool.Input.model_validate(args)
        except ValidationError as e:
            msg = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
            return result(False, f"Invalid arguments: {msg}", error="invalid_arguments")

        future = self._pool.submit(tool.run, parsed)
        try:
            out = future.result(timeout=self._settings.tool_timeout_s)
        except FutureTimeout:
            future.cancel()  # best effort; a running thread cannot be killed
            return result(
                False,
                f"Tool timed out after {self._settings.tool_timeout_s}s.",
                error="timeout",
            )
        except Exception as e:
            return result(False, f"Tool failed: {type(e).__name__}", error=type(e).__name__)

        return result(True, out.content, data=out.data)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def build_registry(
    backend: Backend, ctx: ToolContext, settings: Settings | None = None
) -> ToolRegistry:
    return ToolRegistry([cls(backend, ctx) for cls in ALL_TOOLS], settings=settings)


def build_fixture_registry(name: str, settings: Settings | None = None) -> ToolRegistry:
    fixture = load_incident(name, (settings or get_settings()).fixtures_dir)
    return build_registry(
        FixtureBackend(fixture), ToolContext(fired_at=fixture.alert.fired_at), settings
    )
