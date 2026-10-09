"""Scripted stand-in for the Anthropic client (tests and offline evals). Returns real Messages."""

from __future__ import annotations

import copy
import itertools
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from anthropic.types import Message

_ids = itertools.count(1)


def tool_use(tool_name: str, /, **input: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": f"toolu_{next(_ids):04d}", "name": tool_name, "input": input}


def text(t: str) -> dict[str, Any]:
    return {"type": "text", "text": t}


def msg(*blocks: dict[str, Any], stop: str | None = None, inp: int = 100, out: int = 50) -> Message:
    if stop is None:
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
    return Message.model_validate(
        {
            "id": f"msg_{next(_ids):04d}",
            "type": "message",
            "role": "assistant",
            "model": "fake-model",
            "content": list(blocks),
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": inp, "output_tokens": out},
        }
    )


Step = Message | Callable[[dict[str, Any]], Message] | Exception


def parsed(output: Any | None, stop: str = "end_turn", inp: int = 80, out: int = 40) -> Any:
    """Stand-in for a ParsedMessage returned by `messages.parse`."""
    return SimpleNamespace(
        parsed_output=output,
        stop_reason=stop,
        content=[{"type": "text", "text": "{}"}],
        usage=SimpleNamespace(input_tokens=inp, output_tokens=out),
    )


class FakeClient:
    def __init__(self, script: list[Step], parse_script: list[Any] | None = None):
        self.script = list(script)
        self.parse_script = list(parse_script or [])
        self.calls: list[dict[str, Any]] = []
        self.parse_calls: list[dict[str, Any]] = []
        self.messages = SimpleNamespace(create=self._create, parse=self._parse)
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Message:
        self.calls.append(copy.deepcopy(kwargs))
        if not self.script:
            raise AssertionError("FakeClient script exhausted")
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step(kwargs) if callable(step) else step

    def _parse(self, **kwargs: Any) -> Any:
        self.parse_calls.append(copy.deepcopy(kwargs))
        if not self.parse_script:
            raise AssertionError("FakeClient parse script exhausted")
        step = self.parse_script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def last_user_content(kwargs: dict[str, Any]) -> Any:
    return kwargs["messages"][-1]["content"]
