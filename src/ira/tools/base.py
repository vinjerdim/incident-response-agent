"""Common interface for investigation tools. Every tool is READ-ONLY by construction:

- `ReadOnlyTool.read_only` is `Literal[True]` and checked at class creation
- tool names containing mutating verbs are rejected at class creation
- tools only receive backends whose protocols expose read methods (see backends.py)
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, ClassVar, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from ira.tools.backends import Backend

MUTATING_VERBS = frozenset(
    {
        "apply", "cordon", "create", "delete", "drain", "edit", "exec", "execute",
        "kill", "modify", "patch", "post", "put", "reboot", "remove", "restart", "revert",
        "rollback", "scale", "set", "start", "stop", "update", "write",
    }
)  # fmt: skip


def mutating_verbs_in(name: str) -> set[str]:
    return set(re.split(r"[^a-z]+", name.lower())) & MUTATING_VERBS


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_call_id: str
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    content: str
    data: Any = None
    truncated: bool = False
    redactions: dict[str, int] = Field(default_factory=dict)
    duration_ms: float = 0.0
    error: str | None = None


class ToolOutput(NamedTuple):
    content: str
    data: Any = None


@dataclass(frozen=True)
class ToolContext:
    """Defaults derived from the alert, so the model can omit time windows."""

    fired_at: datetime
    lookback: timedelta = timedelta(minutes=60)
    lookahead: timedelta = timedelta(minutes=15)
    deploy_lookback: timedelta = timedelta(days=7)

    @property
    def default_since(self) -> datetime:
        return self.fired_at - self.lookback

    @property
    def default_until(self) -> datetime:
        return self.fired_at + self.lookahead


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WindowInput(ToolInput):
    since: datetime | None = Field(
        default=None, description="ISO-8601 start. Defaults to 60 minutes before the alert."
    )
    until: datetime | None = Field(
        default=None, description="ISO-8601 end. Defaults to 15 minutes after the alert."
    )

    def window(self, ctx: ToolContext) -> tuple[datetime, datetime]:
        return self.since or ctx.default_since, self.until or ctx.default_until


class ReadOnlyTool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    Input: ClassVar[type[ToolInput]]
    read_only: ClassVar[Literal[True]] = True

    def __init__(self, backend: Backend, ctx: ToolContext):
        self.backend = backend
        self.ctx = ctx

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.read_only is not True:
            raise TypeError(f"{cls.__name__}: investigation tools must be read-only")
        name = cls.__dict__.get("name")
        if name is not None and (bad := mutating_verbs_in(name)):
            raise TypeError(f"tool name {name!r} contains mutating verb(s) {sorted(bad)}")

    @classmethod
    def spec(cls) -> dict[str, Any]:
        """Anthropic tool definition."""
        return {
            "name": cls.name,
            "description": cls.description,
            "input_schema": cls.Input.model_json_schema(),
        }

    @abstractmethod
    def run(self, args: Any) -> ToolOutput: ...


def fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
