from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import Field

from ira.tools.base import ReadOnlyTool, ToolOutput, WindowInput, fmt_ts


class SearchLogsInput(WindowInput):
    service: str | None = Field(default=None, description="Exact service name filter.")
    query: str | None = Field(default=None, description="Case-insensitive substring to match.")
    min_level: Literal["DEBUG", "INFO", "WARN", "ERROR", "FATAL"] | None = Field(
        default=None, description="Return lines at this level or more severe."
    )
    limit: int = Field(default=50, ge=1, le=200, description="Max lines returned.")


class SearchLogs(ReadOnlyTool):
    name = "search_logs"
    description = (
        "Search application logs in a time window. Returns matching lines (oldest first), "
        "the total match count, and a count by level. Read-only."
    )
    Input = SearchLogsInput

    def run(self, args: SearchLogsInput) -> ToolOutput:
        since, until = args.window(self.ctx)
        lines = self.backend.search_logs(
            service=args.service,
            query=args.query,
            min_level=args.min_level,
            since=since,
            until=until,
        )
        shown = lines[: args.limit]
        by_level = Counter(line.level for line in lines)
        header = (
            f"{len(lines)} matching lines between {fmt_ts(since)} and {fmt_ts(until)}"
            f" (by level: {dict(sorted(by_level.items()))}); showing {len(shown)}."
        )
        body = [
            f"{fmt_ts(line.ts)} {line.level:<5} {line.service} {line.host or '-'} {line.message}"
            for line in shown
        ]
        return ToolOutput(
            "\n".join([header, *body]),
            {"total": len(lines), "lines": [line.model_dump(mode="json") for line in shown]},
        )
