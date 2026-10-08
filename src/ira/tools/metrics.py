from __future__ import annotations

from itertools import pairwise
from statistics import fmean, median

from pydantic import Field

from ira.fixtures import MetricSeries
from ira.tools.base import ReadOnlyTool, ToolInput, ToolOutput, WindowInput, fmt_ts


class ListMetricsInput(ToolInput):
    service: str | None = Field(default=None, description="Exact service name filter.")


class ListMetrics(ReadOnlyTool):
    name = "list_metrics"
    description = "List available metric series (name, service, unit). Read-only."
    Input = ListMetricsInput

    def run(self, args: ListMetricsInput) -> ToolOutput:
        series = self.backend.list_metrics(service=args.service)
        rows = [f"{m.name} service={m.service} unit={m.unit}" for m in series]
        return ToolOutput(
            "\n".join([f"{len(rows)} metric series.", *rows]),
            [{"name": m.name, "service": m.service, "unit": m.unit} for m in series],
        )


class QueryMetricsInput(WindowInput):
    name: str = Field(min_length=1, description="Metric series name, from list_metrics.")
    service: str | None = Field(default=None, description="Exact service name filter.")
    include_points: bool = Field(default=False, description="Also return raw points.")


def summarize(series: MetricSeries) -> dict:
    pts = series.points
    if not pts:
        return {"points": 0}
    values = [p.value for p in pts]
    baseline = fmean(values[: min(10, len(values))])
    recent = fmean(values[-5:])
    jumps = [(abs(b.value - a.value), a, b) for a, b in pairwise(pts)]
    biggest = max(jumps, key=lambda j: j[0]) if jumps else None
    intervals = [(b.ts - a.ts).total_seconds() for a, b in pairwise(pts)]
    typical = median(intervals) if intervals else 0
    gaps = [
        fmt_ts(a.ts)
        for (a, _), dt in zip(pairwise(pts), intervals, strict=True)
        if typical and dt > 1.5 * typical
    ]
    peak = max(pts, key=lambda p: p.value)
    return {
        "points": len(pts),
        "min": min(values),
        "max": max(values),
        "max_at": fmt_ts(peak.ts),
        "mean": round(fmean(values), 2),
        "first": values[0],
        "last": values[-1],
        "baseline_mean_first10": round(baseline, 2),
        "recent_mean_last5": round(recent, 2),
        "largest_step": None
        if biggest is None
        else {"from": biggest[1].value, "to": biggest[2].value, "at": fmt_ts(biggest[2].ts)},
        "gaps_after": gaps,
    }


class QueryMetrics(ReadOnlyTool):
    name = "query_metrics"
    description = (
        "Summarize one metric series in a time window: min/max/mean, baseline vs recent, "
        "largest step change and when, and scrape gaps. Read-only."
    )
    Input = QueryMetricsInput

    def run(self, args: QueryMetricsInput) -> ToolOutput:
        since, until = args.window(self.ctx)
        series = self.backend.get_series(
            name=args.name, service=args.service, since=since, until=until
        )
        if series is None:
            return ToolOutput(f"No metric series named {args.name!r}. Use list_metrics.", None)
        s = summarize(series)
        lines = [
            f"{series.name} ({series.service}, {series.unit}) "
            f"{fmt_ts(since)}..{fmt_ts(until)}: {s['points']} points"
        ]
        if s["points"]:
            lines.append(
                f"min={s['min']} max={s['max']} (at {s['max_at']}) mean={s['mean']} "
                f"first={s['first']} last={s['last']}"
            )
            lines.append(
                f"baseline(first 10)={s['baseline_mean_first10']} "
                f"recent(last 5)={s['recent_mean_last5']}"
            )
            if step := s["largest_step"]:
                lines.append(f"largest step: {step['from']} -> {step['to']} at {step['at']}")
            if s["gaps_after"]:
                lines.append(f"scrape gaps after: {', '.join(s['gaps_after'])}")
        data = {"summary": s}
        if args.include_points:
            data["points"] = [p.model_dump(mode="json") for p in series.points]
            lines.extend(f"{fmt_ts(p.ts)} {p.value}" for p in series.points)
        return ToolOutput("\n".join(lines), data)
