"""Render an eval run (optionally against a baseline) as markdown.

uv run python evals/report.py RUN.json [BASELINE.json] [--out report.md]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from ira.evaluation import Aggregate, EvalRun


def pct(x: float) -> str:
    return f"{x:.0%}"


def num(x: float) -> str:
    return f"{x:.1f}"


def usd(x: float) -> str:
    return f"${x:.4f}"


# (field, label, formatter, higher_is_better)
METRICS: list[tuple[str, str, Callable[[float], str], bool]] = [
    ("top1_accuracy", "Top-1 accuracy", pct, True),
    ("top3_accuracy", "Top-3 accuracy", pct, True),
    ("citation_validity", "Citation validity", pct, True),
    ("hallucination_rate", "Hallucination rate", pct, False),
    ("key_evidence_coverage", "Key evidence coverage", pct, True),
    ("unsafe_action_rate", "Unsafe-action rate (must be 0)", pct, False),
    ("injection_resistance_rate", "Prompt-injection resistance (must be 100%)", pct, True),
    ("completion_rate", "Completed", pct, True),
    ("crashed_trials", "Crashed trials", lambda x: str(int(x)), False),
    ("mean_steps", "Mean steps", num, False),
    ("mean_tokens", "Mean tokens", lambda x: f"{x:,.0f}", False),
    ("mean_cost_usd", "Mean cost (upper bound)", usd, False),
    ("mean_latency_s", "Mean latency (s)", num, False),
]


def load(path: str | Path) -> EvalRun:
    return EvalRun.model_validate_json(Path(path).read_text(encoding="utf-8"))


def delta(new: float, old: float, fmt: Callable[[float], str], higher_better: bool) -> str:
    if fmt(new) == fmt(old):  # equal at display precision
        return "="
    better = (new > old) == higher_better
    sign = "+" if new > old else "-"
    return f"{'▲' if better else '▼'} {sign}{fmt(abs(new - old))}"


def _summary(run: EvalRun, base: EvalRun | None) -> list[str]:
    head = "| Metric | Run |" + (" Baseline | Δ |" if base else "")
    sep = "|---|---|" + ("---|---|" if base else "")
    rows = [head, sep]
    for field, label, fmt, hib in METRICS:
        v = getattr(run.aggregate, field)
        row = f"| {label} | {'n/a' if v is None else fmt(v)} |"
        if base:
            b = getattr(base.aggregate, field)
            d = "" if v is None or b is None else delta(v, b, fmt, hib)
            row += f" {'n/a' if b is None else fmt(b)} | {d} |"
        rows.append(row)
    return rows


def _incident_rows(run: EvalRun, base: EvalRun | None) -> list[str]:
    head = "| Incident | Top-1 | Top-3 | Halluc. | Key ev. | Unsafe | Steps | Cost | Latency |"
    head += " Top-1 Δ |" if base else ""
    head += " Top hypothesis |"
    rows = [head, "|" + "---|" * (head.count("|") - 1)]
    first = {r.incident: r for r in reversed(run.results)}
    for name, a in run.per_incident.items():
        row = (
            f"| {name} | {pct(a.top1_accuracy)} | {pct(a.top3_accuracy)} | "
            f"{pct(a.hallucination_rate)} | {pct(a.key_evidence_coverage)} | {a.unsafe_trials} | "
            f"{num(a.mean_steps)} | {usd(a.mean_cost_usd)} | {num(a.mean_latency_s)}s |"
        )
        if base:
            b = base.per_incident.get(name)
            row += f" {delta(a.top1_accuracy, b.top1_accuracy, pct, True) if b else 'new'} |"
        top = first[name].top_hypothesis or f"_{first[name].status}_"
        rows.append(row + f" {top.replace('|', '/')[:60]} |")
    return rows


def regressions(run: EvalRun, base: EvalRun) -> list[str]:
    out = []
    for name, a in run.per_incident.items():
        b: Aggregate | None = base.per_incident.get(name)
        if b is None:
            continue
        reasons = []
        if a.top1_accuracy < b.top1_accuracy:
            reasons.append("top-1 dropped")
        if a.top3_accuracy < b.top3_accuracy:
            reasons.append("top-3 dropped")
        if a.hallucination_rate > b.hallucination_rate:
            reasons.append("more hallucination")
        if a.unsafe_trials > b.unsafe_trials:
            reasons.append("new unsafe actions")
        if (a.injection_resistance_rate or 1.0) < (b.injection_resistance_rate or 1.0):
            reasons.append("weaker injection resistance")
        if reasons:
            out.append(f"- **{name}**: {', '.join(reasons)}")
    return out


def render(run: EvalRun, base: EvalRun | None = None) -> str:
    lines = [
        f"# Eval report: {run.label}",
        "",
        f"run `{run.run_id}` at {run.created_at}, git `{run.git_sha}`, model `{run.model}`, "
        f"{run.trials_per_incident} trial(s) x {len(run.incidents)} incidents",
    ]
    if base:
        lines.append(f"baseline: `{base.run_id}` ({base.label}, git `{base.git_sha}`)")
    lines += ["", "## Summary", "", *_summary(run, base)]

    unsafe = [r for r in run.results if r.unsafe]
    if unsafe:
        lines += ["", "## UNSAFE ACTIONS DETECTED", ""]
        lines += [f"- {r.incident} #{r.trial}: {'; '.join(r.unsafe_reasons)}" for r in unsafe]
    crashed = [r for r in run.results if r.crashed]
    if crashed:
        lines += ["", "## Crashed trials", ""]
        lines += [f"- {r.incident} #{r.trial}: {r.error}" for r in crashed]

    inj = [r for r in run.results if r.injection]
    if inj:
        lines += [
            "",
            "## Prompt injection",
            "",
            "| Incident | Trial | Detected | Resisted | Failures |",
            "|---|---|---|---|---|",
        ]
        for r in inj:
            fails = "; ".join(r.injection_failures).replace("|", "/") or "-"
            lines.append(
                f"| {r.incident} | {r.trial} | {'yes' if r.injection_detected else 'no'} | "
                f"{'yes' if r.injection_resisted else '**NO**'} | {fails} |"
            )

    lines += ["", "## Per incident", "", *_incident_rows(run, base)]
    if base:
        regs = regressions(run, base)
        lines += ["", "## Regressions vs baseline", "", *(regs or ["None."])]
    lines += ["", "_Cost prices cache reads as normal input tokens, so it is an upper bound._"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Render an eval run as markdown.")
    p.add_argument("run")
    p.add_argument("baseline", nargs="?")
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    text = render(load(args.run), load(args.baseline) if args.baseline else None)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to cp1252
            sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
