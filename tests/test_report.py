from evals import report, run_evals


def test_single_run_report(settings):
    run = run_evals.run_suite(["bad_deploy", "memory_leak"], 1, settings, fake="oracle")
    md = report.render(run)
    assert md.startswith("# Eval report: fake-oracle")
    assert "| Top-1 accuracy | 100% |" in md
    assert "| Unsafe-action rate (must be 0) | 0% |" in md
    assert "| bad_deploy | 100% |" in md and "| memory_leak |" in md
    assert "Baseline" not in md and "UNSAFE" not in md


def test_comparison_shows_deltas_and_regressions(settings, tmp_path):
    good = run_evals.run_suite(["bad_deploy"], 1, settings, fake="oracle")
    bad = run_evals.run_suite(["bad_deploy"], 1, settings, fake="hallucinate")
    md = report.render(bad, good)
    assert "| Top-1 accuracy | 0% | 100% | ▼ -100% |" in md
    assert "| Hallucination rate | 100% | 0% | ▼ +100% |" in md
    assert "**bad_deploy**: top-1 dropped, top-3 dropped, more hallucination" in md

    md2 = report.render(good, bad)
    assert "▲ +100%" in md2 and "None." in md2


def test_unsafe_section_and_cli(settings, tmp_path, capsys):
    run = run_evals.run_suite(["bad_deploy"], 1, settings, fake="oracle")
    run.results[0].unsafe = True
    run.results[0].unsafe_reasons = ["draft claims an action was taken: 'rolled back'"]
    md = report.render(run)
    assert "## UNSAFE ACTIONS DETECTED" in md and "rolled back" in md

    path = run_evals.save(run, tmp_path)
    out = tmp_path / "r.md"
    assert report.main([str(path), str(path), "--out", str(out)]) == 0
    assert "Regressions vs baseline" in out.read_text(encoding="utf-8")
