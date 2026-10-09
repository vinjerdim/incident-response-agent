import json

from evals import run_evals

from ira.evaluation import EvalRun
from ira.fixtures import list_incidents


def test_oracle_suite_offline(settings, tmp_path, capsys):
    code = run_evals.main(["--fake", "oracle", "--out-dir", str(tmp_path)], settings=settings)
    assert code == 0, capsys.readouterr()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1 and "fake-oracle" in files[0].name
    run = EvalRun.model_validate(json.loads(files[0].read_text()))
    a = run.aggregate
    assert run.incidents == list_incidents(settings.fixtures_dir) and a.trials == 12
    assert a.injection_trials == 4 and a.injection_resistance_rate == 1.0
    assert a.top1_accuracy == 1.0 and a.top3_accuracy == 1.0
    assert a.unsafe_trials == 0 and a.crashed_trials == 0 and a.completion_rate == 1.0
    assert a.citation_validity == 1.0 and a.hallucination_rate == 0.0
    assert all(r.top_evidence_on_target for r in run.results)
    assert run.per_incident.keys() == set(run.incidents)
    assert "saved" in capsys.readouterr().out


def test_hallucinating_agent_is_caught(settings, tmp_path):
    run = run_evals.run_suite(["bad_deploy", "expired_cert"], 2, settings, fake="hallucinate")
    a = run.aggregate
    assert a.trials == 4
    assert a.top1_accuracy == 0.0 and a.top3_accuracy == 0.0
    assert a.hallucination_rate == 1.0 and a.citation_validity == 0.0
    assert all(r.hypotheses_dropped == 1 for r in run.results)
    assert a.unsafe_trials == 0
    path = run_evals.save(run, tmp_path)
    assert path.exists()


def test_crash_is_recorded_and_fails_exit(settings, tmp_path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(run_evals, "run_investigation", boom)
    code = run_evals.main(
        ["--fake", "oracle", "--incidents", "bad_deploy", "--out-dir", str(tmp_path)],
        settings=settings,
    )
    assert code == 1
    run = EvalRun.model_validate_json(next(tmp_path.glob("*.json")).read_text())
    assert run.results[0].crashed and "pipeline exploded" in run.results[0].error


def test_unknown_incident(settings, tmp_path, capsys):
    code = run_evals.main(["--fake", "oracle", "--incidents", "nope"], settings=settings)
    assert code == 2 and "unknown incidents" in capsys.readouterr().err
