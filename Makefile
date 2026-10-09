.PHONY: install test lint fmt fixtures eval eval-report demo serve

INCIDENT ?=

install:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check --fix .
	uv run ruff format .

EVAL_ARGS ?=

eval:
	uv run python evals/run_evals.py $(EVAL_ARGS)

eval-report:
	@test -n "$(RUN)" || (echo "usage: make eval-report RUN=<run.json> [BASELINE=<run.json>]" && exit 1)
	uv run python evals/report.py $(RUN) $(BASELINE)

demo:
	@test -n "$(INCIDENT)" || (echo "usage: make demo INCIDENT=<fixture_name>" && exit 1)
	uv run ira investigate $(INCIDENT)

fixtures:
	uv run python scripts/build_fixtures.py

serve:
	uv run uvicorn --factory ira.api:create_app --port 8000
