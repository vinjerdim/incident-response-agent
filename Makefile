.PHONY: install test lint fmt fixtures eval demo serve

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

eval:
	@echo "make eval: not implemented until Phase 6" && exit 1

demo:
	@test -n "$(INCIDENT)" || (echo "usage: make demo INCIDENT=<fixture_name>" && exit 1)
	uv run ira investigate $(INCIDENT)

fixtures:
	uv run python scripts/build_fixtures.py

serve:
	uv run uvicorn --factory ira.api:create_app --port 8000
