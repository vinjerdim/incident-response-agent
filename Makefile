.PHONY: install test lint fmt eval demo

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
	@echo "make demo INCIDENT=$(INCIDENT): not implemented until Phase 4" && exit 1
