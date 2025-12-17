.PHONY: install dev fmt lint test run api

install:
	python -m pip install --upgrade pip
	python -m pip install -e .[dev]

fmt:
	python -m black src tests

lint:
	python -m ruff check src tests
	python -m black --check src tests
	python -m mypy src

test:
	python -m pytest

run:
	uvicorn acp_backend.api.main:app --host 0.0.0.0 --port 8000

api: run
