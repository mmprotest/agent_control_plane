.PHONY: install dev fmt format lint typecheck test run api up down

install:
	python -m pip install --upgrade pip
	python -m pip install -e .[dev]

fmt:
	python -m black src tests

format: fmt

lint:
	python -m ruff check src tests
	python -m black --check src tests

typecheck:
	python -m mypy src

test:
	python -m pytest

run:
	uvicorn acp_backend.api.main:app --host 0.0.0.0 --port 8000

api: run

up:
	docker compose up --build

down:
	docker compose down -v
