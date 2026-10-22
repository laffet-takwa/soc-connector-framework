# Convenience wrappers around the uv/pip commands. On Windows prefer
# scripts/dev_verify.ps1 (make is usually absent); everything here just shells out to
# the same tools, so both paths are equivalent.
UV ?= uv
PY ?= python
COMPOSE_FILE ?= docker/docker-compose.yml

.PHONY: help install lock fmt lint type test cov verify secrets clean demo-up demo-down demo-logs

help:
	@echo "install     create .venv and install runtime + dev dependencies"
	@echo "lock        refresh uv.lock"
	@echo "fmt         ruff check --fix + ruff format"
	@echo "lint        ruff check + ruff format --check"
	@echo "type        mypy"
	@echo "test        pytest unit tests"
	@echo "cov         pytest with coverage, fails under 80%"
	@echo "verify      lint + type + test + coverage + secret scan"
	@echo "secrets     hardcoded-credential scan only"
	@echo "demo-up     start the docker compose demo (available from M6)"
	@echo "demo-down   stop the demo"
	@echo "clean       remove caches and build artifacts"

install:
	$(UV) sync --extra dev

lock:
	$(UV) lock

fmt:
	$(UV) run --extra dev ruff check --fix src tests scripts
	$(UV) run --extra dev ruff format src tests scripts

lint:
	$(UV) run --extra dev ruff check src tests scripts
	$(UV) run --extra dev ruff format --check src tests scripts

type:
	$(UV) run --extra dev python -m mypy

test:
	$(UV) run --extra dev python -m pytest -m unit

cov:
	$(UV) run --extra dev python -m pytest --cov --cov-report=term-missing --cov-report=xml --cov-fail-under=80

secrets:
	$(UV) run python scripts/check_no_secrets.py

verify: lint type test cov secrets

demo-up:
	docker compose -f $(COMPOSE_FILE) up --build

demo-down:
	docker compose -f $(COMPOSE_FILE) down -v

demo-logs:
	docker compose -f $(COMPOSE_FILE) logs -f connectors

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache htmlcov coverage.xml .coverage dist build
