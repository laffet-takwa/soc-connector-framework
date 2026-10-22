#!/usr/bin/env bash
# Same checks as CI, run locally. Works in Git Bash on Windows and on Linux/macOS.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run --extra dev ruff check src tests scripts
uv run --extra dev ruff format --check src tests scripts
uv run --extra dev python -m mypy
uv run --extra dev python -m pytest -m unit
uv run --extra dev python -m pytest --cov --cov-report=term-missing --cov-fail-under=80
uv run python scripts/check_no_secrets.py
echo "dev_verify: all checks passed"
