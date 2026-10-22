# Contribute

Short version: small, tested, well-typed pull requests that keep the connector contract
stable. This project is a portfolio-grade reference implementation, so review focuses on
correctness, honest documentation and safe handling of security data.

## Environment

Python 3.11+ with [uv](https://docs.astral.sh/uv/) (recommended) or pip.

```bash
uv sync --extra dev                      # or: python -m venv .venv && .venv/Scripts/activate
uv run --extra dev python -m pre_commit install   # ruff lint, ruff format, mypy, secret scan
```

## Before you open a pull request

```bash
uv run --extra dev ruff check src tests scripts
uv run --extra dev ruff format --check src tests scripts
uv run --extra dev python -m mypy
uv run --extra dev python -m pytest -m unit
uv run --extra dev python -m pytest --cov --cov-fail-under=80
python scripts/check_no_secrets.py
```

All of the above run in CI (`.github/workflows/ci.yml`); a red pipeline means the branch
is not ready.

## What a connector must do

Adding a source is the main contribution path — see
[docs/adding-a-connector.md](docs/adding-a-connector.md) once it lands in the docs
milestone. In short:

1. Subclass `BaseConnector` and implement `fetch`, `parse`, `normalize`.
2. Emit `EcsEvent` objects only — never a raw dict to a forwarder.
3. Ship at least one real sample file in `tests/fixtures/<source>/` (**synthetic or
   anonymized data only**, no customer or personal data).
4. Register the connector in `config/example.yaml` and the field-mapping table in `docs/`.
5. Cover the happy path plus the failure paths you handled: malformed record, missing
   field, partial page, API error.

## Conventions

- Type hints everywhere; `mypy` runs with `strict = true`.
- No network or filesystem side effects at import time.
- Secrets come from the environment only. Config files hold non-secret settings.
- Every upstream field you map gets a row in the field-mapping table and a test.
- Anything not verifiable against a live service is labelled **"tested with
  fixtures/mocks only"** in code, tests and README. Do not claim otherwise.

## Reporting problems

Use the issue templates. For anything with a security impact (credential exposure,
injection, path traversal in log handling), open a normal issue **without** details and
contact the maintainer privately — see [SECURITY](docs/security.md).

## License

By contributing you agree that your contributions are licensed under the MIT license in
[LICENSE](LICENSE).
