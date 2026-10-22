## What changed

One paragraph. Link issues with `#123`.

## Checklist

- [ ] `uv run --extra dev ruff check src tests scripts` and `ruff format --check` clean
- [ ] `uv run --extra dev mypy` clean
- [ ] `uv run --extra dev pytest --cov --cov-fail-under=80` passes
- [ ] New source/destination has at least one synthetic fixture in `tests/fixtures/`
- [ ] Field mapping row added to `docs/ecs-field-mapping.md`
- [ ] Secrets read from the environment; `python scripts/check_no_secrets.py` passes
- [ ] Anything not verifiable against a live service is labelled "tested with
      fixtures/mocks only" in code, tests and README
- [ ] No real account ids, tenant ids, credentials or personal data anywhere in the diff

## How I verified it

Exact commands run and what the output showed. For a connector, include one normalized
ECS event produced from the fixture. Do not report results you did not run.
