#Requires -Version 5.1
# Windows equivalent of scripts/dev_verify.sh and of the CI job.
# Run from the repo root:  .\scripts\dev_verify.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step "ruff" { uv run --extra dev ruff check src tests scripts }
Invoke-Step "ruff format" { uv run --extra dev ruff format --check src tests scripts }
Invoke-Step "mypy" { uv run --extra dev python -m mypy }
Invoke-Step "pytest (unit)" { uv run --extra dev python -m pytest -m unit }
Invoke-Step "coverage" { uv run --extra dev python -m pytest --cov --cov-report=term-missing --cov-fail-under=80 }
Invoke-Step "secret scan" { uv run python scripts/check_no_secrets.py }

Write-Host "dev_verify: all checks passed" -ForegroundColor Green
