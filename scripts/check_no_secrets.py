#!/usr/bin/env python3
"""Fail if a checked-in file assigns a credential literal.

The framework reads every secret from the environment, so a hardcoded value in source,
config, docs or fixtures is always a bug. This runs as a pre-commit hook and in CI.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXEMPT_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
EXEMPT_FILES = {".env.example", Path(__file__).name}
CHECK_SUFFIXES = {
    ".py",
    ".yaml",
    ".yml",
    ".json",
    ".md",
    ".toml",
    ".sh",
    ".ps1",
    ".conf",
}

CREDENTIAL_NAME = (
    r"(?:secret|password|passwd|api[_-]?key|access[_-]?key|auth[_-]?token|token|private[_-]?key)"
)
# key: "value"  /  KEY = "value"  — captures only the value.
ASSIGNMENT = re.compile(
    rf"""["']?[\w.-]*{CREDENTIAL_NAME}[\w.-]*["']?\s*[:=]\s*(?P<value>["'][^"']*["']|[^\s,;]+)""",
    re.IGNORECASE,
)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
QUOTED_EMPTY = {"", '""', "''"}
PLACEHOLDER = re.compile(
    r"""^[\s"']*(?:
        \$\{?[A-Z][A-Z0-9_]*\}?      # ${SOC_ENTRA_CLIENT_SECRET} style
      | <[^>]+>                      # <your-client-secret>
      | (?:CHANGE|YOUR|REPLACE|PUT|SET)[_-]?.*
      | x{6,} | \*{3,} | [.-]{3,}
      | (?:null|none|nil|empty|true|false|todo|tbd|redacted|masked)
      )[\s"']*$
    """,
    re.IGNORECASE | re.VERBOSE,
)
# Anything shorter than this is a flag, an enum or a docstring fragment, not a key.
MIN_SUSPICIOUS_LENGTH = 6
# An unquoted right-hand side is only a literal if it is shaped like one. `self._tokens =
# float(self.burst)` is a rate-limit bucket, and `token = self._next_token(cursor)` is program
# state; parentheses, spaces and dotted names are code, so they are not findings.
KEY_SHAPED_VALUE = re.compile(r"[A-Za-z0-9+/=_-]{8,}")


def looks_like_credential_literal(value: str) -> bool:
    """Quoted text is a literal; unquoted text must also avoid looking like an expression."""
    if value[:1] in {'"', "'"}:
        return True
    return KEY_SHAPED_VALUE.fullmatch(value) is not None


def should_scan(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if EXEMPT_DIRS & set(rel.parts):
        return False
    if rel.name in EXEMPT_FILES:
        return False
    return rel.suffix in CHECK_SUFFIXES


def findings_for(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [f"{path.relative_to(ROOT)}:1: unreadable ({exc})"]

    findings = []
    rel = path.relative_to(ROOT)
    for number, line in enumerate(text.splitlines(), start=1):
        if AWS_ACCESS_KEY.search(line):
            findings.append(f"{rel}:{number}: AWS access key id literal")
            continue
        match = ASSIGNMENT.search(line)
        if not match:
            continue
        value = match.group("value").strip()
        if value in QUOTED_EMPTY or PLACEHOLDER.fullmatch(value):
            continue
        if len(value) < MIN_SUSPICIOUS_LENGTH:
            continue
        if not looks_like_credential_literal(value):
            continue
        findings.append(f"{rel}:{number}: possible credential -> {value[:4]}…")
    return findings


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every regular file under ``root`` without descending into caches and virtualenvs.

    Pruning during the walk rather than after it is the point: ``root.rglob("*")`` enumerates
    all of ``.venv`` — tens of thousands of paths — and the caller then throws them away,
    which costs the check ~20 seconds on a Windows checkout instead of a fraction of one.
    Symlinks are skipped, so a linked directory inside the repo cannot loop the walk.
    """
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in EXEMPT_DIRS:
                    pending.append(entry)
                continue
            yield entry


def main(argv: list[str]) -> int:
    paths = [path for path in iter_files(ROOT) if should_scan(path)]
    if argv:
        wanted = {Path(arg).resolve() for arg in argv}
        paths = [p for p in paths if p.resolve() in wanted]

    findings = [finding for path in paths for finding in findings_for(path)]
    if findings:
        print("Hardcoded credential candidates:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print("Read secrets from the environment instead (see .env.example).", file=sys.stderr)
        return 1

    print(f"no-hardcoded-secrets: {len(paths)} files scanned, nothing hardcoded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
