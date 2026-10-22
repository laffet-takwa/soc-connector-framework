"""The scaffold itself must hold: package surface, CLI, entry point, ignore rules.

These are the tests that stay useful later — if a milestone silently breaks the console
script or starts committing runtime state, this file says so.
"""

from __future__ import annotations

import importlib
import re
from importlib import metadata
from pathlib import Path

import pytest

import soc_connectors
from soc_connectors import cli
from soc_connectors.version import UPSTREAM_REFERENCES

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]

SUBPACKAGES = [
    "soc_connectors.schema",
    "soc_connectors.connectors",
    "soc_connectors.forwarders",
    "soc_connectors.pipeline",
    "soc_connectors.utils",
]


def test_version_follows_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[.\-][0-9A-Za-z.-]+)?", soc_connectors.__version__)


@pytest.mark.parametrize("module_name", SUBPACKAGES)
def test_subpackages_are_importable(module_name: str) -> None:
    assert importlib.import_module(module_name).__doc__, f"{module_name} needs a docstring"


def test_package_ships_py_typed_marker() -> None:
    assert (ROOT / "src" / "soc_connectors" / "py.typed").is_file()


def test_cli_returns_success_and_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "usage: soc-connectors" in out


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert soc_connectors.__version__ in capsys.readouterr().out


def test_console_script_entry_point_is_installed() -> None:
    entry_points = metadata.entry_points(group="console_scripts")
    names = {ep.name for ep in entry_points}
    assert "soc-connectors" in names, f"soc-connectors missing from {sorted(names)}"


@pytest.mark.parametrize(
    "ignored_path",
    ["data/state/", "data/dead_letter/", "data/output/", ".env", "*.pem"],
)
def test_runtime_state_and_secrets_are_gitignored(ignored_path: str) -> None:
    raw = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    patterns = {line.strip() for line in raw if line.strip() and not line.startswith("#")}
    assert ignored_path in patterns


def test_upstream_reference_notes_are_recorded() -> None:
    assert UPSTREAM_REFERENCES["graph_api_version"] == "v1.0"
    assert UPSTREAM_REFERENCES["cloudtrail_event_version"] == "1.11"
