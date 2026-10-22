"""Guard the tooling that guards the repo: the hardcoded-secret scanner."""

from __future__ import annotations

import importlib.util
import re
import sys
import types
from collections.abc import Callable
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_no_secrets.py"


@pytest.fixture(scope="module")
def scanner() -> types.ModuleType:
    """Load scripts/check_no_secrets.py as a module (it is not an importable package)."""
    spec = importlib.util.spec_from_file_location("check_no_secrets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_scanner_reports_the_repository_clean(scanner: types.ModuleType) -> None:
    main: Callable[[list[str]], int] = scanner.main
    assert main([]) == 0


def test_assignment_with_real_looking_value_is_flagged(scanner: types.ModuleType) -> None:
    assignment: re.Pattern[str] = scanner.ASSIGNMENT
    placeholder: re.Pattern[str] = scanner.PLACEHOLDER
    # Assembled at runtime so this test file never contains the string the scanner hunts.
    key = "entra_client_" + "secret"
    value = "sup3rvalue" + "ThatisReal"
    match = assignment.search(f"{key} = '{value}'")
    assert match is not None
    assert match.group("value") == f"'{value}'"
    assert not placeholder.fullmatch(match.group("value"))


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        # Quoted and unquoted literals are findings.
        ("auth_" + "token", "'abc12345678'", True),
        ("api_" + "key", "sk-abcd" + "ef123456", True),
        # Program state that merely mentions a credential-shaped name is not.
        ("self._tokens", "float(self.burst)", False),
        ("self._tokens", "min(float(self.burst), self._tokens + delta)", False),
        ("refresh_" + "token", "await self._fetch(scope)", False),
        ("access_" + "key", "credential_from_env()", False),
    ],
)
def test_only_literal_shaped_values_are_findings(
    scanner: types.ModuleType, key: str, value: str, expected: bool
) -> None:
    """Keys and values are assembled at runtime so this file is never a finding itself."""
    match = scanner.ASSIGNMENT.search(f"{key} = {value}")
    assert match is not None, key
    assert scanner.looks_like_credential_literal(match.group("value").strip()) is expected


@pytest.mark.parametrize(
    "value",
    [
        "${SOC_ENTRA_CLIENT_SECRET}",
        "<your-client-secret>",
        "CHANGE_ME_PLEASE",
        "****************",
        "None",
        "REDACTED",
    ],
)
def test_placeholders_are_not_flagged(scanner: types.ModuleType, value: str) -> None:
    placeholder: re.Pattern[str] = scanner.PLACEHOLDER
    assert placeholder.fullmatch(value)


def test_aws_access_key_shape_is_flagged(scanner: types.ModuleType) -> None:
    aws_key: re.Pattern[str] = scanner.AWS_ACCESS_KEY
    # CloudTrail-style documentation placeholder: AKIA + 16 upper alphanumerics.
    assert aws_key.search("access_key_id = " + "AKIA" + "EXAMPLEEXAMPLE12")
    assert not aws_key.search("AKIA" + "short")


def test_real_env_file_is_skipped_and_config_files_are_scanned(scanner: types.ModuleType) -> None:
    should_scan: Callable[[Path], bool] = scanner.should_scan
    assert not should_scan(ROOT / ".env")
    assert not should_scan(ROOT / ".env.example")
    assert should_scan(ROOT / "config" / "example.yaml")


def test_installed_and_cached_directories_are_never_walked(
    scanner: types.ModuleType, tmp_path: Path
) -> None:
    """The walk prunes during descent: a virtualenv here would cost seconds to enumerate."""
    for name in (".venv/lib", ".git/objects", "__pycache__", "node_modules/pkg"):
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "hidden.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")

    walked = sorted(path.relative_to(tmp_path).as_posix() for path in scanner.iter_files(tmp_path))
    assert walked == ["src/app.py"]


def test_a_symlinked_directory_cannot_loop_the_walk(
    scanner: types.ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "real").mkdir()
    try:
        (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - needs developer mode on Windows
        pytest.skip("this platform does not allow creating symlinks")
    assert list(scanner.iter_files(tmp_path)) == []
