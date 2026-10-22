"""Atomic writes and append-only JSONL: the two primitives state and dead-letters rely on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_connectors.utils.io import (
    append_jsonl,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    ensure_directory,
    file_size,
    fsync_directory,
    read_text,
)

pytestmark = pytest.mark.unit


def test_ensure_directory_creates_nested_and_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "c"
    assert ensure_directory(target) == target
    assert ensure_directory(target) == target
    assert target.is_dir()


def test_fsync_directory_does_not_fail_where_the_os_has_no_support(tmp_path: Path) -> None:
    fsync_directory(tmp_path)
    fsync_directory(tmp_path / "missing")


def test_atomic_write_text_creates_parents_and_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "state" / "demo.json"
    atomic_write_text(target, "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
    assert leftovers == []


def test_atomic_write_bytes_replaces_previous_content(tmp_path: Path) -> None:
    target = tmp_path / "blob"
    atomic_write_bytes(target, b"0123456789")
    atomic_write_bytes(target, b"abc")
    assert target.read_bytes() == b"abc"
    assert file_size(target) == 3


def test_atomic_write_json_is_sorted_readable_and_newline_terminated(tmp_path: Path) -> None:
    target = tmp_path / "doc.json"
    atomic_write_json(target, {"b": 2, "a": {"d": 1, "c": [1, 2]}})
    text = target.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert text.index('"a"') < text.index('"b"')
    assert json.loads(text) == {"b": 2, "a": {"d": 1, "c": [1, 2]}}


def test_a_failed_serialisation_leaves_the_previous_file_intact(tmp_path: Path) -> None:
    """Serialising before opening a temp file means a bad payload cannot tear the state."""
    target = tmp_path / "doc.json"
    atomic_write_json(target, {"cursor": "safe"})
    circular: dict[str, object] = {}
    circular["self"] = circular
    with pytest.raises(ValueError, match="Circular reference"):
        atomic_write_json(target, circular)
    assert json.loads(target.read_text(encoding="utf-8")) == {"cursor": "safe"}
    assert [p.name for p in target.parent.iterdir()] == ["doc.json"]


def test_read_text_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    assert read_text(tmp_path / "nope.txt") is None
    atomic_write_text(tmp_path / "yes.txt", "content")
    assert read_text(tmp_path / "yes.txt") == "content"


def test_append_jsonl_writes_one_object_per_line_and_counts(tmp_path: Path) -> None:
    target = tmp_path / "dead_letter" / "demo.jsonl"
    first = append_jsonl(target, [{"b": 1}, {"a": 2}])
    second = append_jsonl(target, [{"c": 3}])
    assert (first, second) == (2, 1)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0]) == {"b": 1}
    assert json.loads(lines[1]) == {"a": 2}
    assert lines[2] == '{"c": 3}'


def test_append_jsonl_keeps_non_ascii_readable(tmp_path: Path) -> None:
    target = tmp_path / "unicode.jsonl"
    append_jsonl(target, [{"note": "délégation"}])
    assert "délégation" in target.read_text(encoding="utf-8")


def test_append_jsonl_accepts_an_empty_batch(tmp_path: Path) -> None:
    target = tmp_path / "empty.jsonl"
    assert append_jsonl(target, []) == 0
    assert target.read_text(encoding="utf-8") == ""


def test_file_size_reports_zero_for_missing(tmp_path: Path) -> None:
    assert file_size(tmp_path / "missing") == 0
