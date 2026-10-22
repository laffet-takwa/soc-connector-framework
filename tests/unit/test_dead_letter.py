"""The dead-letter file: evidence that survives a failure, at a bounded size."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from logging import LogRecord
from pathlib import Path

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.types import RawEvent
from soc_connectors.utils.dead_letter import TRUNCATED_MARKER, DeadLetterQueue

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)


def raw(payload: object = '{"event": "boom"}', cursor: str | None = "s3:42") -> RawEvent:
    return RawEvent(
        connector_id="demo",
        payload=payload if isinstance(payload, str | bytes | bytearray | dict) else str(payload),
        received_at=NOW,
        cursor=cursor,
    )


def test_a_minimal_record_still_explains_itself(dead_letter: DeadLetterQueue) -> None:
    record = dead_letter.write(
        connector_id="demo", stage="normalize", reason="not valid JSON", at=NOW
    )
    assert record["connector_id"] == "demo"
    assert record["stage"] == "normalize"
    assert record["reason"] == "not valid JSON"
    assert record["logged_at"] == "2026-10-22T09:00:00.000Z"
    assert record["error_type"] is None
    assert "payload" not in record
    assert dead_letter.count() == 1


def test_the_written_record_is_the_stored_record(tmp_path: Path) -> None:
    queue = DeadLetterQueue(tmp_path / "dead.jsonl")
    record = queue.write(
        connector_id="demo",
        stage="forward",
        reason="destination refused",
        error=ValueError("mapping conflict"),
        raw=raw(),
        identity="net:evt-1",
        at=NOW,
    )
    stored = list(queue.records())
    assert stored == [record]
    assert record["error"] == "mapping conflict"
    assert record["error_type"] == "ValueError"
    assert record["identity"] == "net:evt-1"
    assert record["cursor"] == "s3:42"
    assert record["payload"] == '{"event": "boom"}'


def test_payloads_longer_than_the_limit_are_clipped_with_a_marker(tmp_path: Path) -> None:
    queue = DeadLetterQueue(tmp_path / "dead.jsonl", payload_limit=16)
    record = queue.write(
        connector_id="demo",
        stage="parse",
        reason="too big",
        raw=raw("x" * 400, cursor=None),
    )
    assert record["payload"][TRUNCATED_MARKER] is True
    assert record["payload"]["bytes"] == 400
    assert len(record["payload"]["text"]) == 16


def test_a_malformed_error_carries_its_own_evidence(dead_letter: DeadLetterQueue) -> None:
    error = MalformedEventError("payload is not valid JSON", raw=raw("garbage{"), field="payload")
    record = dead_letter.write(connector_id="demo", stage="parse", reason="broken", error=error)
    assert record["payload"] == "garbage{"
    assert record["error_type"] == "MalformedEventError"


def test_an_undecodable_payload_is_stored_as_its_repr(tmp_path: Path) -> None:
    queue = DeadLetterQueue(tmp_path / "dead.jsonl")
    record = queue.write(connector_id="demo", stage="parse", reason="binary", raw=raw(b"\xff\xfe"))
    assert record["payload"].startswith("b'")


def test_documents_are_stored_under_the_redaction_policy(tmp_path: Path) -> None:
    queue = DeadLetterQueue(
        tmp_path / "dead.jsonl",
        redaction=RedactionSettings(fields=["user.name"], mode="mask", keep_raw=False),
    )
    record = queue.write(
        connector_id="demo",
        stage="forward",
        reason="refused",
        document={"user": {"name": "j.doe"}, "event": {"action": "login"}},
    )
    assert record["event"]["user"]["name"] == "***"
    assert record["event"]["event"]["action"] == "login"


def test_write_logs_the_failure_as_an_error(
    dead_letter: DeadLetterQueue, capture_logs: Callable[[str], list[LogRecord]]
) -> None:
    records = capture_logs("dead_letter")
    dead_letter.write(connector_id="demo", stage="parse", reason="broken")
    assert any(record.getMessage() == "event dead-lettered" for record in records)


def test_an_oversized_file_is_rotated_before_the_next_write(tmp_path: Path) -> None:
    queue = DeadLetterQueue(tmp_path / "dead.jsonl", max_bytes=200)
    for index in range(6):
        queue.write(connector_id="demo", stage="parse", reason=f"failure {index}")
    rotated = sorted(p.name for p in tmp_path.glob("dead.*.jsonl"))
    assert len(rotated) >= 1
    assert queue.count() < 6
    assert queue.size < 10_000


def test_a_rotation_failure_counts_drops_instead_of_growing_forever(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capture_logs: Callable[[str], list[LogRecord]]
) -> None:
    path = tmp_path / "dead.jsonl"
    path.write_text("already at the ceiling\n", encoding="utf-8")
    queue = DeadLetterQueue(path, max_bytes=1)
    records = capture_logs("dead_letter")

    def refuse(_self: Path, _target: Path) -> Path:
        raise OSError("device or resource busy")

    monkeypatch.setattr(Path, "replace", refuse)
    queue.write(connector_id="demo", stage="parse", reason="first")
    assert queue.dropped_by_cap == 1
    assert queue.count() == 1  # the record is still stored, only the rotation was refused
    assert any("rotation failed" in record.getMessage() for record in records)


def test_reading_skips_blank_and_unparseable_lines(tmp_path: Path) -> None:
    path = tmp_path / "dead.jsonl"
    path.write_text(
        "\n" + json.dumps({"reason": "kept"}) + "\n{ torn line\n\n",
        encoding="utf-8",
    )
    queue = DeadLetterQueue(path)
    assert [record["reason"] for record in queue.records()] == ["kept"]
    assert queue.count() == 1


def test_records_of_a_file_that_was_never_written(tmp_path: Path) -> None:
    queue = DeadLetterQueue(tmp_path / "nothing.jsonl")
    assert list(queue.records()) == []
    assert queue.count() == 0
    assert queue.size == 0


def test_the_directory_is_created_eagerly(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "dead.jsonl"
    assert not target.exists()
    DeadLetterQueue(target)
    assert target.parent.is_dir()
