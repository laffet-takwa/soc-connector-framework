"""The value objects exchanged between stages."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.types import CycleReport, ParsedEvent, RawEvent

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)


def make(payload: Any, **kwargs: Any) -> RawEvent:
    return RawEvent(connector_id="demo", payload=payload, received_at=NOW, **kwargs)


def test_as_text_passes_through_each_payload_shape() -> None:
    assert make("line").as_text() == "line"
    assert make(b"line").as_text() == "line"
    assert make(bytearray(b"line")).as_text() == "line"
    assert make({"a": 1}).as_text() == '{"a": 1}'


def test_as_text_rejects_undecodable_bytes() -> None:
    raw = make(b"\xff\xfe")
    with pytest.raises(MalformedEventError, match="not utf-8-decodable") as exc_info:
        raw.as_text()
    assert exc_info.value.raw is raw
    assert exc_info.value.field == "payload"


def test_as_text_falls_back_to_a_lossy_decoding_when_asked() -> None:
    assert make(b"log\x80entry").as_text(encoding="latin-1") == "log\x80entry"


def test_as_mapping_accepts_dicts_and_json_text() -> None:
    assert make({"a": 1}).as_mapping() == {"a": 1}
    assert make('{"a": 1}').as_mapping() == {"a": 1}
    assert make(b'{"a": 1}').as_mapping() == {"a": 1}


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '"a string"', "null", "3"])
def test_as_mapping_refuses_anything_that_is_not_an_object(payload: str) -> None:
    with pytest.raises(MalformedEventError):
        make(payload).as_mapping()


def test_size_hint_measures_the_payload_not_the_wrapper() -> None:
    assert make("12345").size_hint == 5
    assert make(b"1234").size_hint == 4
    assert make({"a": 1}).size_hint == len(json.dumps({"a": 1}))


def test_raw_event_is_frozen() -> None:
    raw = make("line", cursor="7")
    assert raw.cursor == "7"
    with pytest.raises(FrozenInstanceError):
        raw.cursor = "8"  # type: ignore[misc]


def test_parsed_event_get_replaces_none_with_the_default() -> None:
    raw = make("{}")
    parsed = ParsedEvent(raw=raw, fields={"present": "yes", "blank": None}, source_event_type="x")
    assert parsed.get("present") == "yes"
    assert parsed.get("blank", "fallback") == "fallback"
    assert parsed.get("missing", "fallback") == "fallback"


def test_cycle_report_serialises_every_field(tmp_path: Path) -> None:
    report = CycleReport(
        connector_id="demo",
        fetched=4,
        normalized=3,
        forwarded=3,
        dead_lettered=1,
        duplicates=0,
        cursor="file:893",
    )
    assert report.as_dict() == {
        "connector_id": "demo",
        "fetched": 4,
        "normalized": 3,
        "forwarded": 3,
        "dead_lettered": 1,
        "duplicates": 0,
        "cursor": "file:893",
        "error": None,
    }
