"""The reference connector, tested against the contract a real connector must also satisfy.

The interesting behaviours are the ones a naive file reader gets wrong: a half-written line at
EOF must be left for the next cycle, the cursor is a **byte** offset (so a non-ASCII record
shifts it), a rotated or truncated file must restart rather than crash, and a cycle must not
read the whole world.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from soc_connectors.connectors.base import ConnectorContext
from soc_connectors.connectors.sample_jsonl import CURSOR_SEPARATOR, SampleJsonlConnector
from soc_connectors.exceptions import ConfigError, MalformedEventError
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.types import ParsedEvent, RawEvent

pytestmark = pytest.mark.unit

BASE_TIME = "2026-10-22T09:00:00Z"
SampleConnector = Callable[..., SampleJsonlConnector]
MakeContext = Callable[..., ConnectorContext]


def sample_record(index: int = 0, /, **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "@timestamp": BASE_TIME,
        "event.kind": "event",
        "event.category": "network",
        "event.action": f"demo-action-{index}",
        "event.severity": 42,
        "source.ip": "192.0.2.10",
    }
    record.update(overrides)
    return {key: value for key, value in record.items() if value is not None}


def as_json_line(*records: dict[str, Any]) -> str:
    return "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)


def write_lines(path: Path, text: str) -> None:
    """Write with LF: a byte-offset cursor and text-mode newline translation do not mix."""
    path.write_text(text, encoding="utf-8", newline="\n")


@pytest.fixture
def sample_connector(
    context_factory: MakeContext, jsonl_file: Any
) -> Callable[..., SampleJsonlConnector]:
    """Build the connector over a JSON Lines file the test controls.

    The file is always created, even for an empty list: construction refuses a missing path,
    which is itself a tested rule, and parse/normalize tests need a connector but no records.
    """

    def factory(
        records: list[dict[str, Any]] | None = None, **options: Any
    ) -> SampleJsonlConnector:
        file = jsonl_file()
        file.write([] if records is None else records)
        return SampleJsonlConnector(
            context_factory("demo", options={"path": str(file.path), **options})
        )

    return factory


def cursor_offset(connector: SampleJsonlConnector, raw: RawEvent) -> int:
    assert raw.cursor is not None
    head, separator, tail = raw.cursor.rpartition(CURSOR_SEPARATOR)
    assert separator and head == str(connector.path)
    return int(tail)


# -- construction -----------------------------------------------------------


def test_the_sample_file_must_exist_when_the_connector_is_built(
    tmp_path: Path, context_factory: MakeContext
) -> None:
    missing = tmp_path / "input" / "absent.jsonl"
    with pytest.raises(ConfigError, match=r"sample file .* does not exist"):
        SampleJsonlConnector(context_factory("demo", options={"path": str(missing)}))


def test_the_path_option_is_required(context_factory: MakeContext) -> None:
    with pytest.raises(ConfigError, match="requires option 'path'"):
        SampleJsonlConnector(context_factory("demo", options={}))


def test_a_blank_path_option_is_refused_not_resolved_to_the_working_directory(
    context_factory: MakeContext,
) -> None:
    with pytest.raises(ConfigError, match="requires option 'path'"):
        SampleJsonlConnector(context_factory("demo", options={"path": "   "}))


def test_defaults_for_dataset_module_and_cycle_cap(sample_connector: SampleConnector) -> None:
    connector = sample_connector([sample_record()])
    assert connector.dataset == "sample.events"
    assert connector.id_field is None
    assert connector.max_records == 500


def test_an_existing_empty_file_is_a_valid_source(sample_connector: SampleConnector) -> None:
    assert list(sample_connector([]).fetch()) == []


# -- fetch: the cursor contract ----------------------------------------------


def test_first_fetch_reads_every_terminated_line_and_reports_byte_offsets(
    sample_connector: SampleConnector,
) -> None:
    records = [sample_record(index) for index in range(3)]
    connector = sample_connector(records)
    raw = list(connector.fetch())
    assert len(raw) == 3
    expected = []
    total = 0
    for record in records:
        total += len((json.dumps(record, ensure_ascii=False) + "\n").encode())
        expected.append(total)
    assert [cursor_offset(connector, item) for item in raw] == expected
    assert expected[-1] == connector.path.stat().st_size


def test_the_offset_counts_bytes_not_characters(sample_connector: SampleConnector) -> None:
    """ "é" is two UTF-8 bytes; a line-number cursor would be wrong, a byte offset is not."""
    record = sample_record(0, **{"user.name": "café"})
    connector = sample_connector([record])
    (raw,) = list(connector.fetch())
    assert cursor_offset(connector, raw) == len(
        (json.dumps(record, ensure_ascii=False) + "\n").encode()
    )
    assert connector.path.read_text(encoding="utf-8").count("é") == 1


def test_the_cursor_carries_the_file_so_two_sources_cannot_confuse_each_other(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector([sample_record()])
    (raw,) = list(connector.fetch())
    assert raw.cursor is not None
    assert raw.cursor.startswith(f"{connector.path}{CURSOR_SEPARATOR}")
    assert raw.connector_id == "demo"


def test_resuming_from_the_stored_cursor_reads_only_what_was_appended(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector([sample_record(0), sample_record(1)])
    first = list(connector.fetch())
    assert len(first) == 2
    connector.checkpoint.advance(cursor=first[-1].cursor)
    assert list(connector.fetch()) == []

    write_lines(connector.path, as_json_line(*[sample_record(index) for index in range(4)]))
    appended = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in appended] == [
        "demo-action-2",
        "demo-action-3",
    ]


def test_an_unterminated_last_line_is_left_for_the_next_cycle(
    sample_connector: SampleConnector,
) -> None:
    """A shipper mid-write must not be read as a truncated JSON document."""
    connector = sample_connector([sample_record(0)])
    complete = connector.path.read_text(encoding="utf-8")
    half = json.dumps(sample_record(1), ensure_ascii=False)
    write_lines(connector.path, complete + half[:20])

    read = list(connector.fetch())
    assert len(read) == 1
    assert cursor_offset(connector, read[0]) == len(complete.encode())
    connector.checkpoint.advance(cursor=read[0].cursor)

    write_lines(connector.path, complete + half + "\n")
    finished = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in finished] == ["demo-action-1"]


def test_blank_lines_are_skipped_without_rewinding_the_cursor(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    connector.path.write_text(
        "\n" + as_json_line(sample_record(0)) + "\n" + as_json_line(sample_record(1)),
        encoding="utf-8",
    )
    read = list(connector.fetch())
    assert len(read) == 2
    assert cursor_offset(connector, read[-1]) == connector.path.stat().st_size


def test_a_cycle_stops_at_the_record_cap_and_resumes_exactly_there(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(
        [sample_record(index) for index in range(5)], max_records_per_cycle=2
    )
    first = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in first] == [
        "demo-action-0",
        "demo-action-1",
    ]
    connector.checkpoint.advance(cursor=first[-1].cursor)
    second = list(connector.fetch())
    assert len(second) == 2
    connector.checkpoint.advance(cursor=second[-1].cursor)
    third = list(connector.fetch())
    assert len(third) == 1
    connector.checkpoint.advance(cursor=third[-1].cursor)
    assert list(connector.fetch()) == [], "EOF, not a cap: the source is drained"


def test_a_file_that_shrank_below_the_cursor_restarts_and_says_so(
    sample_connector: SampleConnector, capture_logs: Callable[[str], list[Any]]
) -> None:
    connector = sample_connector([sample_record(0), sample_record(1)])
    read = list(connector.fetch())
    connector.checkpoint.advance(cursor=read[-1].cursor)
    logs = capture_logs("connector.demo")

    write_lines(connector.path, as_json_line(sample_record(9)))
    restarted = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in restarted] == ["demo-action-9"]
    warnings = [record for record in logs if "restarting" in record.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].levelname == "WARNING"


def test_a_copytruncate_rotation_restarts_from_the_beginning(
    sample_connector: SampleConnector, capture_logs: Callable[[str], list[Any]]
) -> None:
    """``logrotate`` with ``copytruncate`` leaves the same inode but a shorter file."""
    connector = sample_connector([sample_record(0), sample_record(1)])
    read = list(connector.fetch())
    connector.checkpoint.advance(cursor=read[-1].cursor)
    logs = capture_logs("connector.demo")

    first_line = len(as_json_line(sample_record(0)).encode())
    with connector.path.open("r+b") as handle:
        handle.truncate(first_line)

    restarted = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in restarted] == ["demo-action-0"]
    assert any("restarting" in record.getMessage() for record in logs)


def test_a_crlf_file_is_read_correctly_even_though_every_offset_shifted(
    sample_connector: SampleConnector,
) -> None:
    """A Windows shipper writes CRLF; the cursor counts those bytes too, and must not skip lines."""
    connector = sample_connector(None)
    write_lines(
        connector.path, as_json_line(sample_record(0), sample_record(1)).replace("\n", "\r\n")
    )

    read = list(connector.fetch())
    assert [json.loads(item.as_text())["event.action"] for item in read] == [
        "demo-action-0",
        "demo-action-1",
    ]
    assert cursor_offset(connector, read[-1]) == connector.path.stat().st_size
    assert all("\r" not in item.as_text() for item in read), "strip() removes the carriage return"


def test_a_source_that_disappears_between_cycles_fails_the_cycle_not_the_process(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector([sample_record()])
    connector.path.unlink()
    with pytest.raises(ConfigError, match="disappeared"):
        list(connector.fetch())


def test_an_unparsable_cursor_is_reported_with_the_connector_id(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector([sample_record()])
    connector.checkpoint.advance(cursor="nonsense-without-a-number")
    with pytest.raises(ConfigError, match=r"demo.*unparsable cursor"):
        list(connector.fetch())


def test_a_cursor_that_is_only_a_number_still_works(sample_connector: SampleConnector) -> None:
    """``rpartition`` tolerates a bare offset — older state files carried no path prefix."""
    connector = sample_connector([sample_record(0), sample_record(1)])
    first = list(connector.fetch())
    connector.checkpoint.advance(cursor=str(cursor_offset(connector, first[0])))
    assert len(list(connector.fetch())) == 1


def test_payload_text_is_the_line_as_read_with_the_json_left_intact(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector([sample_record(0)])
    (raw,) = list(connector.fetch())
    assert raw.as_text().startswith("{")
    assert raw.size_hint == len(json.dumps(sample_record(0), ensure_ascii=False))


# -- parse ------------------------------------------------------------------


def test_parse_keeps_the_source_field_names_and_uses_event_kind(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    raw = connector.make_raw(json.dumps(sample_record(0, **{"event.kind": "alert"})))
    parsed = connector.parse(raw)
    assert isinstance(parsed, ParsedEvent)
    assert parsed.source_event_type == "alert"
    assert parsed.fields["event.action"] == "demo-action-0"
    assert parsed.raw is raw


def test_parse_defaults_the_source_event_type_when_the_record_has_no_kind(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    parsed = connector.parse(connector.make_raw(json.dumps({"event.action": "x"})))
    assert parsed.source_event_type == "event"


def test_parse_of_a_non_json_line_raises_a_typed_malformed_error(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    with pytest.raises(MalformedEventError, match="not valid JSON"):
        connector.parse(connector.make_raw("{ this line is deliberately not JSON"))


def test_parse_of_a_json_array_is_refused_because_a_record_must_be_an_object(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    with pytest.raises(MalformedEventError, match="expected a JSON object"):
        connector.parse(connector.make_raw(json.dumps([1, 2, 3])))


# -- normalize --------------------------------------------------------------


def test_normalize_maps_the_dotted_ecs_paths_and_adds_the_dataset_defaults(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    event = connector.normalize(connector.parse(connector.make_raw(json.dumps(sample_record(0)))))
    assert isinstance(event, EcsEvent)
    assert event.event.dataset == "sample.events"
    assert event.event.module == "sample"
    assert event.event.action == "demo-action-0"
    assert event.source is not None and event.source.ip == "192.0.2.10"
    assert event.score == 42


def test_normalize_keeps_the_original_record_under_raw(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    record = sample_record(0)
    event = connector.normalize(connector.parse(connector.make_raw(json.dumps(record))))
    assert event.raw == record


def test_the_configured_dataset_wins_over_the_default_but_not_the_source(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None, dataset="custom.set")
    inferred = connector.normalize(connector.parse(connector.make_raw(json.dumps(sample_record()))))
    assert inferred.event.dataset == "custom.set"
    explicit = connector.normalize(
        connector.parse(
            connector.make_raw(json.dumps(sample_record(**{"event.dataset": "source.set"})))
        )
    )
    assert explicit.event.dataset == "source.set", "setdefault, not overwrite"


def test_the_id_field_option_promotes_the_source_id_into_event_id(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None, id_field="event.action")
    event = connector.normalize(connector.parse(connector.make_raw(json.dumps(sample_record(3)))))
    assert event.event.id == "demo-action-3"
    assert event.identity_key() == "sample.events:demo-action-3"


def test_an_id_field_absent_from_the_record_is_ignored_not_invented(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None, id_field="event.id")
    event = connector.normalize(connector.parse(connector.make_raw(json.dumps(sample_record()))))
    assert event.event.id is None


def test_normalize_rejects_a_source_field_that_is_not_an_ecs_path(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    with pytest.raises(MalformedEventError, match="not an ECS path"):
        connector.normalize(connector.parse(connector.make_raw(json.dumps({"srcip": "192.0.2.1"}))))


def test_normalize_reports_a_schema_violation_as_a_malformed_event(
    sample_connector: SampleConnector,
) -> None:
    connector = sample_connector(None)
    with pytest.raises(MalformedEventError, match="not a valid ECS document"):
        connector.normalize(connector.parse(connector.make_raw(json.dumps({"source.port": 99999}))))


def test_two_cycles_of_the_same_line_produce_the_same_identity(
    sample_connector: SampleConnector,
) -> None:
    """Dedup depends on it: the hash must not include the cursor or the receive time."""
    connector = sample_connector(None)
    raw = json.dumps(sample_record(0))
    first = connector.normalize(connector.parse(connector.make_raw(raw, cursor="a:1")))
    second = connector.normalize(connector.parse(connector.make_raw(raw, cursor="a:2")))
    assert first.identity_key() == second.identity_key()
