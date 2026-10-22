"""The always-accepting destination: what ``self-test`` and connector development rely on.

The sink has to be trustworthy in a specific way — it must record *exactly* the document a real
destination would have received, redaction included, or the field-mapping check it enables is
worthless. Those are the assertions here, plus the counters ``self-test`` reads.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest

from soc_connectors.config import parse_config
from soc_connectors.exceptions import ConfigError
from soc_connectors.forwarders.base import BaseForwarder, DeliveryResult, ForwarderContext
from soc_connectors.forwarders.sink import SinkForwarder
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.factory import FORWARDER_TYPES, register_builtins
from soc_connectors.schema.ecs_models import EcsEvent, to_document
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.retry import RetryPolicy

pytestmark = pytest.mark.unit

MakeEvent = Callable[..., EcsEvent]
MakeEvents = Callable[..., list[EcsEvent]]
BuildContext = Callable[..., ForwarderContext]


@pytest.fixture
def sink(forwarder_context: BuildContext) -> Callable[..., SinkForwarder]:
    """``sink()`` for the in-memory terminal, ``sink(record_file=...)`` for the recording one."""

    def factory(forwarder_id: str = "recorded", **options: Any) -> SinkForwarder:
        return SinkForwarder(forwarder_context(forwarder_id, options=options))

    return factory


def record_path(tmp_path: Path, name: str = "received.jsonl") -> Path:
    return tmp_path / "sink" / name


def rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


# -- the no-file mode -------------------------------------------------------


def test_without_a_record_file_the_sink_accepts_everything_and_writes_nothing(
    sink: Callable[..., SinkForwarder], tmp_path: Path, make_events: MakeEvents
) -> None:
    destination = sink()
    result = destination.send(make_events(3))
    assert result == DeliveryResult(accepted=3)
    assert result.ok
    assert destination.received == 3
    assert destination.written == 0
    assert list(tmp_path.rglob("*.jsonl")) == []


def test_an_empty_batch_is_accepted_as_zero_and_never_touches_the_output(
    sink: Callable[..., SinkForwarder], tmp_path: Path
) -> None:
    target = record_path(tmp_path)
    destination = sink(record_file=str(target))
    destination.open()
    assert destination.send([]) == DeliveryResult(accepted=0)
    assert destination.written == 0
    assert rows(target) == []


def test_health_reports_the_counters_and_the_absent_record_file(
    sink: Callable[..., SinkForwarder], make_events: MakeEvents
) -> None:
    destination = sink()
    destination.send(make_events(2))
    assert destination.health() == {
        "forwarder_id": "recorded",
        "type": "sink",
        "metrics": {},
        "received": 2,
        "recorded": 0,
        "record_file": None,
    }


# -- the record file --------------------------------------------------------


def test_open_creates_the_directory_for_the_record_file(
    sink: Callable[..., SinkForwarder], tmp_path: Path
) -> None:
    target = tmp_path / "deep" / "nested" / "received.jsonl"
    destination = sink(record_file=str(target))
    assert not target.parent.exists()
    destination.open()
    assert target.parent.is_dir()
    assert not target.exists(), "open() prepares the directory; an empty file would lie"


def test_the_record_file_holds_one_document_per_event_in_ecs_shape(
    sink: Callable[..., SinkForwarder], tmp_path: Path, make_events: MakeEvents
) -> None:
    target = record_path(tmp_path)
    destination = sink(record_file=str(target))
    destination.open()
    destination.send(make_events(2))

    recorded = rows(target)
    assert len(recorded) == 2
    assert recorded[0]["@timestamp"] == "2026-10-22T09:00:00.000Z"
    assert recorded[0]["ecs"]["version"] == "9.5.0"
    assert recorded[0]["event"]["severity"] == 40
    assert recorded[0]["source"]["ip"] == "192.0.2.10"
    assert destination.written == 2


def test_the_recorded_document_is_exactly_what_a_real_destination_would_get(
    sink: Callable[..., SinkForwarder], tmp_path: Path, make_event: MakeEvent
) -> None:
    """The whole point of ``record_file``: it is the field-mapping table under test."""
    target = record_path(tmp_path)
    destination = sink(record_file=str(target))
    destination.open()
    event = make_event()
    destination.send([event])
    assert rows(target) == [to_document(event)]


def test_recorded_documents_respect_the_pipelines_redaction_policy(
    metrics: Metrics, retry_policy: RetryPolicy, make_event: MakeEvent, tmp_path: Path
) -> None:
    target = record_path(tmp_path)
    destination = SinkForwarder(
        ForwarderContext(
            forwarder_id="recorded",
            options={"record_file": str(target)},
            retry_policy=retry_policy,
            metrics=metrics,
            redaction=RedactionSettings(fields=["user.name"], mode="drop", ip_mode="drop"),
        )
    )
    destination.open()
    event = make_event()
    destination.send([event])

    recorded = rows(target)[0]
    assert "user" not in recorded
    assert "source" not in recorded, "an address-less source set says nothing at all"
    assert event.user is not None and event.user.name == "svc-demo", "the event itself is untouched"


def test_the_mask_mode_of_the_same_policy_blanks_the_field_instead_of_dropping_it(
    metrics: Metrics, retry_policy: RetryPolicy, make_event: MakeEvent, tmp_path: Path
) -> None:
    target = record_path(tmp_path)
    destination = SinkForwarder(
        ForwarderContext(
            forwarder_id="recorded",
            options={"record_file": str(target)},
            retry_policy=retry_policy,
            metrics=metrics,
            redaction=RedactionSettings(fields=["source.ip"], mode="mask"),
        )
    )
    destination.open()
    destination.send([make_event()])
    assert rows(target)[0]["source"] == {"ip": "***"}


def test_sends_append_rather_than_replace(
    sink: Callable[..., SinkForwarder], tmp_path: Path, make_events: MakeEvents
) -> None:
    target = record_path(tmp_path)
    destination = sink(record_file=str(target))
    destination.open()
    destination.send(make_events(2))
    destination.send(make_events(2, severity=60))
    assert len(rows(target)) == 4
    assert (destination.received, destination.written) == (4, 4)


def test_the_counters_separate_events_received_from_lines_written(
    sink: Callable[..., SinkForwarder], make_events: MakeEvents
) -> None:
    """``received`` counts accepted events; ``recorded`` counts proof on disk."""
    destination = sink()
    destination.send(make_events(5))
    assert (destination.received, destination.written) == (5, 0)
    assert destination.health()["recorded"] == 0


def test_a_record_file_option_given_as_a_path_object_works(
    sink: Callable[..., SinkForwarder], tmp_path: Path, make_events: MakeEvents
) -> None:
    target = record_path(tmp_path)
    destination = sink(record_file=target)
    destination.send(make_events(1))
    assert destination.written == 1
    assert target.exists()


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_record_file_is_no_record_file(
    sink: Callable[..., SinkForwarder], make_events: MakeEvents, blank: str
) -> None:
    """A blank option must not resolve to the working directory.

    ``Path("")`` is ``.``, so without this guard the sink would try to append JSON to the
    current directory and fail with an ``IsADirectoryError`` that names no setting.
    """
    destination = sink(record_file=blank)
    destination.open()
    assert destination.record_path is None
    destination.send(make_events(2))
    assert (destination.received, destination.written) == (2, 0)
    assert destination.health()["record_file"] is None


# -- the name, and why it is not ``null`` ------------------------------------


def test_the_sink_is_registered_under_its_type_name() -> None:
    register_builtins()
    assert FORWARDER_TYPES["sink"] is SinkForwarder
    assert SinkForwarder.summary


def test_a_destination_typed_null_is_rejected_because_yaml_reads_it_as_none(
    tmp_path: Path,
) -> None:
    """The documented reason the terminal destination is called ``sink``.

    ``type: null`` in YAML becomes Python ``None``, and a destination whose type is ``None``
    fails validation with a message about the field rather than about the missing name.
    """
    with pytest.raises(ConfigError, match=r"destinations\.0\.type"):
        parse_config(
            {
                "pipeline": {"state_dir": str(tmp_path / "state")},
                "sources": [{"id": "demo", "type": "sample_jsonl"}],
                "destinations": [{"id": "void", "type": None}],
            }
        )


def test_a_sink_destination_needs_no_options_at_all(tmp_path: Path) -> None:
    config = parse_config(
        {
            "pipeline": {"state_dir": str(tmp_path / "state")},
            "sources": [{"id": "demo", "type": "sample_jsonl"}],
            "destinations": [{"id": "void", "type": "sink"}],
        }
    )
    assert config.destinations[0].options == {}


class _CountingSink(SinkForwarder):
    type_name: ClassVar[str] = "counting-sink"

    def __init__(self, context: ForwarderContext) -> None:
        super().__init__(context)
        self.sizes: list[int] = []

    def send(self, events: Any) -> DeliveryResult:
        self.sizes.append(len(events))
        return super().send(events)


def test_a_subclass_of_the_sink_keeps_the_record_file_behaviour(
    forwarder_context: BuildContext, tmp_path: Path, make_events: MakeEvents
) -> None:
    target = record_path(tmp_path)
    destination = _CountingSink(forwarder_context("counted", options={"record_file": str(target)}))
    assert isinstance(destination, BaseForwarder)
    destination.send(make_events(3))
    assert destination.sizes == [3]
    assert destination.written == 3
