"""Shared fixtures: synthetic events, deterministic time, and the fakes the pipeline tests need.

Everything here is constructed, never captured: no fixture holds a real tenant id, account id,
address of a system anybody uses, or a credential. The addresses are RFC 5737 documentation
ranges and the names are invented, so the whole suite is safe to publish.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from soc_connectors.config import AppConfig, parse_config
from soc_connectors.connectors.base import BaseConnector, ConnectorContext
from soc_connectors.exceptions import TransientError
from soc_connectors.forwarders.base import BaseForwarder, DeliveryResult, ForwarderContext
from soc_connectors.metrics import Metrics
from soc_connectors.schema.ecs_models import EcsEvent, build_event
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.types import ParsedEvent, RawEvent
from soc_connectors.utils.checkpoint import CheckpointStore
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.rate_limit import NoLimiter, RateLimiter
from soc_connectors.utils.retry import RetryPolicy

BASE_TIME = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)
DOC_IPS = ("192.0.2.10", "198.51.100.22", "203.0.113.7")


class _RecordHandler(logging.Handler):
    """Collect records emitted on one logger.

    ``configure_logging`` sets ``propagate = False``, so pytest's ``caplog`` — which attaches
    to the root logger — never sees them. This attaches directly to the logger under test.
    """

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def capture_logs() -> Iterator[Callable[[str], list[logging.LogRecord]]]:
    """``capture_logs("checkpoint")`` -> the live list of records for that logger.

    The level is lowered for the test and restored after it: an unconfigured logger inherits
    the root's ``WARNING``, which would silently hide the ``info`` lines this captures.
    """
    installed: list[tuple[logging.Logger, _RecordHandler, int]] = []

    def factory(suffix: str = "") -> list[logging.LogRecord]:
        logger = logging.getLogger("soc_connectors" if not suffix else f"soc_connectors.{suffix}")
        handler = _RecordHandler()
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        installed.append((logger, handler, previous))
        return handler.records

    yield factory
    for logger, handler, previous in installed:
        logger.removeHandler(handler)
        logger.setLevel(previous)


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


@pytest.fixture
def retry_policy() -> RetryPolicy:
    return RetryPolicy(max_attempts=3, base_wait_seconds=0, max_wait_seconds=0, jitter_ratio=0)


@pytest.fixture
def clock() -> Callable[[], datetime]:
    """A clock that advances one millisecond per call: ordering without waiting."""
    state = {"step": 0}

    def tick() -> datetime:
        now = BASE_TIME + timedelta(milliseconds=state["step"])
        state["step"] += 1
        return now

    return tick


@pytest.fixture
def make_event() -> Callable[..., EcsEvent]:
    def factory(**overrides: Any) -> EcsEvent:
        fields: dict[str, Any] = {
            "@timestamp": overrides.pop("timestamp", BASE_TIME),
            "event": {
                "kind": "event",
                "category": ["network"],
                "action": "test-action",
                "severity": 42,
            },
            "source": {"ip": DOC_IPS[0]},
            "destination": {"ip": DOC_IPS[1]},
            "user": {"name": "svc-demo"},
        }
        fields.update(overrides)
        return build_event(**fields)

    return factory


@pytest.fixture
def make_events() -> Callable[..., list[EcsEvent]]:
    """``count`` distinct events, each a second later and one severity step up from the last."""

    def factory(count: int, *, severity: int = 40, action_prefix: str = "action") -> list[EcsEvent]:
        return [
            build_event(
                **{
                    "@timestamp": BASE_TIME + timedelta(seconds=index),
                    "event": {
                        "kind": "alert" if severity + index >= 80 else "event",
                        "category": ["network"],
                        "action": f"{action_prefix}-{index}",
                        "severity": severity + index,
                        "id": f"evt-{index}",
                    },
                    "source": {"ip": DOC_IPS[index % len(DOC_IPS)]},
                }
            )
            for index in range(count)
        ]

    return factory


@pytest.fixture
def make_raw() -> Callable[..., RawEvent]:
    def factory(
        payload: Any = "{}", *, connector_id: str = "test", cursor: str | None = None
    ) -> RawEvent:
        text = payload if isinstance(payload, (str, bytes, bytearray)) else json.dumps(payload)
        return RawEvent(
            connector_id=connector_id, payload=text, received_at=BASE_TIME, cursor=cursor
        )

    return factory


@pytest.fixture
def checkpoint_store(tmp_path: Path) -> Callable[[str], CheckpointStore]:
    def factory(
        connector_id: str = "test", *, max_seen_ids: int = 100, path: Path | None = None
    ) -> CheckpointStore:
        return CheckpointStore(
            path or tmp_path / "state" / f"{connector_id}.json",
            connector_id,
            max_seen_ids=max_seen_ids,
        )

    return factory


@pytest.fixture
def dead_letter(tmp_path: Path) -> DeadLetterQueue:
    return DeadLetterQueue(tmp_path / "dead_letter" / "test.jsonl")


class FakeConnector(BaseConnector):
    """A connector with no source behind it: records are supplied, failures are scripted."""

    type_name: ClassVar[str] = "fake"
    summary: ClassVar[str] = "Test double driven by a list of records."

    def __init__(
        self,
        context: ConnectorContext,
        *,
        records: Sequence[Mapping[str, Any]] = (),
        fetch_error: BaseException | None = None,
        raise_after: int | None = None,
        normalize_errors: Mapping[str, BaseException] | None = None,
        normalize_failures: int = 0,
    ) -> None:
        super().__init__(context)
        self.records = list(records)
        self.fetch_error = fetch_error
        self.raise_after = raise_after
        self.normalize_errors = dict(normalize_errors or {})
        #: Raised by the first ``n`` normalizations, then the record succeeds: the only way to
        #: show that a retry is what saved the event rather than a second pass of the loop.
        self.normalize_failures = normalize_failures
        self.fetch_calls = 0
        self.closed = 0

    def fetch(self) -> Iterator[RawEvent]:
        self.fetch_calls += 1
        for index, record in enumerate(self.records):
            if self.fetch_error is not None and self.raise_after == index:
                raise self.fetch_error
            yield self.make_raw(dict(record), cursor=str(index + 1))

    def parse(self, raw: RawEvent) -> ParsedEvent:
        record = raw.as_mapping()
        return ParsedEvent(raw=raw, fields=record, source_event_type="fake")

    def normalize(self, parsed: ParsedEvent) -> EcsEvent:
        action = str(parsed.fields.get("action", "act"))
        if action in self.normalize_errors:
            raise self.normalize_errors[action]
        if self.normalize_failures:
            self.normalize_failures -= 1
            raise TransientError(f"transient failure normalizing {action}")
        severity = int(parsed.fields.get("severity", 42))
        return build_event(
            **{
                "@timestamp": parsed.fields.get("@timestamp", BASE_TIME),
                "event": {"action": action, "severity": severity, "category": ["network"]},
                "source": {"ip": str(parsed.fields.get("source_ip", DOC_IPS[0]))},
            }
        )

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def context_factory(
    checkpoint_store: Callable[..., CheckpointStore],
    metrics: Metrics,
    retry_policy: RetryPolicy,
    clock: Callable[[], datetime],
) -> Callable[..., ConnectorContext]:
    """``context_factory("demo", options={"path": ...})`` — a connector's wiring on demand."""

    def factory(
        connector_id: str = "fake",
        *,
        options: dict[str, Any] | None = None,
        checkpoint: CheckpointStore | None = None,
        limiter: RateLimiter | None = None,
    ) -> ConnectorContext:
        return ConnectorContext(
            connector_id=connector_id,
            options=dict(options or {}),
            checkpoint=checkpoint or checkpoint_store(connector_id),
            retry_policy=retry_policy,
            metrics=metrics,
            limiter=limiter or NoLimiter(),
            clock=clock,
        )

    return factory


@pytest.fixture
def connector_context(context_factory: Callable[..., ConnectorContext]) -> ConnectorContext:
    return context_factory("fake")


@pytest.fixture
def make_connector(
    context_factory: Callable[..., ConnectorContext],
) -> Callable[..., FakeConnector]:
    def factory(connector_id: str = "fake", **behaviour: Any) -> FakeConnector:
        return FakeConnector(context_factory(connector_id), **behaviour)

    return factory


class FakeForwarder(BaseForwarder):
    """A destination whose behaviour the test dictates, one call at a time."""

    type_name: ClassVar[str] = "fake"

    def __init__(
        self,
        context: ForwarderContext,
        *,
        results: Sequence[DeliveryResult | BaseException] | None = None,
    ) -> None:
        super().__init__(context)
        self.batches: list[list[EcsEvent]] = []
        self._results = list(results or [])
        self.opened = False
        self.closed = 0

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed += 1

    def send(self, events: Sequence[EcsEvent]) -> DeliveryResult:
        self.batches.append(list(events))
        if self._results:
            outcome = self._results.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return DeliveryResult(accepted=len(events))

    @property
    def sent_count(self) -> int:
        return sum(len(batch) for batch in self.batches)


@pytest.fixture
def forwarder_context(
    metrics: Metrics, retry_policy: RetryPolicy
) -> Callable[[str], ForwarderContext]:
    def factory(
        forwarder_id: str = "sink",
        *,
        options: dict[str, Any] | None = None,
        redaction: RedactionSettings | None = None,
    ) -> ForwarderContext:
        return ForwarderContext(
            forwarder_id=forwarder_id,
            options=dict(options or {}),
            retry_policy=retry_policy,
            metrics=metrics,
            redaction=redaction or RedactionSettings(),
        )

    return factory


@pytest.fixture
def make_forwarder(
    forwarder_context: Callable[..., ForwarderContext],
) -> Callable[..., FakeForwarder]:
    def factory(
        forwarder_id: str = "sink",
        *,
        results: Sequence[DeliveryResult | BaseException] | None = None,
        **context_kwargs: Any,
    ) -> FakeForwarder:
        return FakeForwarder(forwarder_context(forwarder_id, **context_kwargs), results=results)

    return factory


def write_events(path: Path, records: Sequence[Mapping[str, Any]]) -> Path:
    """Write a JSON Lines file the way a log shipper would: one object per line.

    ``newline="\\n"`` matters on Windows: a connector's cursor is a byte offset, and a file
    written through text-mode newline translation is one byte per line longer than the text
    the test believes it wrote. The framework's own writers use the same setting.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(dict(record), ensure_ascii=False) + "\n" for record in records)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
    return path


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@dataclass(slots=True)
class JsonlFile:
    """A JSON Lines file a test owns: write, append raw bytes, read back.

    ``append_raw`` exists because the interesting cases for a file-tailing connector are the
    malformed ones — a half-written line at EOF, a blank line, a truncated file — and those
    cannot be expressed through ``write``.
    """

    path: Path

    def write(self, records: Sequence[Mapping[str, Any]]) -> Path:
        return write_events(self.path, records)

    def append_raw(self, text: str) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return self.path

    def append(self, records: Sequence[Mapping[str, Any]]) -> Path:
        return self.append_raw(
            "".join(json.dumps(dict(record), ensure_ascii=False) + "\n" for record in records)
        )

    def truncate(self, size: int) -> None:
        with self.path.open("r+b") as handle:
            handle.truncate(size)

    def rows(self) -> list[dict[str, Any]]:
        return read_jsonl(self.path)

    def text(self) -> str:
        return "" if not self.path.exists() else self.path.read_text(encoding="utf-8")


@pytest.fixture
def jsonl_file(tmp_path: Path) -> Callable[[str], JsonlFile]:
    def factory(name: str = "sample.jsonl") -> JsonlFile:
        return JsonlFile(tmp_path / "input" / name)

    return factory


@pytest.fixture
def sample_config(tmp_path: Path) -> Callable[..., AppConfig]:
    """A valid :class:`AppConfig` rooted in ``tmp_path``, with per-test overrides."""

    def factory(**overrides: Any) -> AppConfig:
        raw: dict[str, Any] = {
            "pipeline": {
                "poll_interval_seconds": 1,
                "batch_size": 5,
                "state_dir": str(tmp_path / "state"),
                "dead_letter_dir": str(tmp_path / "dead_letter"),
                "log_format": "json",
            },
            "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
            "sources": [{"id": "fake", "type": "fake", "options": {}}],
            "destinations": [{"id": "sink", "type": "fake", "options": {}}],
        }
        raw.update(overrides)
        return parse_config(raw)

    return factory
