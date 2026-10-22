"""The runner: the order of operations *is* the guarantee.

State is written **last**, a bad record is dead-lettered rather than fatal, one source's outage
stops only that source, and de-duplication happens before delivery. Each of those is a separate
behaviour with a separate failure mode, so each gets its own test against a clock and a
destination the test controls.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from soc_connectors.config import AppConfig
from soc_connectors.exceptions import (
    CheckpointError,
    MalformedEventError,
    PermanentError,
    TransientError,
)
from soc_connectors.forwarders.base import BaseForwarder, DeliveryResult
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.dispatcher import Dispatcher, Route
from soc_connectors.pipeline.runner import PipelineRunner, RunnerState, SourceRuntime
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.types import CycleReport
from soc_connectors.utils.checkpoint import CheckpointStore
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.retry import RetryPolicy

pytestmark = pytest.mark.unit

MakeConnector = Callable[..., Any]
MakeForwarder = Callable[..., Any]
ForwarderContexts = Callable[..., Any]
BuildConfig = Callable[..., AppConfig]
Checkpoints = Callable[..., CheckpointStore]
Probe = Callable[[], Any]

#: Every event in this module is stamped from here, so an age rule is a subtraction the test
#: can see rather than a race against the wall clock.
TIMESTAMP = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)


class Clock:
    """A clock the test advances: batching by age becomes arithmetic instead of sleeping."""

    def __init__(self, start: datetime = TIMESTAMP) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def record(index: int = 0, /, *, ts: datetime | None = None, **fields: Any) -> dict[str, Any]:
    """One synthetic source record: a distinct action and timestamp unless overridden."""
    data: dict[str, Any] = {
        "action": f"act-{index}",
        "severity": 42,
        "@timestamp": TIMESTAMP + timedelta(seconds=index),
    }
    if ts is not None:
        data["@timestamp"] = ts
    data.update(fields)
    return data


def records(count: int, /, **fields: Any) -> list[dict[str, Any]]:
    return [record(index, **fields) for index in range(count)]


class _PeekingForwarder(BaseForwarder):
    """A destination that reports what the state file said at the exact moment of delivery."""

    type_name: ClassVar[str] = "peek"

    def __init__(self, context: Any, *, probe: Probe | None = None) -> None:
        super().__init__(context)
        self.batches: list[list[EcsEvent]] = []
        self.probe = probe
        self.observed: list[Any] = []

    def send(self, events: Sequence[EcsEvent]) -> DeliveryResult:
        self.batches.append(list(events))
        self.observed.append(None if self.probe is None else self.probe())
        return DeliveryResult(accepted=len(events))


class _CountingSleeper:
    """Stands in for the poll wait so a loop test can see how often it would have slept."""

    def __init__(self, stop_after: int | None = None) -> None:
        self.calls: list[float] = []
        self.stop_after = stop_after

    def __call__(self, seconds: float) -> bool:
        self.calls.append(seconds)
        return self.stop_after is not None and len(self.calls) >= self.stop_after


@dataclass(slots=True)
class SourceSpec:
    """One connector and the rules the pipeline would have built around it."""

    id: str = "fake"
    records: list[dict[str, Any]] = field(default_factory=list)
    batch_size: int = 5
    destinations: tuple[str, ...] | None = None
    retry_policy: RetryPolicy | None = None
    fetch_error: BaseException | None = None
    raise_after: int | None = None
    normalize_errors: dict[str, BaseException] | None = None
    normalize_failures: int = 0


@dataclass(slots=True)
class DestinationSpec:
    id: str = "sink"
    results: list[Any] = field(default_factory=list)
    forwarder: Any | None = None
    severity_min: int = 0
    batch_size: int = 200
    retry_policy: RetryPolicy | None = None


@dataclass(slots=True)
class Harness:
    """Everything a runner test wants to look at afterwards — a report alone is not enough."""

    runner: PipelineRunner
    config: AppConfig
    metrics: Metrics
    dispatcher: Dispatcher
    runtimes: list[SourceRuntime]
    forwarders: dict[str, Any]
    clock: Clock
    state_dir: Path

    @property
    def runtime(self) -> SourceRuntime:
        return self.runtimes[0]

    @property
    def connector(self) -> Any:
        return self.runtimes[0].connector

    @property
    def checkpoint(self) -> CheckpointStore:
        return self.runtimes[0].checkpoint

    @property
    def dead_letter(self) -> DeadLetterQueue:
        return self.runtimes[0].dead_letter

    @property
    def forwarder(self) -> Any:
        return self.forwarders[self.dispatcher.routes[0].forwarder.id]

    def batch_sizes(self, destination: str = "sink") -> list[int]:
        return [len(batch) for batch in self.forwarders[destination].batches]

    def state_file(self, source_id: str = "fake") -> Path:
        return self.state_dir / f"{source_id}.json"

    def persisted(self, source_id: str = "fake") -> dict[str, Any]:
        """The state file as the disk sees it. Missing state is a test failure, not a ``None``."""
        path = self.state_file(source_id)
        assert path.exists(), f"no state file at {path}"
        decoded = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(decoded, dict)
        return decoded

    def persisted_or_none(self, source_id: str = "fake") -> dict[str, Any] | None:
        path = self.state_file(source_id)
        if not path.exists():
            return None
        decoded = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(decoded, dict)
        return decoded


HarnessFactory = Callable[..., Harness]


def _no_wait(_seconds: float) -> None:
    """Retry backoff that returns immediately, so a retry test stays a fast test."""


@pytest.fixture
def harness(
    tmp_path: Path,
    metrics: Metrics,
    retry_policy: RetryPolicy,
    sample_config: BuildConfig,
    make_connector: MakeConnector,
    make_forwarder: MakeForwarder,
    forwarder_context: ForwarderContexts,
    checkpoint_store: Checkpoints,
) -> HarnessFactory:
    """``harness(records=records(5), batch_size=2)`` — a pipeline with the test in every socket.

    The state and dead-letter paths are the ones the factory would have chosen, so a test can
    read what the pipeline actually wrote instead of trusting the counters it returned.
    """

    def factory(
        *,
        records: Sequence[Mapping[str, Any]] | None = None,
        sources: Sequence[SourceSpec] | None = None,
        destinations: Sequence[DestinationSpec] | None = None,
        forwarder: Any | None = None,
        results: Sequence[Any] | None = None,
        probe: Probe | None = None,
        batch_size: int = 5,
        poll_interval_seconds: float = 1.0,
        source_destinations: tuple[str, ...] | None = None,
        source_retry: RetryPolicy | None = None,
        **behaviour: Any,
    ) -> Harness:
        specs = (
            [
                SourceSpec(
                    records=[dict(item) for item in records or ()],
                    batch_size=batch_size,
                    destinations=source_destinations,
                    retry_policy=source_retry,
                    **behaviour,
                )
            ]
            if sources is None
            else list(sources)
        )
        first_destination = "sink" if destinations is None else destinations[0].id
        dest_specs = (
            [
                DestinationSpec(
                    id=first_destination,
                    forwarder=forwarder
                    or (
                        _PeekingForwarder(forwarder_context(first_destination), probe=probe)
                        if probe is not None
                        else None
                    ),
                    results=list(results or ()),
                )
            ]
            if destinations is None
            else list(destinations)
        )
        state_dir = tmp_path / "state"
        config = sample_config(
            pipeline={
                "poll_interval_seconds": poll_interval_seconds,
                "batch_size": batch_size,
                "state_dir": str(state_dir),
                "dead_letter_dir": str(tmp_path / "dead_letter"),
                "log_format": "json",
            },
            sources=[{"id": spec.id, "type": "fake"} for spec in specs],
            destinations=[{"id": item.id, "type": "fake"} for item in dest_specs],
        )
        clock = Clock()
        runtimes: list[SourceRuntime] = []
        for spec, source_config in zip(specs, config.sources, strict=True):
            runtimes.append(
                SourceRuntime(
                    config=source_config,
                    connector=make_connector(
                        spec.id,
                        records=spec.records,
                        fetch_error=spec.fetch_error,
                        raise_after=spec.raise_after,
                        normalize_errors=spec.normalize_errors,
                        normalize_failures=spec.normalize_failures,
                    ),
                    dead_letter=DeadLetterQueue(tmp_path / "dead_letter" / f"{spec.id}.jsonl"),
                    checkpoint=checkpoint_store(spec.id),
                    retry_policy=spec.retry_policy or retry_policy,
                    batch_size=spec.batch_size,
                    destinations=spec.destinations,
                )
            )
        forwarders: dict[str, Any] = {}
        route_objs: list[Route] = []
        for item in dest_specs:
            prepared = item.forwarder or make_forwarder(item.id, results=item.results)
            forwarders[item.id] = prepared
            route_objs.append(
                Route(
                    forwarder=prepared,
                    severity_min=item.severity_min,
                    batch_size=item.batch_size,
                    retry_policy=item.retry_policy or retry_policy,
                )
            )
        dispatcher = Dispatcher(route_objs, metrics=metrics)
        runner = PipelineRunner(
            config=config,
            sources=runtimes,
            dispatcher=dispatcher,
            metrics=metrics,
            clock=clock,
            retry_sleep=_no_wait,
        )
        return Harness(
            runner=runner,
            config=config,
            metrics=metrics,
            dispatcher=dispatcher,
            runtimes=runtimes,
            forwarders=forwarders,
            clock=clock,
            state_dir=state_dir,
        )

    return factory


# -- one cycle ---------------------------------------------------------------


def test_run_cycle_reports_each_source_in_order(harness: HarnessFactory) -> None:
    built = harness(
        sources=[
            SourceSpec(id="alpha", records=records(1)),
            SourceSpec(id="beta", records=records(2)),
        ]
    )
    reports = built.runner.run_cycle()
    assert [report.connector_id for report in reports] == ["alpha", "beta"]
    assert [report.fetched for report in reports] == [1, 2]


def test_a_healthy_cycle_counts_every_stage(harness: HarnessFactory) -> None:
    report = harness(records=records(3)).runner.run_cycle()[0]
    assert report.fetched == 3
    assert report.normalized == 3
    assert report.forwarded == 3
    assert report.duplicates == 0
    assert report.dead_lettered == 0
    assert report.error is None
    assert report.cursor == "3"


def test_the_same_counters_are_recorded_as_metrics(harness: HarnessFactory) -> None:
    built = harness(records=records(2))
    built.runner.run_cycle()
    counts = built.metrics.for_source("fake")
    assert counts["fetched"] == 2
    assert counts["forwarded"] == 2
    assert counts["cycles"] == 1


def test_a_quiet_source_reports_an_empty_cycle(harness: HarnessFactory) -> None:
    report = harness(records=[]).runner.run_cycle()[0]
    assert (report.fetched, report.forwarded, report.cursor) == (0, 0, None)


def test_a_cycle_complete_line_carries_the_report(
    harness: HarnessFactory, capture_logs: Callable[[str], list[Any]]
) -> None:
    lines = capture_logs("runner")
    built = harness(records=records(1))
    report = built.runner.run_cycle()[0]
    complete = [item for item in lines if item.getMessage() == "cycle complete"]
    assert complete[0].report == report.as_dict()


# -- batching ----------------------------------------------------------------


def test_a_full_batch_flushes_mid_cycle(harness: HarnessFactory) -> None:
    built = harness(records=records(5), batch_size=2)
    report = built.runner.run_cycle()[0]
    assert built.batch_sizes() == [2, 2, 1]
    assert report.forwarded == 5


def test_a_partial_tail_is_flushed_when_the_source_runs_dry(harness: HarnessFactory) -> None:
    built = harness(records=records(4), batch_size=3)
    built.runner.run_cycle()
    assert built.batch_sizes() == [3, 1]


def test_an_aged_batch_flushes_on_arrival(harness: HarnessFactory) -> None:
    # The accumulator's clock is the runner's, so this is the age rule firing inside a cycle —
    # not a test that passes because the machine was slow.
    built = harness(records=records(3), poll_interval_seconds=1.0)
    built.clock.advance(60)
    built.runner.run_cycle()
    assert built.batch_sizes() == [1, 1, 1]


def test_a_fresh_batch_waits_for_the_trailing_flush(harness: HarnessFactory) -> None:
    built = harness(records=records(3), poll_interval_seconds=1.0)
    built.runner.run_cycle()
    assert built.batch_sizes() == [3]


# -- de-duplication ----------------------------------------------------------


def test_two_identical_records_in_one_cycle_deliver_once(harness: HarnessFactory) -> None:
    built = harness(records=[record(0), record(0)])
    report = built.runner.run_cycle()[0]
    assert report.fetched == 2
    assert report.normalized == 1
    assert report.duplicates == 1
    assert built.batch_sizes() == [1]
    assert built.metrics.for_source("fake")["duplicated"] == 1


def test_a_second_cycle_rereads_the_source_and_delivers_nothing(harness: HarnessFactory) -> None:
    # The fake re-reads from the start on every cycle, which is exactly the at-least-once
    # replay the seen-id window exists to absorb.
    built = harness(records=records(3))
    built.runner.run_cycle()
    second = built.runner.run_cycle()[0]
    assert (second.fetched, second.normalized, second.duplicates) == (3, 0, 3)
    assert len(built.forwarder.batches) == 1


def test_a_restart_replays_the_window_without_re_delivering(harness: HarnessFactory) -> None:
    harness(records=records(2)).runner.run_cycle()
    restarted = harness(records=records(2))
    report = restarted.runner.run_cycle()[0]
    assert report.duplicates == 2
    assert restarted.batch_sizes() == []


# -- records that fail -------------------------------------------------------


def test_a_malformed_record_is_dead_lettered_not_fatal(harness: HarnessFactory) -> None:
    built = harness(
        records=[record(1, action="bad"), record(2)],
        normalize_errors={"bad": MalformedEventError("event.severity is not a number")},
    )
    report = built.runner.run_cycle()[0]
    assert (report.fetched, report.dead_lettered, report.forwarded) == (2, 1, 1)
    assert report.error is None
    entries = list(built.dead_letter.records())
    assert [entry["stage"] for entry in entries] == ["normalize"]
    assert entries[0]["reason"] == "event.severity is not a number"
    assert entries[0]["connector_id"] == "fake"
    assert entries[0]["error_type"] == "MalformedEventError"


def test_a_crash_that_is_not_a_data_error_is_still_dead_lettered(harness: HarnessFactory) -> None:
    built = harness(
        records=records(1, action="boom"),
        normalize_errors={"boom": RuntimeError("parser bug")},
    )
    report = built.runner.run_cycle()[0]
    assert report.dead_lettered == 1
    entry = next(built.dead_letter.records())
    assert entry["stage"] == "source"
    assert entry["error_type"] == "RuntimeError"


def test_the_dead_letter_keeps_the_payload_and_the_cursor(harness: HarnessFactory) -> None:
    built = harness(
        records=[record(1), record(2, action="bad")],
        normalize_errors={"bad": MalformedEventError("unusable")},
    )
    built.runner.run_cycle()
    entry = next(built.dead_letter.records())
    # The cursor is the dead record's own position, so a replay can start from it.
    assert entry["cursor"] == "2"
    assert json.loads(entry["payload"])["action"] == "bad"


def test_a_transient_normalizer_failure_is_retried_then_delivered(harness: HarnessFactory) -> None:
    built = harness(records=records(1), normalize_failures=1)
    report = built.runner.run_cycle()[0]
    assert (report.forwarded, report.dead_lettered) == (1, 0)
    assert built.metrics.for_source("fake")["retried"] == 1


def test_a_normalizer_keeps_retrying_until_the_policy_runs_out(harness: HarnessFactory) -> None:
    built = harness(records=records(1), normalize_failures=99)
    report = built.runner.run_cycle()[0]
    # The shared policy allows three attempts: two retries, then the dead letter.
    assert built.metrics.for_source("fake")["retried"] == 2
    assert (report.dead_lettered, report.forwarded) == (1, 0)


def test_a_source_retry_policy_is_the_one_the_runner_uses(harness: HarnessFactory) -> None:
    built = harness(
        records=records(1),
        normalize_failures=99,
        source_retry=RetryPolicy(max_attempts=1, base_wait_seconds=0),
    )
    report = built.runner.run_cycle()[0]
    assert report.dead_lettered == 1
    assert "retried" not in built.metrics.for_source("fake")


# -- a source that fails -----------------------------------------------------


def test_a_source_that_never_opens_ends_the_cycle_with_an_error(harness: HarnessFactory) -> None:
    built = harness(records=records(4), fetch_error=TransientError("endpoint down"), raise_after=0)
    report = built.runner.run_cycle()[0]
    assert report.error == "TransientError: endpoint down"
    assert (report.fetched, report.forwarded, report.cursor) == (0, 0, None)
    assert built.metrics.for_source("fake")["errors"] == 1


def test_a_source_failure_mid_cycle_keeps_what_was_already_done(harness: HarnessFactory) -> None:
    built = harness(records=records(4), fetch_error=TransientError("endpoint down"), raise_after=2)
    report = built.runner.run_cycle()[0]
    assert report.error == "TransientError: endpoint down"
    assert (report.fetched, report.forwarded, report.cursor) == (2, 2, "2")
    assert built.persisted()["cursor"] == "2"


def test_an_oserror_is_treated_like_a_source_failure(harness: HarnessFactory) -> None:
    built = harness(records=records(3), fetch_error=OSError("file vanished"), raise_after=1)
    report = built.runner.run_cycle()[0]
    assert report.error == "OSError: file vanished"
    assert built.persisted()["cursor"] == "1"


def test_a_bug_is_not_mistaken_for_a_source_failure(harness: HarnessFactory) -> None:
    built = harness(records=records(3), fetch_error=RuntimeError("bug"), raise_after=1)
    with pytest.raises(RuntimeError, match="bug"):
        built.runner.run_cycle()
    # Nothing was delivered and no state was written: the whole window replays on the next
    # start, which is the price of never advancing past a cycle nobody finished.
    assert built.batch_sizes() == []
    assert built.persisted_or_none() is None


def test_one_source_failing_does_not_stop_the_others(harness: HarnessFactory) -> None:
    built = harness(
        sources=[
            SourceSpec(
                id="alpha",
                records=records(1),
                fetch_error=TransientError("alpha is down"),
                raise_after=0,
            ),
            SourceSpec(id="beta", records=records(2)),
        ]
    )
    reports = {report.connector_id: report for report in built.runner.run_cycle()}
    assert reports["alpha"].error == "TransientError: alpha is down"
    assert reports["alpha"].fetched == 0
    assert reports["beta"].forwarded == 2


def test_a_source_failure_is_logged_with_its_identity(
    harness: HarnessFactory, capture_logs: Callable[[str], list[Any]]
) -> None:
    lines = capture_logs("runner")
    built = harness(
        records=records(1),
        fetch_error=PermanentError("403 forbidden"),
        raise_after=0,
    )
    built.runner.run_cycle()
    failure = [item for item in lines if item.getMessage() == "source cycle failed"]
    assert failure[0].connector_id == "fake"
    assert failure[0].error_type == "PermanentError"
    assert failure[0].cursor is None


# -- the destination ---------------------------------------------------------


def test_a_destination_outage_fails_events_and_dead_letters_them(harness: HarnessFactory) -> None:
    built = harness(records=records(3), results=[PermanentError("index closed")])
    report = built.runner.run_cycle()[0]
    assert (report.forwarded, report.dead_lettered) == (0, 3)
    assert report.error == "sink: index closed"
    entries = list(built.dead_letter.records())
    assert [entry["stage"] for entry in entries] == ["forward"] * 3
    assert {entry["connector_id"] for entry in entries} == {"sink"}


def test_a_destination_that_recovers_loses_nothing(harness: HarnessFactory) -> None:
    built = harness(
        records=records(2),
        results=[TransientError("connection reset"), DeliveryResult(accepted=2)],
    )
    report = built.runner.run_cycle()[0]
    assert (report.forwarded, report.dead_lettered) == (2, 0)
    assert built.metrics.for_source("sink")["retried"] == 1


def test_a_refusal_counts_as_a_lost_event_not_a_delivered_one(harness: HarnessFactory) -> None:
    # Two units again: one delivery record was refused, so one *event* did not land and the
    # cycle forwarded 2 of 3 — and a refusal that names no identity is still an error line.
    built = harness(
        records=records(3),
        results=[DeliveryResult(accepted=2, rejected=[{"reason": "mapper"}])],
    )
    report = built.runner.run_cycle()[0]
    assert (report.forwarded, report.dead_lettered) == (2, 1)
    assert report.error == "sink: refused 1 document(s) without naming their identity"
    assert next(built.dead_letter.records())["stage"] == "forward"


def test_a_severity_floor_is_a_skip_not_a_failure(harness: HarnessFactory) -> None:
    built = harness(
        records=[record(1, severity=42), record(2, severity=70)],
        destinations=[DestinationSpec(id="sink", severity_min=60)],
    )
    report = built.runner.run_cycle()[0]
    assert built.batch_sizes() == [1]
    assert report.forwarded == 2


def test_only_the_configured_destinations_receive_the_batch(harness: HarnessFactory) -> None:
    built = harness(
        records=records(2),
        destinations=[DestinationSpec(id="es"), DestinationSpec(id="hive")],
        source_destinations=("es",),
    )
    report = built.runner.run_cycle()[0]
    assert built.batch_sizes("es") == [2]
    assert built.forwarders["hive"].batches == []
    assert report.forwarded == 2


def test_a_route_batch_size_splits_below_the_source_batch(harness: HarnessFactory) -> None:
    built = harness(records=records(4), destinations=[DestinationSpec(id="sink", batch_size=1)])
    built.runner.run_cycle()
    assert built.batch_sizes() == [1, 1, 1, 1]


# -- state written last ------------------------------------------------------


def test_state_is_persisted_only_after_delivery(harness: HarnessFactory, tmp_path: Path) -> None:
    state = tmp_path / "state" / "fake.json"

    def read_cursor() -> Any:
        if not state.exists():
            return None
        return json.loads(state.read_text(encoding="utf-8")).get("cursor")

    built = harness(records=records(3), probe=read_cursor)
    report = built.runner.run_cycle()[0]
    assert report.forwarded == 3
    # At the moment of delivery the disk still held nothing; the runner writes state afterwards.
    assert built.forwarder.observed == [None]
    assert built.persisted()["cursor"] == "3"


def test_a_second_delivery_sees_the_state_the_first_cycle_wrote(
    harness: HarnessFactory, tmp_path: Path
) -> None:
    state = tmp_path / "state" / "fake.json"

    def cursor_on_disk() -> Any:
        if not state.exists():
            return None
        return json.loads(state.read_text(encoding="utf-8")).get("cursor")

    built = harness(records=records(3), probe=cursor_on_disk)
    built.runner.run_cycle()
    built.connector.records.append(record(9))
    built.runner.run_cycle()
    # The second batch went out against a checkpoint that already held the first cycle's
    # position: state is written after the send, never before it.
    assert built.forwarder.observed == [None, "3"]
    assert cursor_on_disk() == "4"


def test_a_state_write_failure_does_not_lose_delivered_events(
    harness: HarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = harness(records=records(2))

    def explode() -> None:
        raise CheckpointError("disk full")

    monkeypatch.setattr(built.runtime.checkpoint, "save", explode)
    report = built.runner.run_cycle()[0]
    assert built.batch_sizes() == [2]
    assert report.error == "checkpoint save failed: disk full"
    assert built.persisted_or_none() is None


def test_an_empty_cycle_does_not_touch_the_state_file(harness: HarnessFactory) -> None:
    built = harness(records=[])
    report = built.runner.run_cycle()[0]
    assert report.fetched == 0
    assert built.persisted_or_none() is None


def test_a_cycle_that_reads_nothing_keeps_the_persisted_cursor(harness: HarnessFactory) -> None:
    harness(records=records(2)).runner.run_cycle()
    restarted = harness(records=[])
    report = restarted.runner.run_cycle()[0]
    assert report.cursor == "2"
    assert restarted.forwarder.batches == []


def test_the_newest_timestamp_wins_not_the_last_event(harness: HarnessFactory) -> None:
    newer = TIMESTAMP + timedelta(minutes=5)
    built = harness(records=[record(2, ts=newer), record(1, ts=TIMESTAMP)])
    built.runner.run_cycle()
    assert built.checkpoint.state.last_timestamp == newer
    assert built.persisted()["cursor"] == "2"


# -- the loop ----------------------------------------------------------------


def test_run_once_performs_one_cycle_and_never_sleeps(harness: HarnessFactory) -> None:
    sleeper = _CountingSleeper()
    built = harness(records=records(1))
    built.runner.sleeper = sleeper
    state = built.runner.run(once=True)
    assert sleeper.calls == []
    assert (state.cycles, state.fetched, state.forwarded) == (1, 1, 1)
    assert state.stopped is False


def test_max_cycles_stops_after_the_requested_number(harness: HarnessFactory) -> None:
    sleeper = _CountingSleeper()
    built = harness(records=records(1), poll_interval_seconds=7.0)
    built.runner.sleeper = sleeper
    state = built.runner.run(max_cycles=3)
    assert sleeper.calls == [7.0, 7.0]
    assert state.cycles == 3
    assert state.fetched == 3
    assert state.forwarded == 1
    assert state.duplicates == 2


def test_a_stop_request_during_the_sleep_ends_the_run(harness: HarnessFactory) -> None:
    built = harness(records=records(1))
    built.runner.sleeper = _CountingSleeper(stop_after=1)
    state = built.runner.run()
    assert (state.cycles, state.stopped) == (1, True)


def test_request_stop_wakes_the_default_sleeper_immediately(harness: HarnessFactory) -> None:
    built = harness()
    built.runner.request_stop()
    assert built.runner.sleeper(3600) is True


def test_a_stop_signal_still_finishes_the_cycle_in_progress(harness: HarnessFactory) -> None:
    # Graceful shutdown means "finish the cycle you are in", not "drop the buffer".
    built = harness(records=records(2))
    built.runner.request_stop()
    state = built.runner.run()
    assert (state.cycles, state.stopped) == (1, True)
    assert built.batch_sizes() == [2]
    assert built.persisted()["cursor"] == "2"


# -- introspection -----------------------------------------------------------


def test_status_lists_connectors_destinations_and_metrics(harness: HarnessFactory) -> None:
    built = harness(records=records(1))
    built.runner.run_cycle()
    status = built.runner.status()
    assert sorted(status) == ["connectors", "destinations", "metrics"]
    assert [item["connector_id"] for item in status["connectors"]] == ["fake"]
    assert [item["forwarder_id"] for item in status["destinations"]] == ["sink"]
    sources = status["metrics"]["sources"]
    assert sources["fake"]["forwarded"] == 1
    assert sources["sink"]["forwarded"] == 1
    assert sources["fake"]["cycles"] == 1


def test_the_totals_view_sums_two_counting_units(harness: HarnessFactory) -> None:
    # ``forwarded`` is incremented once by the pipeline (events delivered) and once per
    # destination (delivery records accepted), so the total is not an event count: this cycle
    # delivered 2 events to 2 destinations and the total reads 6. Read ``sources.<id>``.
    built = harness(
        records=records(2),
        destinations=[DestinationSpec(id="es"), DestinationSpec(id="hive")],
    )
    report = built.runner.run_cycle()[0]
    snapshot = built.metrics.snapshot()
    assert report.forwarded == 2
    assert snapshot["sources"]["fake"]["forwarded"] == 2
    assert snapshot["sources"]["es"]["forwarded"] == 2
    assert snapshot["totals"]["forwarded"] == 6


def test_cycle_report_as_dict_is_the_log_shape() -> None:
    report = CycleReport(
        connector_id="fake",
        fetched=3,
        normalized=2,
        forwarded=2,
        dead_lettered=1,
        duplicates=0,
        cursor="3",
        error=None,
    )
    assert report.as_dict() == {
        "connector_id": "fake",
        "fetched": 3,
        "normalized": 2,
        "forwarded": 2,
        "dead_lettered": 1,
        "duplicates": 0,
        "cursor": "3",
        "error": None,
    }


def test_runner_state_summary_aggregates_every_cycle() -> None:
    ok = CycleReport(
        connector_id="alpha",
        fetched=2,
        normalized=2,
        forwarded=2,
        dead_lettered=0,
        duplicates=0,
        cursor="2",
    )
    bad = CycleReport(
        connector_id="beta",
        fetched=4,
        normalized=1,
        forwarded=0,
        dead_lettered=1,
        duplicates=3,
        cursor="4",
        error="TransientError: endpoint down",
    )
    state = RunnerState(cycles=2, reports=[ok, bad])
    summary = state.summary()
    assert summary["cycles"] == 2
    assert summary["fetched"] == 6
    assert summary["forwarded"] == 2
    assert summary["dead_lettered"] == 1
    assert summary["duplicates"] == 3
    assert summary["failed_cycles"] == 1
    assert [item["connector_id"] for item in summary["reports"]] == ["alpha", "beta"]


def test_a_fresh_run_state_counts_nothing() -> None:
    state = RunnerState()
    assert (state.fetched, state.forwarded, state.dead_lettered) == (0, 0, 0)
    assert (state.duplicates, state.failed_cycles) == (0, 0)
    assert state.summary()["reports"] == []
    assert state.stopped is False
