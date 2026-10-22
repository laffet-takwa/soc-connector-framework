"""The runner: one cycle per source, in a fixed order, with the state written last.

Per cycle, for each enabled connector:

1. ``fetch()`` records from the checkpointed cursor;
2. ``parse()`` and ``normalize()`` per record, with typed failures sent to the dead-letter file
   instead of aborting the cycle;
3. de-duplicate against the checkpoint's seen-id window;
4. dispatch to destinations in batches (size or age, whichever comes first);
5. persist cursor, newest timestamp and seen ids **after** delivery.

Step 5 last is the whole point: a crash before it replays a window rather than losing one.
That makes the guarantee at-least-once, not exactly-once — which is why destinations are
expected to tolerate duplicates inside the seen-id window.

One record failing never stops a cycle. A source failing stops only that source: the other
connectors keep polling, and the failure surfaces as a cycle error, a metric and a log line.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from typing import Any

from soc_connectors.config import AppConfig, SourceConfig
from soc_connectors.connectors.base import BaseConnector
from soc_connectors.exceptions import MalformedEventError, SocConnectorError
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.batch import BatchAccumulator
from soc_connectors.pipeline.dispatcher import Dispatcher
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.types import Clock, CycleReport, RawEvent
from soc_connectors.utils.checkpoint import CheckpointStore
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.retry import RetryPolicy, retry_call
from soc_connectors.utils.time import utc_now

Sleeper = Callable[[float], bool]
"""Sleep up to ``seconds``; ``True`` means shutdown was requested meanwhile."""

RetrySleep = Callable[[float], None]


@dataclass(slots=True)
class SourceRuntime:
    """A connector plus the machinery the pipeline built around it."""

    config: SourceConfig
    connector: BaseConnector
    dead_letter: DeadLetterQueue
    checkpoint: CheckpointStore
    retry_policy: RetryPolicy
    batch_size: int
    destinations: tuple[str, ...] | None = None
    """The destination ids this source was configured to reach; ``None`` means every one."""


@dataclass(slots=True)
class CycleCounters:
    """What one cycle of one source did, as it happens."""

    cursor: str | None = None
    fetched: int = 0
    normalized: int = 0
    forwarded: int = 0
    duplicates: int = 0
    dead_lettered: int = 0
    newest: datetime | None = None
    error: str | None = None


@dataclass(slots=True)
class RunnerState:
    """Aggregated results across the cycles one ``run()`` performed."""

    cycles: int = 0
    reports: list[CycleReport] = field(default_factory=list)
    stopped: bool = False

    @property
    def fetched(self) -> int:
        return sum(report.fetched for report in self.reports)

    @property
    def forwarded(self) -> int:
        return sum(report.forwarded for report in self.reports)

    @property
    def dead_lettered(self) -> int:
        return sum(report.dead_lettered for report in self.reports)

    @property
    def duplicates(self) -> int:
        return sum(report.duplicates for report in self.reports)

    @property
    def failed_cycles(self) -> int:
        return sum(1 for report in self.reports if report.error is not None)

    def summary(self) -> dict[str, Any]:
        return {
            "cycles": self.cycles,
            "fetched": self.fetched,
            "forwarded": self.forwarded,
            "dead_lettered": self.dead_lettered,
            "duplicates": self.duplicates,
            "failed_cycles": self.failed_cycles,
            "reports": [report.as_dict() for report in self.reports],
        }


class PipelineRunner:
    def __init__(
        self,
        *,
        config: AppConfig,
        sources: Sequence[SourceRuntime],
        dispatcher: Dispatcher,
        metrics: Metrics,
        sleeper: Sleeper | None = None,
        retry_sleep: RetrySleep = time.sleep,
        clock: Clock = utc_now,
        log: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.sources = list(sources)
        self.dispatcher = dispatcher
        self.metrics = metrics
        self.log = log or logging.getLogger("soc_connectors.runner")
        self.stop_event = threading.Event()
        self.retry_sleep = retry_sleep
        self.clock = clock
        self.sleeper = sleeper or self.stop_event.wait

    # -- one cycle -----------------------------------------------------------

    def run_cycle(self) -> list[CycleReport]:
        return [self.run_source(runtime) for runtime in self.sources]

    def run_source(self, runtime: SourceRuntime) -> CycleReport:
        counters = CycleCounters(cursor=runtime.checkpoint.state.cursor)
        # The age limit is measured against the pipeline's injected clock, like every other
        # timestamp here, so a batching rule can be tested without waiting for one to expire.
        accumulator = BatchAccumulator(
            max_size=max(1, runtime.batch_size),
            max_age_seconds=self.config.pipeline.poll_interval_seconds,
            clock=self.clock,
        )
        try:
            for raw in runtime.connector.fetch():
                self._consume(runtime, counters, accumulator, raw)
        except (SocConnectorError, OSError) as exc:
            counters.error = f"{type(exc).__name__}: {exc}"
            self.metrics.incr("errors", source=runtime.connector.id)
            self.log.exception(
                "source cycle failed",
                extra={
                    "connector_id": runtime.connector.id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "cursor": counters.cursor,
                },
            )

        if len(accumulator):
            self._flush(runtime, counters, accumulator.flush())
        self._persist(runtime, counters)

        self.metrics.incr("cycles", source=runtime.connector.id)
        report = CycleReport(
            connector_id=runtime.connector.id,
            fetched=counters.fetched,
            normalized=counters.normalized,
            forwarded=counters.forwarded,
            dead_lettered=counters.dead_lettered,
            duplicates=counters.duplicates,
            cursor=counters.cursor,
            error=counters.error,
        )
        self.log.info("cycle complete", extra={"report": report.as_dict()})
        return report

    def _consume(
        self,
        runtime: SourceRuntime,
        counters: CycleCounters,
        accumulator: BatchAccumulator,
        raw: RawEvent,
    ) -> None:
        counters.fetched += 1
        self.metrics.incr("fetched", source=runtime.connector.id)
        if raw.cursor:
            counters.cursor = raw.cursor
        try:
            event = self._normalize(runtime, raw)
        except Exception as exc:
            runtime.dead_letter.write(
                connector_id=runtime.connector.id,
                stage="normalize" if isinstance(exc, MalformedEventError) else "source",
                reason=str(exc),
                error=exc,
                raw=raw,
            )
            counters.dead_lettered += 1
            self.metrics.incr("dead_lettered", source=runtime.connector.id)
            return
        identity = event.identity_key()
        if runtime.checkpoint.is_duplicate(identity):
            counters.duplicates += 1
            self.metrics.incr("duplicated", source=runtime.connector.id)
            return
        # Remembered before delivery: a record that then fails lands in the dead-letter file,
        # and re-reading it in the same run would only fail twice.
        runtime.checkpoint.remember([identity])
        counters.normalized += 1
        counters.newest = (
            event.timestamp if counters.newest is None else max(counters.newest, event.timestamp)
        )
        ready = accumulator.add(event)
        if ready is not None:
            self._flush(runtime, counters, ready)

    def _normalize(self, runtime: SourceRuntime, raw: RawEvent) -> EcsEvent:
        connector = runtime.connector

        def work() -> EcsEvent:
            return connector.normalize(connector.parse(raw))

        return retry_call(
            work,
            policy=runtime.retry_policy,
            name=f"{connector.id}:normalize",
            sleep=self.retry_sleep,
            on_retry=partial(self._note_retry, connector.id),
        )

    def _note_retry(
        self, source_id: str, attempt: int, idle_seconds: float, error: BaseException
    ) -> None:
        self.metrics.incr("retried", source=source_id)
        self.log.warning(
            "record processing failed, retrying",
            extra={
                "connector_id": source_id,
                "attempt": attempt,
                "idle_seconds": round(idle_seconds, 3),
                "error_type": type(error).__name__,
            },
        )

    def _flush(
        self, runtime: SourceRuntime, counters: CycleCounters, batch: list[EcsEvent]
    ) -> None:
        if not batch:
            return
        report = self.dispatcher.dispatch(
            batch,
            source_id=runtime.connector.id,
            dead_letter=runtime.dead_letter,
            destinations=runtime.destinations,
        )
        counters.forwarded += report.events_delivered
        if report.events_delivered:
            self.metrics.incr("forwarded", source=runtime.connector.id, by=report.events_delivered)
        counters.dead_lettered += report.events_failed
        if report.errors:
            joined = "; ".join(report.errors)
            counters.error = joined if counters.error is None else f"{counters.error}; {joined}"
        if report.failed:
            self.log.warning(
                "batch partially failed",
                extra={
                    "connector_id": runtime.connector.id,
                    "size": len(batch),
                    "accepted": report.accepted,
                    "rejected": report.rejected,
                    "errors": report.errors,
                },
            )

    def _persist(self, runtime: SourceRuntime, counters: CycleCounters) -> None:
        if not (counters.fetched or counters.dead_lettered):
            return
        runtime.checkpoint.advance(cursor=counters.cursor, last_timestamp=counters.newest)
        try:
            runtime.checkpoint.save()
        except Exception as exc:
            counters.error = counters.error or f"checkpoint save failed: {exc}"
            self.log.exception(
                "checkpoint save failed",
                extra={"connector_id": runtime.connector.id, "error": str(exc)},
            )

    # -- the loop ------------------------------------------------------------

    def run(self, *, once: bool = False, max_cycles: int | None = None) -> RunnerState:
        state = RunnerState()
        while True:
            state.reports.extend(self.run_cycle())
            state.cycles += 1
            self.log.info(
                "metrics", extra={"metrics": self.metrics.snapshot(), "cycles": state.cycles}
            )
            if once or (max_cycles is not None and state.cycles >= max_cycles):
                break
            if self.sleeper(self.config.pipeline.poll_interval_seconds):
                state.stopped = True
                break
        return state

    def request_stop(self) -> None:
        """Ask the loop to finish the current cycle and exit. Safe from a signal handler."""
        self.stop_event.set()

    def status(self) -> dict[str, Any]:
        return {
            "connectors": [runtime.connector.health() for runtime in self.sources],
            "destinations": [route.forwarder.health() for route in self.dispatcher.routes],
            "metrics": self.metrics.snapshot(),
        }
