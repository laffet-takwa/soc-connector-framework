"""Counters that make "is my connector still working?" answerable.

A forwarder that quietly stops shipping events is the classic integration failure, so the
pipeline records every stage per connector and the runner emits the snapshot as a log line.
The numbers are also what the CLI prints after ``--once`` and what the demo asserts on.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Any, Final

from soc_connectors.utils.time import to_iso_z, utc_now

STAGES = (
    "fetched",
    "parsed",
    "normalized",
    "forwarded",
    "failed",
    "duplicated",
    "dropped",
    "retried",
    "dead_lettered",
    "rate_limited",
    "errors",
    "cycles",
)

#: Latency samples retained per name — enough for a p-max without unbounded memory.
DURATION_SAMPLES_KEPT: Final = 100


class Metrics:
    """Thread-safe stage counters, total and per connector/forwarder."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._totals: dict[str, int] = defaultdict(int)
        self._by_source: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._durations_ms: dict[str, list[float]] = defaultdict(list)
        self.started_at = time.monotonic()

    def incr(self, stage: str, *, source: str = "pipeline", by: int = 1) -> None:
        if stage not in STAGES:
            raise ValueError(f"unknown metric stage {stage!r}; expected one of {STAGES}")
        with self._lock:
            self._totals[stage] += by
            self._by_source[source][stage] += by

    def add_duration(self, name: str, seconds: float) -> None:
        with self._lock:
            samples = self._durations_ms[name]
            samples.append(round(seconds * 1000.0, 2))
            del samples[:-DURATION_SAMPLES_KEPT]

    @contextmanager
    def timer(self, name: str) -> Any:
        started = time.monotonic()
        yield
        self.add_duration(name, time.monotonic() - started)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "totals": dict(sorted(self._totals.items())),
                "sources": {
                    name: dict(sorted(counts.items()))
                    for name, counts in sorted(self._by_source.items())
                },
                "duration_ms": {
                    name: {
                        "last": samples[-1],
                        "max": max(samples),
                        "avg": round(sum(samples) / len(samples), 2),
                    }
                    for name, samples in sorted(self._durations_ms.items())
                    if samples
                },
                "uptime_seconds": round(time.monotonic() - self.started_at, 3),
                "updated_at": to_iso_z(utc_now()),
            }

    def total(self, stage: str) -> int:
        with self._lock:
            return int(self._totals.get(stage, 0))

    def for_source(self, source: str) -> dict[str, int]:
        with self._lock:
            return dict(self._by_source.get(source, {}))

    def is_idle(self) -> bool:
        """True when nothing has ever been fetched — used by ``self-test``."""
        with self._lock:
            return not self._totals
