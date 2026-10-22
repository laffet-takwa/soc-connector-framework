"""Batching: size and age, whichever comes first.

A batch sized by count alone starves a quiet source — forty events an hour would sit in a
buffer of two hundred until something else happened, which is exactly the latency a SOC analyst
feels as "the dashboard is behind". So a batch flushes when it is full *or* when its oldest
event has waited long enough. With no events arriving, nothing flushes: there is nothing to
send.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypeVar

from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.utils.time import utc_now

T = TypeVar("T")

DEFAULT_MAX_AGE_SECONDS = 5.0


def chunk(items: Sequence[T], size: int) -> Iterator[list[T]]:
    """Split ``items`` into lists of at most ``size``."""
    if size < 1:
        raise ValueError("batch size must be at least 1")
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


@dataclass
class BatchAccumulator:
    """Holds events until a size or an age threshold is met."""

    max_size: int
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS
    clock: Callable[[], datetime] = field(default=utc_now)
    _items: list[EcsEvent] = field(default_factory=list, init=False)
    _oldest: datetime | None = field(default=None, init=False)

    def __len__(self) -> int:
        return len(self._items)

    @property
    def oldest_age(self) -> float:
        if self._oldest is None:
            return 0.0
        return max(0.0, (self.clock() - self._oldest).total_seconds())

    def add(self, event: EcsEvent) -> list[EcsEvent] | None:
        """Add one event; return the batch when it must go out now, else ``None``."""
        if not self._items:
            self._oldest = event.timestamp
        self._items.append(event)
        if len(self._items) >= self.max_size:
            return self.flush()
        if self.oldest_age >= self.max_age_seconds:
            return self.flush()
        return None

    def flush(self) -> list[EcsEvent]:
        """Take everything currently held, clearing the buffer."""
        ready = self._items
        self._items = []
        self._oldest = None
        return ready

    def due(self) -> bool:
        return bool(self._items) and (
            len(self._items) >= self.max_size or self.oldest_age >= self.max_age_seconds
        )


def batches(events: Iterable[EcsEvent], size: int) -> Iterator[list[EcsEvent]]:
    """Group an iterable into lists of ``size`` without holding the whole stream in memory."""
    current: list[EcsEvent] = []
    for event in events:
        current.append(event)
        if len(current) >= size:
            yield current
            current = []
    if current:
        yield current
