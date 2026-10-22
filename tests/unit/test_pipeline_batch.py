"""Batching: a full buffer *or* a patient one, whichever happens first.

The contract under test is the latency guarantee in the module docstring: an event must not sit
in a buffer because the source is quiet. Every clock here is a fake that only moves when the
test says so, so the age rules are tested without waiting.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest

from soc_connectors.pipeline.batch import (
    DEFAULT_MAX_AGE_SECONDS,
    BatchAccumulator,
    batches,
    chunk,
)
from soc_connectors.schema.ecs_models import EcsEvent

pytestmark = pytest.mark.unit

BASE_TIME = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)
MakeEvent = Callable[..., EcsEvent]
MakeEvents = Callable[..., list[EcsEvent]]


class Clock:
    """A clock a test advances explicitly."""

    def __init__(self, start: datetime = BASE_TIME) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> Clock:
    return Clock()


# -- chunk -----------------------------------------------------------------


def test_chunk_splits_on_exact_multiples_without_a_trailing_empty_list() -> None:
    assert list(chunk([1, 2, 3, 4], 2)) == [[1, 2], [3, 4]]


def test_chunk_keeps_the_remainder() -> None:
    assert list(chunk([1, 2, 3, 4], 3)) == [[1, 2, 3], [4]]


def test_chunk_of_an_empty_sequence_yields_nothing() -> None:
    assert list(chunk([], 10)) == []


def test_size_one_yields_one_item_per_batch() -> None:
    assert list(chunk([1, 2, 3], 1)) == [[1], [2], [3]]


@pytest.mark.parametrize("size", [0, -1])
def test_a_batch_size_below_one_is_rejected_not_treated_as_unlimited(size: int) -> None:
    """An infinite loop is worse than a ValueError, so the guard is the whole point."""
    with pytest.raises(ValueError, match="batch size must be at least 1"):
        list(chunk([1, 2], size))


def test_chunk_returns_new_lists_so_the_caller_can_clear_the_source() -> None:
    source = [1, 2]
    first = next(iter(chunk(source, 2)))
    first.append(3)
    assert source == [1, 2]


# -- BatchAccumulator ------------------------------------------------------


def test_a_fresh_accumulator_is_empty_holds_nothing_and_is_not_due(clock: Clock) -> None:
    accumulator = BatchAccumulator(max_size=3, max_age_seconds=10, clock=clock)
    assert len(accumulator) == 0
    assert accumulator.oldest_age == 0.0
    assert accumulator.due() is False
    assert accumulator.flush() == []


def test_adding_below_the_size_threshold_returns_none(clock: Clock, make_event: MakeEvent) -> None:
    accumulator = BatchAccumulator(max_size=2, max_age_seconds=60, clock=clock)
    assert accumulator.add(make_event()) is None
    assert len(accumulator) == 1


def test_the_batch_leaves_the_moment_it_is_full(clock: Clock, make_events: MakeEvents) -> None:
    accumulator = BatchAccumulator(max_size=2, max_age_seconds=60, clock=clock)
    first, second = make_events(2)
    assert accumulator.add(first) is None
    ready = accumulator.add(second)
    assert ready is not None
    assert [event.identity_key() for event in ready] == [
        first.identity_key(),
        second.identity_key(),
    ]
    assert len(accumulator) == 0


def test_a_size_one_accumulator_flushes_on_the_first_event(
    clock: Clock, make_event: MakeEvent
) -> None:
    accumulator = BatchAccumulator(max_size=1, max_age_seconds=60, clock=clock)
    assert len(accumulator.add(make_event()) or []) == 1


def test_a_zero_size_buffer_flushes_every_event_it_is_given(
    clock: Clock, make_event: MakeEvent
) -> None:
    """The runner clamps to ``max(1, batch_size)``; the accumulator itself would send at once."""
    accumulator = BatchAccumulator(max_size=0, max_age_seconds=60, clock=clock)
    assert len(accumulator.add(make_event()) or []) == 1


def test_age_flushes_a_single_event_before_the_size_is_reached(
    clock: Clock, make_event: MakeEvent
) -> None:
    accumulator = BatchAccumulator(max_size=100, max_age_seconds=5.0, clock=clock)
    held = accumulator.add(make_event(timestamp=BASE_TIME))
    assert held is None
    clock.advance(5.0)
    ready = accumulator.add(make_event(timestamp=BASE_TIME + timedelta(seconds=9)))
    assert ready is not None
    assert len(ready) == 2


def test_age_is_measured_from_the_event_timestamp_not_the_arrival(
    clock: Clock, make_event: MakeEvent
) -> None:
    """A backdated event is already stale: the buffer ages the event, not itself.

    This is why a replayed file does not sit in a buffer for ``max_age_seconds`` — every
    record it holds is older than the threshold, so each ``add`` sends immediately.
    """
    accumulator = BatchAccumulator(max_size=100, max_age_seconds=5.0, clock=clock)
    clock.advance(60)
    ready = accumulator.add(make_event(timestamp=BASE_TIME))
    assert ready is not None
    assert len(ready) == 1
    assert accumulator.oldest_age == 0.0


def test_an_accumulator_built_early_does_not_age_events_that_arrive_later(
    clock: Clock, make_event: MakeEvent
) -> None:
    """Construction time is irrelevant; only the held events' timestamps count."""
    accumulator = BatchAccumulator(max_size=100, max_age_seconds=5.0, clock=clock)
    clock.advance(600)
    assert accumulator.oldest_age == 0.0
    assert accumulator.due() is False
    assert accumulator.add(make_event(timestamp=clock.now)) is None
    assert accumulator.oldest_age == 0.0


def test_flush_clears_the_age_so_the_next_event_starts_a_fresh_window(
    clock: Clock, make_event: MakeEvent
) -> None:
    accumulator = BatchAccumulator(max_size=100, max_age_seconds=5.0, clock=clock)
    accumulator.add(make_event(timestamp=BASE_TIME))
    clock.advance(30)
    accumulator.flush()
    assert accumulator.oldest_age == 0.0
    assert accumulator.due() is False


def test_age_never_goes_negative_when_the_event_is_in_the_future(
    clock: Clock, make_event: MakeEvent
) -> None:
    """``_oldest`` is a source timestamp, not wall time: a skewed source must not panic."""
    accumulator = BatchAccumulator(max_size=100, max_age_seconds=5.0, clock=clock)
    accumulator.add(make_event(timestamp=BASE_TIME + timedelta(hours=1)))
    assert accumulator.oldest_age == 0.0


def test_an_empty_buffer_is_never_due(clock: Clock) -> None:
    """Nothing arrived, so nothing is waiting — a quiet source must not trigger empty sends."""
    accumulator = BatchAccumulator(max_size=1, max_age_seconds=0.0, clock=clock)
    assert accumulator.due() is False


def test_default_max_age_is_a_short_sane_number() -> None:
    assert DEFAULT_MAX_AGE_SECONDS == 5.0


# -- batches ---------------------------------------------------------------


def test_batches_groups_a_generator_without_draining_it_first(make_events: MakeEvents) -> None:
    pulled: list[int] = []

    def counted() -> Iterator[EcsEvent]:
        for event in make_events(5):
            pulled.append(len(pulled) + 1)
            yield event

    generated = batches(counted(), 2)
    first = next(iter(generated))
    assert len(first) == 2
    assert pulled == [1, 2], "only the events of the batch already yielded were pulled"


def test_batches_yields_the_partial_last_group(make_events: MakeEvents) -> None:
    assert [len(group) for group in batches(make_events(5), 2)] == [2, 2, 1]


def test_batches_of_nothing_yields_nothing() -> None:
    empty: list[EcsEvent] = []
    assert list(batches(iter(empty), 3)) == []


def test_batches_honours_a_size_larger_than_the_stream(make_events: MakeEvents) -> None:
    assert [len(group) for group in batches(make_events(2), 500)] == [2]


def test_accumulator_and_batches_agree_on_size_semantics(
    make_events: MakeEvents, clock: Clock
) -> None:
    """Two mechanisms, one promise: full means go."""
    events: list[EcsEvent] = make_events(4)
    accumulator = BatchAccumulator(max_size=2, max_age_seconds=3600, clock=clock)
    flushed: list[list[EcsEvent]] = []
    for event in events:
        ready = accumulator.add(event)
        if ready is not None:
            flushed.append(ready)
    assert [len(group) for group in flushed] == [2, 2]
    assert [len(group) for group in batches(events, 2)] == [2, 2]
