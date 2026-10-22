"""Token bucket: the source's quota, and the operator's polling budget, in one object."""

from __future__ import annotations

import pytest

from soc_connectors.utils.rate_limit import (
    NoLimiter,
    RateLimiter,
    TokenBucket,
    build_limiter,
)

pytestmark = pytest.mark.unit


class FakeClock:
    """A monotonic clock the test advances explicitly, with a recorded sleep."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


def bucket(rate: float = 1.0, burst: int = 3, clock: FakeClock | None = None) -> TokenBucket:
    clock = clock or FakeClock()
    return TokenBucket(rate=rate, burst=burst, clock=clock, sleep=clock.sleep)


def test_a_new_bucket_starts_full() -> None:
    limiter = bucket(burst=3)
    assert limiter.available == 3
    assert limiter.wait_time() == 0.0
    assert limiter.refused == 0


@pytest.mark.parametrize(("rate", "burst"), [(0.0, 3), (-1.0, 3), (1.0, 0)])
def test_an_impossible_quota_is_refused(rate: float, burst: int) -> None:
    with pytest.raises(ValueError):
        TokenBucket(rate=rate, burst=burst)


def test_a_burst_drains_the_bucket_and_the_next_request_waits() -> None:
    limiter = bucket(rate=1.0, burst=2)
    assert limiter.try_acquire()
    assert limiter.try_acquire()
    assert not limiter.try_acquire()
    assert limiter.refused == 1
    assert limiter.wait_time() == pytest.approx(1.0)


def test_tokens_refill_over_time() -> None:
    clock = FakeClock()
    limiter = bucket(rate=0.5, burst=2, clock=clock)
    assert limiter.try_acquire(2)
    assert not limiter.try_acquire()
    clock.advance(4.0)
    assert limiter.available == pytest.approx(2.0)
    assert limiter.try_acquire()


def test_refill_never_exceeds_burst() -> None:
    clock = FakeClock()
    limiter = bucket(rate=10.0, burst=3, clock=clock)
    clock.advance(600)
    assert limiter.available == 3


def test_acquire_sleeps_only_for_what_it_lacks() -> None:
    clock = FakeClock()
    limiter = bucket(rate=1.0, burst=1, clock=clock)
    assert limiter.acquire()
    assert clock.slept == []
    assert limiter.acquire()
    assert clock.slept == [pytest.approx(1.0)]
    assert limiter.available == pytest.approx(0.0)


def test_acquire_refuses_to_block_past_the_callers_budget() -> None:
    clock = FakeClock()
    limiter = bucket(rate=0.1, burst=1, clock=clock)
    assert limiter.acquire()
    assert not limiter.acquire(timeout=2.0)
    assert limiter.refused == 1
    assert clock.slept == []


def test_a_request_larger_than_the_bucket_cannot_be_satisfied() -> None:
    limiter = bucket(rate=1.0, burst=2)
    assert not limiter.acquire(5, timeout=0.5)
    assert limiter.refused == 1


@pytest.mark.parametrize("tokens", [0, -1])
def test_non_positive_token_requests_are_a_bug_not_a_no_op(tokens: int) -> None:
    limiter = bucket()
    with pytest.raises(ValueError, match="tokens"):
        limiter.wait_time(tokens)
    with pytest.raises(ValueError, match="tokens"):
        limiter.try_acquire(tokens)
    with pytest.raises(ValueError, match="tokens"):
        limiter.acquire(tokens)


def test_a_negative_timeout_is_rejected_by_both_limiters() -> None:
    for limiter in (bucket(), NoLimiter()):
        with pytest.raises(ValueError, match="timeout"):
            limiter.acquire(1, timeout=-0.5)


def test_no_limiter_grants_everything_and_keeps_counting() -> None:
    limiter = NoLimiter()
    assert limiter.try_acquire()
    assert limiter.acquire(4)
    assert limiter.wait_time() == 0.0
    assert limiter.granted == 5


def test_the_builder_translates_requests_per_minute() -> None:
    limiter = build_limiter(600)
    assert isinstance(limiter, TokenBucket)
    assert limiter.rate == pytest.approx(10.0)
    assert limiter.burst == 60


def test_an_unset_or_absurd_quota_means_no_limiting() -> None:
    assert isinstance(build_limiter(None), NoLimiter)
    assert isinstance(build_limiter(0), NoLimiter)
    assert isinstance(build_limiter(-5), NoLimiter)


def test_burst_can_be_pinned_below_the_rate() -> None:
    limiter = build_limiter(120, burst=2)
    assert isinstance(limiter, TokenBucket)
    assert limiter.burst == 2


def test_a_fractional_rate_below_one_per_minute_still_holds_one_token() -> None:
    limiter = build_limiter(0.5, burst=None)
    assert isinstance(limiter, TokenBucket)
    assert limiter.burst == 1


@pytest.mark.parametrize("limiter", [NoLimiter(), TokenBucket(rate=10, burst=10)])
def test_both_limiters_satisfy_the_protocol(limiter: RateLimiter) -> None:
    assert limiter.try_acquire(1)
    assert limiter.wait_time(1) >= 0
