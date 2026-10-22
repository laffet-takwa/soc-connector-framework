"""Backoff, jitter and the retry/no-retry boundary."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from soc_connectors.exceptions import (
    AuthenticationError,
    CheckpointError,
    MalformedEventError,
    PaginationError,
    PermanentError,
    RateLimitedError,
    TransientError,
)
from soc_connectors.utils.retry import RetryPolicy, is_retryable, retry_call

pytestmark = pytest.mark.unit


class Sleeper:
    """Records the waits instead of performing them."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


def script(*outcomes: Any) -> Callable[[], Any]:
    """Return a callable that yields each outcome in order, raising when it is an exception."""
    remaining = list(outcomes)

    def call() -> Any:
        if not remaining:
            raise AssertionError("called more times than scripted")
        outcome = remaining.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return call


ZERO_JITTER = {"base_wait_seconds": 1.0, "jitter_ratio": 0.0}


def test_policy_defaults_are_conservative() -> None:
    policy = RetryPolicy()
    assert policy.max_attempts == 4
    assert policy.base_wait_seconds == 0.5
    assert policy.jitter_ratio == 0.5
    assert policy.max_wait_seconds == 30


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_attempts": 0},
        {"max_attempts": 21},
        {"base_wait_seconds": -1},
        {"base_wait_seconds": 61},
        {"max_wait_seconds": 601},
        {"jitter_ratio": 1.5},
        {"unknown_setting": 1},
    ],
)
def test_out_of_range_settings_are_rejected_at_config_time(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RetryPolicy(**overrides)


def test_policy_is_frozen() -> None:
    policy = RetryPolicy()
    with pytest.raises(ValidationError):
        policy.max_attempts = 9  # type: ignore[misc]


def test_no_retry_policy_attempts_once() -> None:
    assert RetryPolicy.no_retry().max_attempts == 1


@pytest.mark.parametrize(
    ("attempt", "expected"),
    [(1, 1.0), (2, 2.0), (3, 4.0), (4, 8.0), (5, 10.0), (6, 10.0)],
)
def test_backoff_grows_exponentially_and_is_capped(attempt: int, expected: float) -> None:
    policy = RetryPolicy(**{**ZERO_JITTER, "max_wait_seconds": 10.0})
    assert policy.backoff(attempt) == expected


def test_zero_base_wait_never_sleeps() -> None:
    assert RetryPolicy(base_wait_seconds=0.0).backoff(4) == 0.0


def test_jitter_stays_inside_its_window() -> None:
    policy = RetryPolicy(
        max_attempts=5, base_wait_seconds=8.0, max_wait_seconds=8.0, jitter_ratio=1.0
    )
    samples = {policy.backoff(2) for _ in range(200)}
    assert all(0.0 <= sample <= 8.0 for sample in samples)
    assert len(samples) > 1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TransientError("x"), True),
        (RateLimitedError("x"), True),
        (TimeoutError("x"), True),
        (ConnectionError("x"), True),
        (PermanentError("x"), False),
        (AuthenticationError("x"), False),
        (MalformedEventError("x"), False),
        (CheckpointError("x"), False),
        (PaginationError("x"), False),
        (TypeError("x"), False),
        (ValueError("x"), False),
    ],
)
def test_only_conditions_that_can_clear_are_retried(error: BaseException, expected: bool) -> None:
    assert is_retryable(error) is expected


def test_success_is_returned_without_any_waiting() -> None:
    sleeper = Sleeper()
    assert retry_call(script("ok"), sleep=sleeper) == "ok"
    assert sleeper.waits == []


def test_transient_failure_then_success_records_the_waits() -> None:
    sleeper = Sleeper()
    policy = RetryPolicy(max_attempts=3, **ZERO_JITTER)
    result = retry_call(
        script(TransientError("reset"), TransientError("reset"), "ok"),
        policy=policy,
        sleep=sleeper,
    )
    assert result == "ok"
    assert sleeper.waits == [1.0, 2.0]


def test_permanent_failure_is_not_retried_and_is_reraised() -> None:
    sleeper = Sleeper()
    error = PermanentError("no such index")
    with pytest.raises(PermanentError, match="no such index"):
        retry_call(script(error), policy=RetryPolicy(max_attempts=5), sleep=sleeper)
    assert sleeper.waits == []


def test_programmer_errors_are_not_retried() -> None:
    error = TypeError("unsupported operand")
    with pytest.raises(TypeError):
        retry_call(script(error), sleep=Sleeper())


def test_exhausting_the_policy_reraises_the_last_error() -> None:
    sleeper = Sleeper()
    second = TransientError("second")
    with pytest.raises(TransientError, match="second"):
        retry_call(
            script(TransientError("first"), second),
            policy=RetryPolicy(max_attempts=2, **ZERO_JITTER),
            sleep=sleeper,
        )
    assert sleeper.waits == [1.0]


def test_retry_after_wins_over_the_computed_backoff() -> None:
    sleeper = Sleeper()
    policy = RetryPolicy(max_attempts=3, max_wait_seconds=60.0, **ZERO_JITTER)
    result = retry_call(
        script(RateLimitedError("429", retry_after_seconds=7.5), "ok"),
        policy=policy,
        sleep=sleeper,
    )
    assert result == "ok"
    assert sleeper.waits == [7.5]


def test_a_defer_longer_than_the_ceiling_fails_the_event_instead_of_hanging_the_cycle(
    capture_logs: Callable[[str], list[Any]],
) -> None:
    sleeper = Sleeper()
    records = capture_logs("retry")
    error = RateLimitedError("429", retry_after_seconds=600)
    with pytest.raises(RateLimitedError):
        retry_call(
            script(error, "never reached"),
            policy=RetryPolicy(max_attempts=5, max_wait_seconds=30.0, **ZERO_JITTER),
            sleep=sleeper,
        )
    assert sleeper.waits == []
    assert any("longer defer" in record.getMessage() for record in records)


def test_rate_limited_without_a_header_uses_normal_backoff() -> None:
    sleeper = Sleeper()
    assert (
        retry_call(
            script(RateLimitedError("429"), "ok"),
            policy=RetryPolicy(max_attempts=2, **ZERO_JITTER),
            sleep=sleeper,
        )
        == "ok"
    )
    assert sleeper.waits == [1.0]


def test_on_retry_reports_attempt_and_the_error() -> None:
    seen: list[tuple[int, str]] = []
    retry_call(
        script(TransientError("one"), TransientError("two"), "ok"),
        policy=RetryPolicy(max_attempts=4, base_wait_seconds=0.0),
        on_retry=lambda attempt, _idle, error: seen.append((attempt, type(error).__name__)),
        sleep=Sleeper(),
    )
    assert seen == [(1, "TransientError"), (2, "TransientError")]


def test_a_caller_can_widen_what_counts_as_retryable() -> None:
    sleeper = Sleeper()
    result = retry_call(
        script(ValueError("transient to this source"), "ok"),
        policy=RetryPolicy(max_attempts=2, **ZERO_JITTER),
        sleep=sleeper,
        retryable=lambda error: isinstance(error, ValueError),
    )
    assert result == "ok"
    assert sleeper.waits == [1.0]
