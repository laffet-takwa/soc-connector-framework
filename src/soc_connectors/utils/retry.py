"""Retry with exponential backoff and jitter.

Two rules shape this module. First, only a condition that can clear is retried: a timeout, a
5xx, a 429 — never a 403 or a mapping error, which a retry loop would only turn into an
outage-shaped request storm. Second, when the server says how long to wait, that instruction
wins over the computed backoff — unless it asks for longer than ``max_wait_seconds``, in which
case the event fails now instead of blocking the cycle for minutes.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field
from tenacity import RetryCallState, Retrying, stop_after_attempt

from soc_connectors.exceptions import (
    MalformedEventError,
    PermanentError,
    RateLimitedError,
    SocConnectorError,
    TransientError,
)
from soc_connectors.logging_setup import get_logger

T = TypeVar("T")
logger = get_logger("retry")

Sleep = Callable[[float], None]
OnRetry = Callable[[int, float, BaseException], None]


class RetryPolicy(BaseModel):
    """Backoff settings, read straight from the ``retry:`` block in the config file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=4, ge=1, le=20)
    base_wait_seconds: float = Field(default=0.5, ge=0, le=60)
    max_wait_seconds: float = Field(default=30, ge=0, le=600)
    jitter_ratio: float = Field(default=0.5, ge=0, le=1)

    def backoff(self, attempt: int) -> float:
        """Exponential estimate for attempt ``attempt`` (1-based), then jittered.

        Jitter is what stops fifty connectors from all retrying the same recovered endpoint
        inside the same millisecond. With ``jitter_ratio=1`` the wait is uniform over
        ``[0, ceiling]``; with ``base_wait_seconds=0`` every wait is zero, which is what the
        tests use to exercise the sequence without sleeping.
        """
        ceiling = min(self.max_wait_seconds, self.base_wait_seconds * (2 ** max(0, attempt - 1)))
        if ceiling <= 0:
            return 0.0
        return random.uniform(ceiling * (1.0 - self.jitter_ratio), ceiling)

    @staticmethod
    def no_retry() -> RetryPolicy:
        """A policy that fails on the first attempt — used for `--no-retry` and tests."""
        return RetryPolicy(max_attempts=1)


def is_retryable(error: BaseException) -> bool:
    """Classify a failure against the exception taxonomy.

    Exceptions the taxonomy does not vouch for are *not* retried: a ``TypeError`` inside a
    parser fails identically on the ninth attempt, so retrying it only delays the traceback.
    """
    if isinstance(error, (PermanentError, MalformedEventError)):
        return False
    if isinstance(error, TransientError):
        return True
    if isinstance(error, SocConnectorError):
        return False
    return isinstance(error, (TimeoutError, ConnectionError))


def _last_error(retry_state: RetryCallState) -> BaseException | None:
    if retry_state.outcome is None:
        return None
    return retry_state.outcome.exception()


def _requested_defer(error: BaseException | None, policy: RetryPolicy) -> float | None:
    """Seconds the upstream asked us to wait, or ``None`` when it gave no usable instruction."""
    if not isinstance(error, RateLimitedError) or error.retry_after_seconds is None:
        return None
    requested = max(0.0, float(error.retry_after_seconds))
    if requested > policy.max_wait_seconds:
        return None
    return requested


def _defer_exceeds_ceiling(error: BaseException, policy: RetryPolicy) -> bool:
    """True only when the server named a wait longer than this policy may block for.

    Kept separate from :func:`_requested_defer` because ``None`` there also means "no header at
    all", and a 429 without ``Retry-After`` must still fall back to ordinary backoff.
    """
    if not isinstance(error, RateLimitedError) or error.retry_after_seconds is None:
        return False
    return max(0.0, float(error.retry_after_seconds)) > policy.max_wait_seconds


def retry_call(
    func: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    name: str = "operation",
    sleep: Sleep = time.sleep,
    on_retry: OnRetry | None = None,
    retryable: Callable[[BaseException], bool] = is_retryable,
) -> T:
    """Call ``func``, retrying retryable failures with backoff, then re-raise the last error.

    ``sleep`` is injectable so tests run in no time *and* can assert the wait sequence, which
    is the part that is easy to get wrong and invisible in a coverage report. ``on_retry`` is told
    the seconds already waited before this decision: tenacity asks *whether* to retry before it
    computes the next backoff, so the upcoming wait does not exist yet at that point.
    """
    active = policy or RetryPolicy()

    def _wait(state: RetryCallState) -> float:
        defer = _requested_defer(_last_error(state), active)
        return active.backoff(state.attempt_number) if defer is None else defer

    def _should_retry(state: RetryCallState) -> bool:
        error = _last_error(state)
        if error is None or state.attempt_number >= active.max_attempts or not retryable(error):
            return False
        if isinstance(error, RateLimitedError) and _defer_exceeds_ceiling(error, active):
            # The server asked for more than this policy may block for: fail the event now
            # rather than retry earlier than it requested and teach it to throttle us harder.
            logger.error(
                "upstream requested a longer defer than the retry ceiling",
                extra={
                    "operation": name,
                    "requested_seconds": error.retry_after_seconds,
                    "max_wait_seconds": active.max_wait_seconds,
                },
            )
            return False
        if on_retry is not None:
            on_retry(state.attempt_number, state.idle_for, error)
        logger.warning(
            "retrying after transient failure",
            extra={
                "operation": name,
                "attempt": state.attempt_number,
                "idle_seconds": round(state.idle_for, 3),
                "error_type": type(error).__name__,
            },
        )
        return True

    retrying = Retrying(
        sleep=sleep,
        stop=stop_after_attempt(active.max_attempts),
        wait=_wait,
        retry=_should_retry,
        reraise=True,
        name=name,
    )
    return retrying(func)
