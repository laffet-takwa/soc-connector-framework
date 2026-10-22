"""Token-bucket rate limiting with an injectable clock.

Two different pressures are handled here. A source's documented request quota (Graph, the S3
ListObjects rate) is honoured by refilling tokens at a fixed rate, so a burst at the start of
a cycle drains the bucket and the rest of the cycle waits rather than collecting a 429. The
second pressure is the operator's own polling budget: ``acquire(timeout=...)`` returns
``False`` instead of blocking past the cycle, which makes "we are being throttled" visible as
a metric instead of as a hung process.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

Clock = Callable[[], float]
Sleep = Callable[[float], None]


class RateLimiter(Protocol):
    """What a connector needs from a limiter — nothing more."""

    def try_acquire(self, tokens: int = 1) -> bool: ...

    def wait_time(self, tokens: int = 1) -> float: ...

    def acquire(self, tokens: int = 1, *, timeout: float | None = None) -> bool: ...


@dataclass
class TokenBucket:
    """A classic token bucket: ``rate`` tokens per second, up to ``burst`` held."""

    rate: float
    burst: int
    clock: Clock = field(default=time.monotonic)
    sleep: Sleep = field(default=time.sleep)
    _tokens: float = field(default=0.0, init=False, repr=False)
    _last_refill: float = field(default=0.0, init=False, repr=False)
    _refused: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be positive; use NoLimiter for unlimited")
        if self.burst < 1:
            raise ValueError("burst must be at least 1")
        self._tokens = float(self.burst)
        self._last_refill = self.clock()

    @property
    def available(self) -> float:
        """Tokens present right now, after applying the elapsed refill."""
        self._refill()
        return self._tokens

    @property
    def refused(self) -> int:
        """Acquires that were denied outright or timed out — the throttling signal."""
        return self._refused

    def _refill(self) -> None:
        now = self.clock()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
        self._last_refill = now

    def wait_time(self, tokens: int = 1) -> float:
        """Seconds until ``tokens`` would be available; ``0.0`` when they already are."""
        if tokens < 1:
            raise ValueError("tokens must be at least 1")
        self._refill()
        missing = tokens - self._tokens
        if missing <= 0:
            return 0.0
        return missing / self.rate

    def try_acquire(self, tokens: int = 1) -> bool:
        """Take ``tokens`` without waiting, and report whether the bucket allowed it."""
        if tokens < 1:
            raise ValueError("tokens must be at least 1")
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        self._refused += 1
        return False

    def acquire(self, tokens: int = 1, *, timeout: float | None = None) -> bool:
        """Take ``tokens``, waiting up to ``timeout`` seconds (``None`` waits indefinitely).

        Sleeping in one go for the whole deficit is deliberate: the deficit only shrinks, so a
        single sleep cannot wake early to a smaller bucket than it computed.
        """
        if tokens < 1:
            raise ValueError("tokens must be at least 1")
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must not be negative")
        needed = self.wait_time(tokens)
        if needed <= 0:
            self._tokens -= tokens
            return True
        if timeout is not None and needed > timeout:
            self._refused += 1
            return False
        self.sleep(needed)
        self._refill()
        self._tokens = max(0.0, self._tokens - tokens)
        return True


@dataclass
class NoLimiter:
    """Unlimited: used when a source has no documented quota, and in tests.

    It validates its arguments and counts grants exactly like :class:`TokenBucket`, so a test
    written against ``granted`` behaves the same whichever limiter the factory chose.
    """

    granted: int = 0

    @staticmethod
    def _check(tokens: int, timeout: float | None) -> None:
        if tokens < 1:
            raise ValueError("tokens must be at least 1")
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must not be negative")

    def try_acquire(self, tokens: int = 1) -> bool:
        self._check(tokens, None)
        self.granted += tokens
        return True

    def wait_time(self, tokens: int = 1) -> float:
        self._check(tokens, None)
        return 0.0

    def acquire(self, tokens: int = 1, *, timeout: float | None = None) -> bool:
        self._check(tokens, timeout)
        self.granted += tokens
        return True


def build_limiter(
    requests_per_minute: float | None,
    *,
    burst: int | None = None,
    clock: Clock = time.monotonic,
    sleep: Sleep = time.sleep,
) -> RateLimiter:
    """From a config value in requests/minute to a limiter, or ``NoLimiter`` when unset."""
    if requests_per_minute is None or requests_per_minute <= 0:
        return NoLimiter()
    capacity = max(1, int(burst if burst is not None else min(requests_per_minute, 60)))
    return TokenBucket(rate=requests_per_minute / 60.0, burst=capacity, clock=clock, sleep=sleep)
