"""Timestamp and retry-window parsing shared by every source.

Sources disagree about time formats (CloudTrail ISO-Z, Graph ISO-Z, Fortinet `date` plus
`time`, iptables syslog `Oct 22 09:12:33`, epoch seconds or milliseconds), so this module
is the single place where that ambiguity is resolved. Naive timestamps are treated as UTC
rather than converted from the machine's local zone: a connector running in a container
with `TZ=UTC` must not disagree with one running in `TZ=CET`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from dateutil import parser as date_parser

from soc_connectors.exceptions import MalformedEventError

#: Epoch values at or above this are read as milliseconds. The boundary has to sit between
#: "seconds for a plausible future date" and "milliseconds for a plausible recent one":
#: 1e11 seconds is the year 5138 while 1e11 milliseconds is 1973, so every log timestamp in
#: service today is classified correctly. A 1e9 cutoff would have misread every timestamp
#: after September 2001 as milliseconds.
_EPOCH_MILLIS_THRESHOLD = 100_000_000_000


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` in UTC, assuming UTC when the source gave no offset."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_timestamp(value: Any, *, field_name: str = "timestamp") -> datetime:
    """Coerce a source timestamp into an aware UTC datetime."""
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, bool):
        raise MalformedEventError(f"{field_name} is a bool, not a timestamp", field=field_name)
    if isinstance(value, (int, float)):
        return _from_epoch(value, field_name=field_name)
    if isinstance(value, str):
        return _from_string(value, field_name=field_name)
    raise MalformedEventError(
        f"{field_name} must be a string or number, got {type(value).__name__}", field=field_name
    )


def _from_epoch(value: int | float, *, field_name: str) -> datetime:
    seconds = value / 1000.0 if abs(value) >= _EPOCH_MILLIS_THRESHOLD else float(value)
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise MalformedEventError(
            f"{field_name}={value!r} is outside the epoch range", field=field_name
        ) from exc


def _from_string(text: str, *, field_name: str) -> datetime:
    stripped = text.strip()
    if not stripped:
        raise MalformedEventError(f"{field_name} is empty", field=field_name)

    candidate = f"{stripped[:-1]}+00:00" if stripped[-1] in "Zz" else stripped
    try:
        return ensure_utc(datetime.fromisoformat(candidate))
    except ValueError:
        pass

    if stripped.lstrip("-+0123456789") in {"", "."} and any(char.isdigit() for char in stripped):
        return _from_epoch(float(stripped), field_name=field_name)

    try:
        return ensure_utc(date_parser.parse(stripped))
    except (ValueError, TypeError, OverflowError) as exc:
        raise MalformedEventError(
            f"{field_name}={stripped!r} is not a recognised timestamp", field=field_name
        ) from exc


def to_iso_z(value: datetime) -> str:
    """Render as the `2026-10-22T09:15:00.000Z` form Elasticsearch and the fixtures use."""
    return ensure_utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_epoch_millis(value: datetime) -> int:
    return int(ensure_utc(value).timestamp() * 1000)


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds from `Retry-After`, whether it is a delta or an HTTP-date.

    Returning ``None`` means "no instruction from the server" — the caller then falls back
    to its own backoff instead of treating an unparsable header as zero wait.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.isdigit():
        return float(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    reference = now or utc_now()
    return max(0.0, (when - reference).total_seconds())
