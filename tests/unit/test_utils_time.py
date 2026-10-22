"""Timestamp coercion: every format a real source has been observed to emit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.utils.time import (
    ensure_utc,
    parse_retry_after,
    parse_timestamp,
    to_epoch_millis,
    to_iso_z,
    utc_now,
)

pytestmark = pytest.mark.unit

INSTANT = datetime(2026, 10, 22, 9, 15, 0, 123000, tzinfo=UTC)


def test_utc_now_is_aware_and_utc() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_naive_timestamp_is_assumed_utc() -> None:
    naive = datetime(2026, 10, 22, 9, 15, 0)
    assert ensure_utc(naive) == INSTANT.replace(microsecond=0)
    assert ensure_utc(naive).tzinfo is UTC


def test_aware_timestamp_is_converted_not_relabeled() -> None:
    plus_two = datetime(2026, 10, 22, 11, 15, 0, tzinfo=timezone(timedelta(hours=2)))
    assert ensure_utc(plus_two) == INSTANT.replace(microsecond=0)


@pytest.mark.parametrize(
    "text",
    [
        "2026-10-22T09:15:00.123Z",
        "2026-10-22T09:15:00.123z",
        "2026-10-22T09:15:00.123+00:00",
        "2026-10-22 09:15:00.123Z",
        "2026-10-22T11:15:00.123+02:00",
    ],
)
def test_iso_forms_all_land_on_the_same_instant(text: str) -> None:
    assert parse_timestamp(text) == INSTANT


def test_epoch_seconds_and_millis_agree() -> None:
    seconds = int(INSTANT.timestamp())
    assert parse_timestamp(seconds) == parse_timestamp(f"{seconds}")
    assert parse_timestamp(seconds * 1000) == parse_timestamp(seconds * 1000.0)


def test_float_millis_keep_the_milliseconds() -> None:
    millis = to_epoch_millis(INSTANT)
    assert parse_timestamp(millis) == INSTANT


@pytest.mark.parametrize("value", [True, False])
def test_bool_is_rejected_before_the_int_branch(value: bool) -> None:
    with pytest.raises(MalformedEventError, match="is a bool"):
        parse_timestamp(value)


@pytest.mark.parametrize("value", ["", "   ", None, ["2026-10-22"], object()])
def test_unusable_values_raise_with_the_field_name(value: Any) -> None:
    with pytest.raises(MalformedEventError) as exc_info:
        parse_timestamp(value, field_name="event.created")
    assert exc_info.value.field == "event.created"


def test_out_of_range_epoch_is_not_silently_clamped() -> None:
    with pytest.raises(MalformedEventError, match="outside the epoch range"):
        parse_timestamp(1e30)


def test_rfc_2822_style_falls_back_to_dateutil() -> None:
    assert parse_timestamp("22 Oct 2026 09:15:00 GMT") == INSTANT.replace(microsecond=0)


def test_to_iso_z_always_has_z_and_milliseconds() -> None:
    assert to_iso_z(INSTANT) == "2026-10-22T09:15:00.123Z"
    plus_one = datetime(2026, 10, 22, 10, 15, 0, tzinfo=timezone(timedelta(hours=1)))
    assert to_iso_z(plus_one) == "2026-10-22T09:15:00.000Z"


def test_epoch_round_trip() -> None:
    assert to_epoch_millis(parse_timestamp(to_epoch_millis(INSTANT))) == to_epoch_millis(INSTANT)


def test_retry_after_missing_or_blank_is_no_instruction() -> None:
    assert parse_retry_after(None) is None
    assert parse_retry_after("   ") is None


def test_retry_after_seconds() -> None:
    assert parse_retry_after("42") == 42.0


def test_retry_after_http_date_is_relative_to_the_supplied_now() -> None:
    reference = datetime(2026, 10, 22, 9, 15, 0, tzinfo=UTC)
    header = "Thu, 22 Oct 2026 09:16:30 GMT"
    assert parse_retry_after(header, now=reference) == 90.0


def test_retry_after_in_the_past_is_zero_not_negative() -> None:
    reference = datetime(2026, 10, 22, 9, 15, 0, tzinfo=UTC)
    assert parse_retry_after("Thu, 22 Oct 2026 09:14:00 GMT", now=reference) == 0.0


def test_retry_after_garbage_is_ignored() -> None:
    assert parse_retry_after("soon", now=datetime(2026, 10, 22, tzinfo=UTC)) is None
