"""The severity scales and the conversions between them."""

from __future__ import annotations

from typing import Any

import pytest

from soc_connectors.schema import severity
from soc_connectors.schema.severity import (
    BANDS,
    band,
    clamp,
    from_conditional_access_result,
    from_risk_level,
    from_syslog_priority,
    to_thehive,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 50), (0, 0), (99, 99), (-5, 0), (400, 99), (42.7, 42), ("61", 61), ("high", 50)],
)
def test_clamp_forces_every_source_score_into_0_99(value: Any, expected: int) -> None:
    assert clamp(value) == expected


def test_clamp_default_is_configurable() -> None:
    assert clamp(None, default=0) == 0


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (84, "high"),
        (85, "critical"),
        (99, "critical"),
    ],
)
def test_bands_use_the_documented_thresholds(score: int, label: str) -> None:
    assert band(score) == label


def test_band_of_a_missing_score_is_medium() -> None:
    assert band(None) == "medium"


def test_bands_are_monotonic() -> None:
    lower_bounds = [lower for lower, _ in BANDS]
    assert lower_bounds == sorted(lower_bounds)
    assert [label for _, label in BANDS] == ["low", "medium", "high", "critical"]


@pytest.mark.parametrize(
    ("priority", "expected"),
    [(0, 99), (1, 85), (3, 57), (7, 1), (None, 50), (8, 50), (-1, 50)],
)
def test_syslog_priority_is_inverted_onto_the_scale(priority: int | None, expected: int) -> None:
    """emerg (0) is the worst syslog severity, so it must land at the top of the ECS scale."""
    assert from_syslog_priority(priority) == expected


@pytest.mark.parametrize(
    ("level", "expected"),
    [("high", 85), ("HIGH", 85), (" none ", 10), ("unknown", 25), (None, 50), ("invented", 50)],
)
def test_unknown_risk_levels_never_default_to_zero(level: str | None, expected: int) -> None:
    assert from_risk_level(level) == expected


@pytest.mark.parametrize(
    ("result", "expected"),
    [("success", 10), ("blocked", 80), ("failure", 55), ("whatever", 40), (None, 40)],
)
def test_conditional_access_results(result: str | None, expected: int) -> None:
    assert from_conditional_access_result(result) == expected


@pytest.mark.parametrize(("score", "hive"), [(0, 1), (29, 1), (30, 2), (60, 3), (85, 4), (99, 4)])
def test_thehive_bands_follow_the_same_thresholds(score: int, hive: int) -> None:
    assert to_thehive(score) == hive


def test_thehive_and_band_never_disagree() -> None:
    for score in range(0, 100):
        assert (to_thehive(score) == 4) == (band(score) == "critical")
        assert 1 <= to_thehive(score) <= 4


def test_syslog_and_unknown_defaults_share_one_constant() -> None:
    assert from_syslog_priority(None) == severity.UNKNOWN_SCORE
    assert clamp(None) == severity.UNKNOWN_SCORE
