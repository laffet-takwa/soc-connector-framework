"""Severity scales and the conversions between them.

ECS ``event.severity`` is 0-99, syslog priorities are 0-7 (descending), TheHive alerts are
1-4 (ascending). Normalizers emit one 0-99 score and everything else derives from it, so a
destination's odd scale never leaks back into the schema.
"""

from __future__ import annotations

from typing import Final

SEVERITY_MIN: Final = 0
SEVERITY_MAX: Final = 99
#: The score emitted when a source gives nothing usable — "medium", never "ignore".
UNKNOWN_SCORE: Final = 50

MEDIUM_AT: Final = 30
HIGH_AT: Final = 60
CRITICAL_AT: Final = 85

#: Inclusive lower bound for each band label.
BANDS: Final[tuple[tuple[int, str], ...]] = (
    (SEVERITY_MIN, "low"),
    (MEDIUM_AT, "medium"),
    (HIGH_AT, "high"),
    (CRITICAL_AT, "critical"),
)

#: syslog priority is 0 (emerg) .. 7 (debug); each step down the scale is worth 14 points.
SYSLOG_MIN_PRIORITY: Final = 0
SYSLOG_MAX_PRIORITY: Final = 7
SYSLOG_SCORE_STEP: Final = 14


def clamp(value: float | int | None, *, default: int = UNKNOWN_SCORE) -> int:
    """Force any source score into 0-99, treating a missing score as medium."""
    if value is None:
        return default
    try:
        score = int(value)
    except (TypeError, ValueError):
        return default
    return max(SEVERITY_MIN, min(SEVERITY_MAX, score))


def band(score: float | int | None) -> str:
    """Human-readable band, as ECS recommends exposing through ``event.severity`` too."""
    clamped = clamp(score)
    label = BANDS[0][1]
    for lower, candidate in BANDS:
        if clamped >= lower:
            label = candidate
    return label


def from_syslog_priority(priority: float | int | None) -> int:
    """syslog severity 0 (emerg) .. 7 (debug) onto the 0-99 scale."""
    if priority is None:
        return UNKNOWN_SCORE
    value = int(priority)
    if not SYSLOG_MIN_PRIORITY <= value <= SYSLOG_MAX_PRIORITY:
        return UNKNOWN_SCORE
    return clamp(SEVERITY_MAX - value * SYSLOG_SCORE_STEP)


_RISK_LEVELS = {"unknown": 25, "none": 10, "low": 45, "medium": 65, "high": 85}
_CA_RESULTS = {"success": 10, "notapplied": 20, "notenabled": 20, "failure": 55, "blocked": 80}


def from_risk_level(level: str | None) -> int:
    return _RISK_LEVELS.get((level or "").strip().lower(), UNKNOWN_SCORE)


def from_conditional_access_result(result: str | None) -> int:
    return _CA_RESULTS.get((result or "").strip().lower(), 40)


def to_thehive(score: float | int | None) -> int:
    """TheHive alert severity 1 (low) .. 4 (critical), clamped.

    TheHive's scale is ascending while syslog's is descending, which is exactly the kind of
    inversion a mapping table is for — see ``docs/field-mapping.md``. The band table is the
    single source of truth, so retuning thresholds changes both scales at once.
    """
    clamped = clamp(score)
    position = 1
    for index, (lower, _) in enumerate(BANDS):
        if clamped >= lower:
            position = index + 1
    return position
