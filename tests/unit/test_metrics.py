"""Stage counters: the only answer to "is my connector still working?"."""

from __future__ import annotations

import threading

import pytest

from soc_connectors.metrics import DURATION_SAMPLES_KEPT, STAGES, Metrics

pytestmark = pytest.mark.unit


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


def test_a_stage_counts_once_globally_and_once_per_source(metrics: Metrics) -> None:
    metrics.incr("fetched", source="cloudtrail")
    metrics.incr("fetched", source="entra")
    metrics.incr("forwarded", source="cloudtrail")
    assert metrics.total("fetched") == 2
    assert metrics.for_source("cloudtrail") == {"fetched": 1, "forwarded": 1}
    assert metrics.for_source("entra") == {"fetched": 1}


def test_incr_can_add_more_than_one_event(metrics: Metrics) -> None:
    metrics.incr("normalized", by=25)
    assert metrics.total("normalized") == 25


def test_an_unknown_stage_is_refused_before_it_becomes_a_typo_in_a_dashboard(
    metrics: Metrics,
) -> None:
    with pytest.raises(ValueError, match="unknown metric stage 'fatched'"):
        metrics.incr("fatched")


@pytest.mark.parametrize("stage", STAGES)
def test_every_documented_stage_is_countable(stage: str) -> None:
    metrics = Metrics()
    metrics.incr(stage)
    assert metrics.total(stage) == 1


def test_a_stage_never_seen_has_a_zero_and_does_not_look_used(metrics: Metrics) -> None:
    assert metrics.is_idle()
    assert metrics.total("failed") == 0
    assert metrics.is_idle(), "reading a counter must not create it"


def test_any_activity_ends_the_idle_state(metrics: Metrics) -> None:
    metrics.incr("cycles", source="syslog")
    assert not metrics.is_idle()
    assert metrics.for_source("unknown-source") == {}


def test_snapshot_reports_totals_sources_and_uptime(metrics: Metrics) -> None:
    metrics.incr("fetched", source="demo")
    metrics.incr("failed", source="demo")
    snapshot = metrics.snapshot()
    assert snapshot["totals"] == {"fetched": 1, "failed": 1}
    assert snapshot["sources"] == {"demo": {"fetched": 1, "failed": 1}}
    assert snapshot["uptime_seconds"] >= 0
    assert snapshot["updated_at"].endswith("Z")


def test_snapshot_ordering_is_stable(metrics: Metrics) -> None:
    """Sorted on both axes, so two snapshots of the same state are interchangeable."""
    metrics.incr("parsed", source="b")
    metrics.incr("parsed", source="a")
    first, second = metrics.snapshot(), metrics.snapshot()
    assert list(first["totals"]) == ["parsed"]
    assert list(first["sources"]) == ["a", "b"]
    assert first["sources"] == second["sources"]


def test_durations_are_recorded_in_milliseconds(metrics: Metrics) -> None:
    metrics.add_duration("forward.batch", 0.0125)
    entry = metrics.snapshot()["duration_ms"]["forward.batch"]
    assert entry == {"last": 12.5, "max": 12.5, "avg": 12.5}


def test_durations_summarise_last_max_and_avg(metrics: Metrics) -> None:
    for seconds in (0.001, 0.005, 0.003):
        metrics.add_duration("cycle", seconds)
    entry = metrics.snapshot()["duration_ms"]["cycle"]
    assert entry == {"last": 3.0, "max": 5.0, "avg": 3.0}


def test_only_the_recent_samples_are_kept(metrics: Metrics) -> None:
    """Unbounded latency history would grow with uptime; a window is enough for p-max."""
    for index in range(DURATION_SAMPLES_KEPT + 50):
        metrics.add_duration("cycle", float(index))
    entry = metrics.snapshot()["duration_ms"]["cycle"]
    kept = [float(index) * 1000.0 for index in range(50, DURATION_SAMPLES_KEPT + 50)]
    assert entry["last"] == round(kept[-1], 2)
    assert entry["max"] == round(max(kept), 2)
    assert entry["avg"] == round(sum(kept) / len(kept), 2)


def test_the_timer_measures_the_block_it_wraps(metrics: Metrics) -> None:
    with metrics.timer("normalise"):
        sum(range(200))
    entry = metrics.snapshot()["duration_ms"]["normalise"]
    assert entry["last"] >= 0.0
    assert entry["max"] >= entry["last"]


def test_the_timer_still_propagates_a_failure_inside_it(metrics: Metrics) -> None:
    with pytest.raises(RuntimeError), metrics.timer("failing"):
        raise RuntimeError("boom")
    assert "failing" not in metrics.snapshot()["duration_ms"]


def test_counters_survive_concurrent_writers(metrics: Metrics) -> None:
    writers = 10
    per_writer = 100

    def write() -> None:
        for _ in range(per_writer):
            metrics.incr("normalized", source="worker")

    threads = [threading.Thread(target=write) for _ in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert metrics.total("normalized") == writers * per_writer
    assert metrics.for_source("worker")["normalized"] == writers * per_writer
