"""Fan-out: the two units of counting, and the independence of destinations.

The dispatch report deliberately mixes two units — delivery *records* and *events* — so a cycle
report cannot be inflated by fan-out. Every assertion here separates those two, checks that a
failing destination cannot stop a healthy one, and confirms the dead-letter file carries the
document with the destination's own reason.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from soc_connectors.exceptions import PermanentError, TransientError
from soc_connectors.forwarders.base import DeliveryResult
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.dispatcher import Dispatcher, DispatchReport, Route
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.types import CycleReport
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.retry import RetryPolicy

pytestmark = pytest.mark.unit

MakeEvents = Callable[..., list[EcsEvent]]
MakeEvent = Callable[..., EcsEvent]
MakeForwarder = Callable[..., Any]
CaptureLogs = Callable[[str], list[Any]]

POLICY = RetryPolicy(max_attempts=3, base_wait_seconds=0, max_wait_seconds=0, jitter_ratio=0)


def route_for(forwarder: Any, **kwargs: Any) -> Route:
    return Route(forwarder=forwarder, retry_policy=POLICY, **kwargs)


# -- the value objects -------------------------------------------------------


def test_a_route_carries_safe_defaults(make_forwarder: MakeForwarder) -> None:
    built = Route(forwarder=make_forwarder("es"))
    assert (built.severity_min, built.batch_size) == (0, 200)
    assert built.retry_policy == RetryPolicy()


def test_an_empty_report_is_not_failed_and_grows_a_destination_entry_on_demand() -> None:
    report = DispatchReport(routed=1)
    assert report.failed is False
    assert report.per_destination == {}
    totals = report.totals("es")
    totals["accepted"] += 3
    assert report.per_destination == {
        "es": {"accepted": 3, "rejected": 0, "dead_lettered": 0, "skipped": 0}
    }
    assert report.totals("es") is totals, "the same dict, not a fresh one"


@pytest.mark.parametrize(
    ("accepted", "rejected", "errors", "expected"),
    [(3, 0, [], False), (2, 1, [], True), (2, 0, ["es: 503"], True), (0, 0, [], False)],
)
def test_a_dispatch_is_failed_by_any_refusal_or_error(
    accepted: int, rejected: int, errors: list[str], expected: bool
) -> None:
    report = DispatchReport(accepted=accepted, rejected=rejected, errors=list(errors))
    assert report.failed is expected


# -- happy paths -------------------------------------------------------------


def test_a_healthy_route_accepts_the_whole_batch_and_counts_one_event_delivered(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder("es")
    events = make_events(3)
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(events, source_id="demo")
    assert (report.routed, report.accepted, report.events_delivered) == (3, 3, 3)
    assert report.events_failed == 0 and report.errors == []
    assert report.per_destination["es"]["accepted"] == 3
    assert metrics.for_source("es")["forwarded"] == 3
    assert [event.identity_key() for event in forwarder.batches[0]] == [
        event.identity_key() for event in events
    ]


def test_fan_out_counts_two_records_but_still_one_event(
    make_forwarder: MakeForwarder, make_event: MakeEvent, metrics: Metrics
) -> None:
    report = Dispatcher(
        [route_for(make_forwarder("es")), route_for(make_forwarder("wazuh"))], metrics=metrics
    ).dispatch([make_event()], source_id="demo")
    assert report.accepted == 2, "delivery records"
    assert report.events_delivered == 1, "events"
    assert sorted(report.per_destination) == ["es", "wazuh"]


def test_no_route_is_visited_for_an_empty_batch(
    make_forwarder: MakeForwarder, metrics: Metrics
) -> None:
    forwarder = make_forwarder("es")
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch([], source_id="demo")
    assert (report.routed, report.accepted, report.events_delivered) == (0, 0, 0)
    assert forwarder.batches == []
    assert report.per_destination["es"]["skipped"] == 0


def test_a_batch_is_split_by_the_routes_own_size(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder("es")
    Dispatcher([route_for(forwarder, batch_size=2)], metrics=metrics).dispatch(
        make_events(5), source_id="demo"
    )
    assert [len(batch) for batch in forwarder.batches] == [2, 2, 1]
    assert forwarder.sent_count == 5


# -- severity floors ---------------------------------------------------------


def test_a_severity_floor_skips_quiet_events_without_calling_the_destination(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder("hive")
    events = make_events(4, severity=40)
    report = Dispatcher([route_for(forwarder, severity_min=80)], metrics=metrics).dispatch(
        events, source_id="demo"
    )
    assert [event.score for event in events] == [40, 41, 42, 43]
    assert forwarder.batches == []
    assert report.per_destination["hive"]["skipped"] == 4
    assert report.accepted == 0
    assert report.events_delivered == 4, "a filtered event was never owed to this destination"
    assert report.errors == []


def test_each_destination_applies_its_own_floor_to_the_same_events(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    index, alerts = make_forwarder("es"), make_forwarder("hive")
    events = make_events(4, severity=78)
    report = Dispatcher(
        [route_for(index), route_for(alerts, severity_min=80)], metrics=metrics
    ).dispatch(events, source_id="demo")
    assert index.sent_count == 4
    assert alerts.sent_count == 2, "only the two events at or above 80"
    assert report.per_destination["hive"]["skipped"] == 2
    assert report.events_delivered == 4


def test_the_floor_uses_the_clamped_ecs_severity(
    make_forwarder: MakeForwarder, make_event: MakeEvent, metrics: Metrics
) -> None:
    """An event with no severity at all is not silently routed to an alert destination."""
    events = [make_event(event={"action": "no-severity"})]
    assert events[0].score == 50, "an unknown severity is medium, never ignore"

    above = make_forwarder("hive-50")
    Dispatcher([route_for(above, severity_min=50)], metrics=metrics).dispatch(
        events, source_id="demo"
    )
    assert above.sent_count == 1

    below = make_forwarder("hive-51")
    Dispatcher([route_for(below, severity_min=51)], metrics=metrics).dispatch(
        events, source_id="demo"
    )
    assert below.batches == []


# -- failures ---------------------------------------------------------------


def test_a_destination_that_raises_every_time_fails_only_itself(
    make_forwarder: MakeForwarder,
    make_events: MakeEvents,
    metrics: Metrics,
    dead_letter: DeadLetterQueue,
) -> None:
    broken = make_forwarder("es", results=[PermanentError("403 forbidden")] * 3)
    healthy = make_forwarder("wazuh")
    events = make_events(2)
    report = Dispatcher([route_for(broken), route_for(healthy)], metrics=metrics).dispatch(
        events, source_id="demo", dead_letter=dead_letter
    )

    assert healthy.sent_count == 2, "an Elasticsearch outage must not stop the Wazuh file"
    assert report.accepted == 2
    assert report.events_delivered == 0, "no event reached every route that wanted it"
    assert report.events_failed == 2
    assert len(report.errors) == 1 and "es:" in report.errors[0]
    assert report.per_destination["es"]["dead_lettered"] == 2
    assert metrics.for_source("es")["failed"] == 2

    dead = list(dead_letter.records())
    assert len(dead) == 2
    assert {record["connector_id"] for record in dead} == {"es"}
    assert all(record["stage"] == "forward" for record in dead)
    assert all("failed the batch after retries" in record["reason"] for record in dead)
    assert all(record["error_type"] == "PermanentError" for record in dead)
    assert all("event" in record for record in dead)


def test_a_transient_failure_is_retried_per_destination_and_the_events_still_land(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder("es", results=[TransientError("502"), DeliveryResult(accepted=2)])
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        make_events(2), source_id="demo"
    )
    assert report.accepted == 2 and report.errors == []
    assert len(forwarder.batches) == 2
    assert metrics.for_source("es")["retried"] == 1
    assert metrics.for_source("es")["forwarded"] == 2


def test_a_send_that_never_returns_succeeding_is_dead_lettered_once_per_event(
    make_forwarder: MakeForwarder,
    make_events: MakeEvents,
    metrics: Metrics,
    dead_letter: DeadLetterQueue,
) -> None:
    forwarder = make_forwarder("es", results=[ConnectionError("reset")] * 3)
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        make_events(3), source_id="demo", dead_letter=dead_letter
    )
    assert len(forwarder.batches) == 3, "the policy retried the batch, not each event"
    assert report.dead_lettered == 3
    assert dead_letter.count() == 3
    assert report.failed


def test_without_a_dead_letter_queue_a_failure_is_still_reported(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder("es", results=[PermanentError("403 forbidden")] * 3)
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        make_events(2), source_id="demo"
    )
    assert (report.dead_lettered, report.events_failed) == (0, 2)
    assert len(report.errors) == 1


def test_per_item_rejections_are_dead_lettered_with_their_own_document(
    make_forwarder: MakeForwarder,
    make_events: MakeEvents,
    metrics: Metrics,
    dead_letter: DeadLetterQueue,
) -> None:
    events = make_events(3)
    refused = events[1]
    forwarder = make_forwarder(
        "es",
        results=[
            DeliveryResult(
                accepted=2,
                rejected=[
                    {"identity": refused.identity_key(), "reason": "mapper_parsing_exception"}
                ],
            )
        ],
    )
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        events, source_id="demo", dead_letter=dead_letter
    )
    assert (report.accepted, report.rejected, report.dead_lettered) == (2, 1, 1)
    assert report.events_delivered == 2 and report.events_failed == 1
    assert report.per_destination["es"]["rejected"] == 1
    assert metrics.for_source("es")["failed"] == 1

    (record,) = list(dead_letter.records())
    assert record["identity"] == refused.identity_key()
    assert "mapper_parsing_exception" in record["reason"]
    assert record["event"]["event"]["action"] == "action-1"
    assert "error_type" in record and record["error_type"] is None


def test_an_anonymous_refusal_is_counted_as_a_failed_event_and_flagged(
    make_forwarder: MakeForwarder,
    make_events: MakeEvents,
    metrics: Metrics,
    dead_letter: DeadLetterQueue,
) -> None:
    """A destination that refuses documents without naming them must not inflate the count.

    The event-level numbers come from identities, so an anonymous refusal is counted under a key
    no real identity can produce and the failure is reported as a contract breach.
    """
    forwarder = make_forwarder(
        "es",
        results=[
            DeliveryResult(
                accepted=1,
                rejected=[{"reason": "index closed"}, {"identity": "", "reason": "index closed"}],
            )
        ],
    )
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        make_events(3), source_id="demo", dead_letter=dead_letter
    )
    assert (report.accepted, report.rejected, report.dead_lettered) == (1, 2, 2)
    assert report.events_failed == 2 and report.events_delivered == 1
    assert report.errors == ["es: refused 2 document(s) without naming their identity"]
    assert report.failed
    dead = list(dead_letter.records())
    assert len(dead) == 2
    assert all("index closed" in record["reason"] for record in dead)
    assert all("event" not in record for record in dead), "no document could be matched"
    assert all(record["identity"] is None for record in dead)


def test_a_partially_failed_batch_carries_its_error_message_into_the_report(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    forwarder = make_forwarder(
        "es", results=[DeliveryResult(accepted=1, error="some items failed")]
    )
    report = Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(
        make_events(1), source_id="demo"
    )
    assert report.errors == ["es: some items failed"]
    assert report.failed


def test_the_record_dead_lettered_is_the_redacted_document(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics, tmp_path: Any
) -> None:
    queue = DeadLetterQueue(tmp_path / "dl" / "es.jsonl")
    redaction = RedactionSettings(fields=["user.name"], mode="drop", ip_mode="drop")
    forwarder = make_forwarder("es", results=[PermanentError("403 forbidden")] * 3)
    Dispatcher([route_for(forwarder)], metrics=metrics, redaction=redaction).dispatch(
        make_events(1), source_id="demo", dead_letter=queue
    )
    (record,) = list(queue.records())
    assert "user" not in record["event"]
    assert "source" not in record["event"]


def test_the_dispatcher_logs_the_failure_with_the_destination_and_batch_size(
    make_forwarder: MakeForwarder,
    make_events: MakeEvents,
    metrics: Metrics,
    capture_logs: CaptureLogs,
) -> None:
    logs = capture_logs("dispatcher")
    forwarder = make_forwarder("es", results=[PermanentError("403 forbidden")] * 3)
    Dispatcher([route_for(forwarder)], metrics=metrics).dispatch(make_events(2), source_id="demo")
    failures = [record for record in logs if "destination batch failed" in record.getMessage()]
    assert len(failures) == 1
    assert failures[0].levelname == "ERROR"
    assert failures[0].destination == "es"
    assert failures[0].batch_size == 2
    assert failures[0].source_id == "demo"


# -- the report as the CLI sees it -------------------------------------------


def test_a_cycle_report_of_a_dispatch_keeps_events_not_records(
    make_forwarder: MakeForwarder, make_events: MakeEvents, metrics: Metrics
) -> None:
    report = Dispatcher(
        [route_for(make_forwarder("es")), route_for(make_forwarder("wazuh"))], metrics=metrics
    ).dispatch(make_events(2), source_id="demo")
    cycle = CycleReport(
        connector_id="demo",
        fetched=2,
        normalized=2,
        forwarded=report.events_delivered,
        dead_lettered=report.dead_lettered,
        duplicates=0,
        cursor="7",
    )
    assert cycle.as_dict()["forwarded"] == 2
    assert cycle.as_dict()["error"] is None
