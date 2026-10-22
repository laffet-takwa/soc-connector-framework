"""The ECS contract: aliases, timestamp coercion, severity, dedup keys and serialisation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.schema.ecs_models import (
    ECS_VERSION,
    CloudFieldSet,
    EcsEvent,
    Endpoint,
    EventCategory,
    EventFieldSet,
    EventKind,
    EventOutcome,
    NatInfo,
    NetworkDirection,
    UserFieldSet,
    build_event,
    to_document,
)
from soc_connectors.schema.redaction import RedactionSettings

pytestmark = pytest.mark.unit

BASE_TIME = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)
DOC_IPS = ("192.0.2.10", "198.51.100.22", "203.0.113.7")


def test_document_uses_ecs_aliases_and_iso_z() -> None:
    event = build_event(**{"@timestamp": BASE_TIME, "event": {"action": "login"}})
    document = to_document(event)
    assert document["@timestamp"] == "2026-10-22T09:00:00.000Z"
    assert document["ecs"] == {"version": ECS_VERSION}
    assert "@timestamp" not in json.dumps(document["event"])


def test_naive_timestamps_are_read_as_utc_and_rendered_z() -> None:
    naive = datetime(2026, 10, 22, 9, 0, 0)
    event = build_event(**{"@timestamp": naive})
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)
    assert to_document(event)["@timestamp"].endswith("Z")


INSTANT = datetime(2026, 10, 22, 7, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-22T09:00:00+02:00",
        "2026-10-22T07:00:00Z",
        "2026-10-22 07:00:00",
        int(INSTANT.timestamp()),
        int(INSTANT.timestamp()) * 1000,
    ],
)
def test_every_source_time_shape_lands_on_the_same_instant(value: object) -> None:
    event = build_event(**{"@timestamp": value})
    assert event.timestamp == INSTANT


def test_unparsable_timestamp_is_a_malformed_event_not_a_crash() -> None:
    with pytest.raises(MalformedEventError, match="@timestamp"):
        build_event(**{"@timestamp": "yesterday-ish"})


def test_severity_is_always_present_and_always_bounded() -> None:
    assert build_event(**{"event": {"severity": 500}}).score == 99
    assert build_event(**{"event": {"severity": -20}}).score == 0
    assert build_event().score == 50
    assert to_document(build_event(**{"event": {"severity": None}}))["event"]["severity"] == 50


@pytest.mark.parametrize(
    ("score", "band"), [(5, "low"), (45, "medium"), (70, "high"), (90, "critical")]
)
def test_severity_bands(score: int, band: str) -> None:
    assert build_event(**{"event": {"severity": score}}).severity_band == band


def test_high_severity_threshold_uses_the_clamped_score() -> None:
    event = build_event(**{"event": {"severity": 88}})
    assert event.is_high(85) and not event.is_high(90)


def test_enums_accept_source_strings_and_serialise_to_values() -> None:
    event = build_event(
        **{
            "event": {
                "kind": "ALERT",
                "outcome": "Failure",
                "category": ["Network", "network"],
                "type": "info",
            },
            "network": {"direction": "Inbound"},
        }
    )
    assert event.event.kind is EventKind.ALERT
    assert event.event.outcome is EventOutcome.FAILURE
    assert event.event.category == ["network"]
    assert event.network is not None and event.network.direction is NetworkDirection.INBOUND
    document = to_document(event)
    assert document["event"]["kind"] == "alert"
    assert document["event"]["type"] == ["info"]


def test_category_enum_lists_the_values_this_framework_emits() -> None:
    values = EventCategory.values()
    assert {"authentication", "network", "configuration"} <= set(values)


def test_empty_containers_are_stripped_and_unknown_fields_survive() -> None:
    event = build_event(
        **{
            "event": {"action": "x", "category": [], "hash": ""},
            "source": Endpoint(ip=None, nat=NatInfo()),
            "sdk_version": "1.2",
        }
    )
    document = to_document(event)
    assert "category" not in document["event"]
    assert "hash" not in document["event"]
    assert "source" not in document
    assert document["sdk_version"] == "1.2"


def test_identity_key_prefers_the_source_event_id() -> None:
    first = build_event(**{"event": {"id": "abc", "dataset": "cloudtrail.mgmt"}})
    same = build_event(
        **{"event": {"id": "abc", "dataset": "cloudtrail.mgmt", "action": "different"}}
    )
    assert first.identity_key() == same.identity_key() == "cloudtrail.mgmt:abc"


def test_identity_key_hashes_content_when_the_source_has_no_id() -> None:
    # A fixed @timestamp on purpose: without an explicit one every event stamps itself with
    # the wall clock, and two "identical" events built a millisecond apart would disagree.
    a = build_event(
        **{
            "@timestamp": BASE_TIME,
            "event": {"action": "deny", "dataset": "fw.deny"},
            "source": {"ip": DOC_IPS[0]},
        }
    )
    b = build_event(
        **{
            "@timestamp": BASE_TIME,
            "event": {"action": "deny", "dataset": "fw.deny"},
            "source": {"ip": DOC_IPS[0]},
        }
    )
    c = build_event(
        **{
            "@timestamp": BASE_TIME,
            "event": {"action": "deny", "dataset": "fw.deny"},
            "source": {"ip": DOC_IPS[2]},
        }
    )
    assert a.identity_key() == b.identity_key()
    assert a.identity_key() != c.identity_key()
    assert a.identity_key().startswith("h:")


def test_two_events_at_different_seconds_do_not_collapse_into_one_identity() -> None:
    """The hash has to separate a repeated line from the same line one second later."""
    first = build_event(
        **{"@timestamp": BASE_TIME, "event": {"action": "deny", "dataset": "fw.deny"}}
    )
    later = build_event(
        **{
            "@timestamp": BASE_TIME + timedelta(seconds=1),
            "event": {"action": "deny", "dataset": "fw.deny"},
        }
    )
    assert first.identity_key() != later.identity_key()


def test_build_event_reports_schema_problems_as_malformed() -> None:
    with pytest.raises(MalformedEventError, match="not a valid ECS document"):
        build_event(**{"event": {"severity": "not-a-number"}})


def test_redaction_is_applied_at_serialisation_only() -> None:
    event = build_event(
        **{"user": UserFieldSet(name="j.doe"), "cloud": CloudFieldSet(account_id="123456789012")}
    )
    plain = to_document(event)
    masked = to_document(
        event, RedactionSettings(fields=["user.name", "cloud.account.id"], mode="mask")
    )
    assert plain["user"]["name"] == "j.doe"
    assert masked["user"]["name"] == "***"
    assert event.user is not None and event.user.name == "j.doe"


def test_redaction_can_drop_the_raw_payload() -> None:
    event = build_event(**{"raw": {"secret_blob": "x" * 400}})
    assert "raw" in to_document(event)
    assert "raw" not in to_document(event, RedactionSettings(keep_raw=False))


def test_labels_are_stringified_and_tags_deduplicated() -> None:
    event = build_event(**{"labels": {"team": 7}, "tags": ["SOC", "soc", "demo"]})
    document = to_document(event)
    assert document["labels"] == {"team": "7"}
    assert document["tags"] == ["soc", "demo"]


def test_field_sets_are_reusable_models() -> None:
    event = EcsEvent(
        event=EventFieldSet(action="a"),
        source=Endpoint(ip=DOC_IPS[1], port=443, nat=NatInfo(ip="192.0.2.1", port=4430)),
    )
    document = to_document(event)
    assert document["source"]["nat"]["ip"] == "192.0.2.1"
    assert document["source"]["port"] == 443


def test_out_of_range_port_is_rejected() -> None:
    with pytest.raises(MalformedEventError):
        build_event(**{"source": {"port": 70000}})
