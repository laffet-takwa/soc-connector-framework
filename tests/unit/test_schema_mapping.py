"""Flat source fields to a nested ECS document, without silently dropping anything."""

from __future__ import annotations

from typing import Any

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.schema.mapping import (
    REPEATED_PATHS,
    TOP_LEVEL_KEYS,
    from_flat,
    prune,
    set_dotted,
)

pytestmark = pytest.mark.unit

TOP_LEVEL_SAMPLE_VALUES = {
    "@timestamp": "2026-10-22T09:00:00Z",
    "message": "deny tcp 203.0.113.9",
    "tags": ["probe"],
    "labels": {"team": "soc"},
    "raw": {"line": "srcip=203.0.113.9"},
}


def _leaf(document: dict[str, Any], path: str) -> Any:
    """Read a dotted path out of a partially built document, for assertions only."""
    target: Any = document
    for part in path.split("."):
        target = target[part]
    return target


def test_set_dotted_builds_the_intermediate_objects() -> None:
    document: dict[str, object] = {}
    set_dotted(document, "source.ip", "203.0.113.9")
    set_dotted(document, "source.port", 443)
    set_dotted(document, "@timestamp", "2026-10-22T09:00:00Z")
    assert document == {
        "source": {"ip": "203.0.113.9", "port": 443},
        "@timestamp": "2026-10-22T09:00:00Z",
    }


def test_set_dotted_refuses_an_empty_path() -> None:
    document: dict[str, object] = {}
    with pytest.raises(MalformedEventError, match="empty ECS path"):
        set_dotted(document, "..", "x")


def test_set_dotted_refuses_to_walk_through_a_scalar() -> None:
    document = {"source": "10.0.0.1"}
    with pytest.raises(MalformedEventError, match="already"):
        set_dotted(document, "source.ip", "10.0.0.2")


def test_repeated_paths_accumulate_instead_of_overwriting() -> None:
    document: dict[str, object] = {}
    set_dotted(document, "event.category", ["network"])
    set_dotted(document, "event.category", "network")
    set_dotted(document, "event.category", ["file"])
    assert document == {"event": {"category": ["network", "file"]}}


def test_a_repeated_path_accepts_a_bare_set() -> None:
    document: dict[str, Any] = {}
    set_dotted(document, "related.user", {"alice", "bob"})
    assert sorted(_leaf(document, "related.user")) == ["alice", "bob"]


@pytest.mark.parametrize("path", sorted(REPEATED_PATHS))
def test_every_repeated_path_starts_empty(path: str) -> None:
    document: dict[str, Any] = {}
    set_dotted(document, path, "one")
    set_dotted(document, path, "two")
    assert _leaf(document, path) == ["one", "two"]


def test_prune_removes_nothing_bearing_values_at_any_depth() -> None:
    """A container that empties out during pruning goes too — ECS has no use for ``{}``."""
    assert prune(
        {
            "event": {"action": "x", "type": [], "hash": "", "nested": {"empty": None}},
            "user": {"name": "kept"},
            "cloud": {},
            "source": {"nat": {"ip": "", "port": None}},
        }
    ) == {"event": {"action": "x"}, "user": {"name": "kept"}}


def test_from_flat_uses_an_alias_table() -> None:
    event = from_flat(
        {"srcip": "203.0.113.9", "srcport": "51234", "date": "2026-10-22T09:00:00Z"},
        aliases={"srcip": "source.ip", "srcport": "source.port", "date": "@timestamp"},
    )
    assert event.source is not None
    assert event.source.ip == "203.0.113.9"
    document = event.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert document["source"]["ip"] == "203.0.113.9"
    assert document["source"]["port"] == 51234
    assert document["@timestamp"].startswith("2026-10-22T09:00:00")


def test_from_flat_takes_ecs_paths_directly_and_applies_defaults() -> None:
    event = from_flat(
        {"event.action": "deny", "source.ip": "203.0.113.9"},
        defaults={"event.module": "fortinet", "event.dataset": "fortinet.firewall"},
    )
    document = event.model_dump(by_alias=True, exclude_none=True)
    assert document["event"]["module"] == "fortinet"
    assert document["event"]["dataset"] == "fortinet.firewall"
    assert document["event"]["action"] == "deny"


def test_defaults_never_overwrite_a_value_the_source_gave() -> None:
    """Defaults are written last, so a source that does report its dataset keeps its own."""
    event = from_flat({"event.dataset": "actual.dataset"}, defaults={"event.dataset": "fallback"})
    assert event.model_dump(by_alias=True)["event"]["dataset"] == "actual.dataset"


def test_a_repeated_field_from_a_default_and_a_source_both_survive() -> None:
    """Repeated paths accumulate rather than overwrite, whatever wrote them."""
    event = from_flat({"event.category": "network"}, defaults={"event.category": ["web"]})
    assert sorted(event.model_dump(by_alias=True)["event"]["category"]) == ["network", "web"]


@pytest.mark.parametrize("value", [None, ""])
def test_empty_values_are_never_mapped(value: object) -> None:
    event = from_flat({"event.action": value, "event.kind": "event"})
    assert "action" not in event.model_dump(by_alias=True, exclude_none=True)["event"]


def test_an_unaliased_source_field_is_a_rejected_mapping_not_a_silent_drop() -> None:
    with pytest.raises(MalformedEventError, match="not an ECS path"):
        from_flat({"srcip": "203.0.113.9"})


@pytest.mark.parametrize("key", sorted(TOP_LEVEL_KEYS))
def test_bare_top_level_keys_are_allowed(key: str) -> None:
    event = from_flat({key: TOP_LEVEL_SAMPLE_VALUES[key]})
    document = event.model_dump(mode="json", by_alias=True, exclude_none=True)
    if key == "@timestamp":
        assert document[key].startswith("2026-10-22T09:00:00")
    else:
        assert document[key] == TOP_LEVEL_SAMPLE_VALUES[key]


def test_an_alias_that_points_at_a_bad_path_reports_the_source_field() -> None:
    with pytest.raises(MalformedEventError):
        from_flat({"srcip": "203.0.113.9"}, aliases={"srcip": ""})
