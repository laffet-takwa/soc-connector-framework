"""Redaction: what leaves the process, and how much of it."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from soc_connectors.schema.redaction import (
    MASK,
    TRUNCATED_KEY,
    RedactionSettings,
    redact_document,
)

pytestmark = pytest.mark.unit


def document(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "@timestamp": "2026-10-22T09:00:00.000Z",
        "event": {"action": "signin", "severity": 42},
        "user": {"name": "j.doe", "domain": "example.com"},
        "source": {"ip": "203.0.113.24", "port": 51234},
        "cloud": {"account": {"id": "000000000000"}},
        "nat": {"ip": "192.0.2.5"},
        "host": {"name": "workstation-7"},
        "raw": {"user": "j.doe", "srcip": "203.0.113.24"},
    }
    base.update(overrides)
    return base


def test_settings_are_closed_to_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        RedactionSettings.model_validate({"unknown_switch": True})


def test_named_paths_are_masked_in_place() -> None:
    settings = RedactionSettings(fields=["user.name", "cloud.account.id"], mode="mask")
    result = redact_document(document(), settings)
    assert result["user"]["name"] == MASK
    assert result["cloud"]["account"]["id"] == MASK
    assert result["event"]["action"] == "signin"


def test_a_dropped_leaf_takes_its_empty_parents_with_it() -> None:
    """``cloud.account.id`` dropped must not leave a hollow ``cloud.account`` behind."""
    settings = RedactionSettings(fields=["user.name", "cloud.account.id"], mode="drop")
    result = redact_document(document(), settings)
    assert "name" not in result["user"]
    assert "cloud" not in result
    assert result["event"]["action"] == "signin"


def test_paths_that_do_not_exist_are_ignored() -> None:
    settings = RedactionSettings(fields=["nope.nested", "user.name"])
    assert "name" not in redact_document(
        document(), RedactionSettings(fields=["user"], mode="drop")
    )
    assert redact_document(document(), settings)["event"]["severity"] == 42


def test_a_scalar_on_the_way_blocks_the_path_without_crashing() -> None:
    settings = RedactionSettings(fields=["user.name.first"], mode="drop")
    assert "name" in redact_document(document(), settings)["user"]


@pytest.mark.parametrize("dotted", ["", ".", ".."])
def test_blank_paths_are_not_treated_as_the_whole_document(dotted: str) -> None:
    assert RedactionSettings(fields=[dotted]).normalized_fields() == []


def test_ip_addresses_can_be_dropped_entirely() -> None:
    result = redact_document(document(), RedactionSettings(ip_mode="drop"))
    assert "ip" not in result["source"]
    assert "nat" not in result  # its only field was the address
    assert result["source"]["port"] == 51234
    # `srcip` is not one of the ECS address keys the policy recognises, so it survives even a
    # drop: address policy is keyed on field names, not on the shape of the value.
    assert result["raw"]["srcip"] == "203.0.113.24"


def test_ip_addresses_can_be_coarsened_to_their_subnet() -> None:
    result = redact_document(document(), RedactionSettings(ip_mode="mask_subnet"))
    assert result["source"]["ip"] == "203.0.113.0"
    assert result["nat"]["ip"] == "192.0.2.0"


def test_masking_leaves_a_hostname_alone() -> None:
    result = redact_document(
        document(source={"ip": "dc01.example.com"}), RedactionSettings(ip_mode="mask_subnet")
    )
    assert result["source"]["ip"] == "dc01.example.com"


def test_ipv6_is_masked_to_its_64_prefix() -> None:
    result = redact_document(
        document(source={"ip": "2001:db8:dead:beef:1234:5678:9abc:def0"}),
        RedactionSettings(ip_mode="mask_subnet"),
    )
    assert result["source"]["ip"] == "2001:db8:dead:beef::"


def test_a_list_of_addresses_is_masked_entry_by_entry() -> None:
    """``related.ip`` is a list in ECS; masking only the scalar form would leak the host."""
    settings = RedactionSettings(ip_mode="mask_subnet")
    value = document(related={"ip": ["203.0.113.9", "198.51.100.4"]})
    result = redact_document(value, settings)
    assert result["related"]["ip"] == ["203.0.113.0", "198.51.100.0"]
    assert result["source"]["ip"] == "203.0.113.0"


def test_a_list_of_addresses_can_be_dropped_with_the_field() -> None:
    result = redact_document(
        document(related={"ip": ["203.0.113.9"]}), RedactionSettings(ip_mode="drop")
    )
    assert "related" not in result


def test_raw_is_kept_by_default() -> None:
    assert redact_document(document(), RedactionSettings())["raw"]["srcip"] == "203.0.113.24"


def test_raw_can_be_dropped_entirely() -> None:
    assert "raw" not in redact_document(document(), RedactionSettings(keep_raw=False))


def test_a_dotted_source_key_is_masked_in_the_raw_copy_too() -> None:
    # The source wrote `"user.name": "j.doe"` as one flat key. Masking only the shaped field
    # would leave the username two keys away in the same document.
    settings = RedactionSettings(fields=["user.name"])
    result = redact_document(document(raw={"user.name": "j.doe", "id": 7}), settings)
    assert result["raw"]["user.name"] == MASK
    assert result["raw"]["id"] == 7


def test_a_nested_source_field_is_masked_in_the_raw_copy_too() -> None:
    settings = RedactionSettings(fields=["user.name"], mode="drop")
    result = redact_document(
        document(raw={"user": {"name": "j.doe", "domain": "example.com"}}), settings
    )
    assert result["raw"]["user"] == {"domain": "example.com"}


def test_a_dropped_dotted_key_leaves_nothing_behind_in_raw() -> None:
    settings = RedactionSettings(fields=["user.name"], mode="drop")
    result = redact_document(document(raw={"user.name": "j.doe", "id": 7}), settings)
    assert "user.name" not in result["raw"]
    assert result["raw"] == {"id": 7}


def test_the_address_policy_reaches_a_dotted_address_in_raw() -> None:
    result = redact_document(
        document(raw={"source.ip": "203.0.113.24", "source.port": 51234}),
        RedactionSettings(ip_mode="mask_subnet"),
    )
    assert result["raw"]["source.ip"] == "203.0.113.0"
    assert result["raw"]["source.port"] == 51234


def test_a_dropped_address_policy_removes_the_key_from_raw() -> None:
    result = redact_document(
        document(raw={"source.ip": "203.0.113.24"}), RedactionSettings(ip_mode="drop")
    )
    assert "source.ip" not in result["raw"]


def test_raw_still_keeps_everything_the_policy_says_nothing_about() -> None:
    settings = RedactionSettings(fields=["user.name"])
    result = redact_document(document(raw={"srcip": "203.0.113.24", "msg": "hello"}), settings)
    assert result["raw"] == {"srcip": "203.0.113.24", "msg": "hello"}


def test_the_raw_budget_is_measured_after_the_raw_copy_is_masked() -> None:
    oversized = document(raw={"user.name": "j" * 400, "keeps": "yes"})
    without_policy = redact_document(oversized, RedactionSettings(max_raw_bytes=128))
    assert without_policy["raw"][TRUNCATED_KEY] == ["user.name"]
    # Masked first, the value no longer needs trimming: the budget is a size limit, not a
    # substitute for the field policy.
    masked = redact_document(oversized, RedactionSettings(fields=["user.name"], max_raw_bytes=128))
    assert masked["raw"]["user.name"] == MASK
    assert TRUNCATED_KEY not in masked["raw"]
    assert len(json.dumps(masked["raw"]).encode("utf-8")) <= 128


def test_redacting_raw_does_not_mutate_the_event_it_came_from() -> None:
    source = document(raw={"user.name": "j.doe"})
    redact_document(source, RedactionSettings(fields=["user.name"]))
    assert source["raw"]["user.name"] == "j.doe"


def test_an_oversized_raw_payload_is_trimmed_largest_first() -> None:
    settings = RedactionSettings(max_raw_bytes=200)
    result = redact_document(
        document(raw={"small": "1", "blob": "x" * 4000, "keeps": "yes"}), settings
    )
    assert "blob" not in result["raw"]
    assert result["raw"]["keeps"] == "yes"
    assert result["raw"][TRUNCATED_KEY] == ["blob"]


def test_a_raw_payload_that_still_does_not_fit_reports_every_dropped_key() -> None:
    settings = RedactionSettings(max_raw_bytes=128)
    result = redact_document(document(raw={"a": "y" * 300, "b": "z" * 300}), settings)
    assert result["raw"][TRUNCATED_KEY] == ["a", "b"]
    assert json.dumps(result, default=str)


def test_an_empty_raw_payload_is_left_alone() -> None:
    assert redact_document(document(raw={}), RedactionSettings())["raw"] == {}


def test_non_mapping_raw_is_not_stored_in_the_result() -> None:
    assert "raw" not in redact_document(document(raw="a plain line"), RedactionSettings())


def test_redaction_never_mutates_the_input_document() -> None:
    original = document()
    snapshot = json.dumps(original, sort_keys=True, default=str)
    redact_document(original, RedactionSettings(fields=["user.name"], ip_mode="mask_subnet"))
    assert json.dumps(original, sort_keys=True, default=str) == snapshot
