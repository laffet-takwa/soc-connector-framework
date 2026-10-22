"""Checkpoint state: restart position, dedup window, and what happens to a corrupt file."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from logging import LogRecord
from pathlib import Path

import pytest

from soc_connectors.exceptions import CheckpointError
from soc_connectors.utils.checkpoint import STATE_VERSION, Checkpoint, CheckpointStore

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 22, 9, 0, 0, tzinfo=UTC)


def payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "state_version": STATE_VERSION,
        "connector_id": "demo",
        "cursor": "file:100",
        "last_timestamp": "2026-10-22T08:00:00.000Z",
        "seen_ids": ["a", "b"],
        "updated_at": "2026-10-22T08:00:00.000Z",
    }
    base.update(overrides)
    return base


def seed(store: CheckpointStore, **overrides: object) -> None:
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps(payload(**overrides)), encoding="utf-8")


def test_a_store_without_a_state_file_starts_fresh(
    checkpoint_store: Callable[..., CheckpointStore],
) -> None:
    store = checkpoint_store("demo")
    assert store.state.is_fresh
    assert store.state.connector_id == "demo"
    assert store.size == 0


def test_max_seen_ids_must_keep_something(checkpoint_store: Callable[..., CheckpointStore]) -> None:
    with pytest.raises(CheckpointError, match="max_seen_ids"):
        checkpoint_store("demo", max_seen_ids=0)


def test_save_then_load_restores_the_position(
    tmp_path: Path, checkpoint_store: Callable[..., CheckpointStore]
) -> None:
    store = checkpoint_store("demo")
    store.advance(cursor="s3:7", last_timestamp=NOW, seen_ids=["a", "b"])
    store.save()

    reopened = CheckpointStore(store.path, "demo")
    assert reopened.state.cursor == "s3:7"
    assert reopened.state.last_timestamp == NOW
    assert reopened.state.seen_ids == ["a", "b"]
    assert reopened.is_duplicate("a")
    assert store.size > 0


def test_advance_treats_none_as_no_new_information(
    checkpoint_store: Callable[..., CheckpointStore],
) -> None:
    store = checkpoint_store("demo")
    store.advance(cursor="c1")
    store.advance(cursor=None, last_timestamp=NOW)
    assert store.state.cursor == "c1"
    assert store.state.last_timestamp == NOW


def test_remember_counts_only_new_ids(checkpoint_store: Callable[..., CheckpointStore]) -> None:
    store = checkpoint_store("demo")
    assert store.remember(["a", "b", "a"]) == 2
    assert store.remember(["a"]) == 0
    assert store.remember([""]) == 0
    assert store.is_duplicate("b")
    assert not store.is_duplicate("z")


def test_the_window_evicts_the_oldest_id_first(
    checkpoint_store: Callable[..., CheckpointStore],
) -> None:
    store = checkpoint_store("demo", max_seen_ids=3)
    store.remember(["a", "b", "c", "d"])
    assert store.state.seen_ids == ["b", "c", "d"]
    assert not store.is_duplicate("a")
    assert store.is_duplicate("d")


def test_a_reloaded_window_keeps_the_newest_ids(
    tmp_path: Path, checkpoint_store: Callable[..., CheckpointStore]
) -> None:
    """Restarting with a smaller window must forget the stale end, not the recent one."""
    store = checkpoint_store("demo", max_seen_ids=10)
    store.remember([f"id-{index}" for index in range(10)])
    store.save()

    narrowed = CheckpointStore(store.path, "demo", max_seen_ids=4)
    assert narrowed.state.seen_ids == ["id-6", "id-7", "id-8", "id-9"]
    assert narrowed.is_duplicate("id-9")
    assert not narrowed.is_duplicate("id-0")


def test_a_corrupt_state_file_is_moved_aside_not_deleted(
    checkpoint_store: Callable[..., CheckpointStore], capture_logs: Callable[[str], list[LogRecord]]
) -> None:
    store = checkpoint_store("demo")
    records = capture_logs("checkpoint")
    seed(store)
    store.path.write_text("{ half a json doc", encoding="utf-8")

    assert store.load().is_fresh
    quarantined = list(store.path.parent.glob(f"{store.path.name}.*.corrupt"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == "{ half a json doc"
    assert any("starting from scratch" in record.getMessage() for record in records)


@pytest.mark.parametrize("content", ["[1, 2]", '"a string"', "42"])
def test_a_state_file_that_is_not_an_object_is_moved_aside(
    checkpoint_store: Callable[..., CheckpointStore], content: str
) -> None:
    store = checkpoint_store("demo")
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(content, encoding="utf-8")
    assert store.load().is_fresh
    assert list(store.path.parent.glob("*.corrupt"))


def test_unusable_field_values_are_dropped_not_fatal(
    checkpoint_store: Callable[..., CheckpointStore],
) -> None:
    store = checkpoint_store("demo")
    seed(
        store,
        last_timestamp="yesterday-ish",
        seen_ids="not-a-list",
        connector_id="",
    )
    state = store.load()
    assert state.last_timestamp is None
    assert state.seen_ids == []
    assert state.connector_id == "demo"


def test_non_scalar_seen_ids_are_ignored(checkpoint_store: Callable[..., CheckpointStore]) -> None:
    store = checkpoint_store("demo")
    seed(store, seen_ids=["ok", None, {"nested": 1}, 7])
    assert store.load().seen_ids == ["ok", "7"]


def test_reset_clears_disk_and_memory(
    tmp_path: Path, checkpoint_store: Callable[..., CheckpointStore]
) -> None:
    store = checkpoint_store("demo")
    store.advance(cursor="c1", seen_ids=["a"])
    store.save()
    store.reset()
    assert not store.path.exists()
    assert store.state.is_fresh
    assert not store.is_duplicate("a")


def test_reset_is_idempotent_when_no_file_exists(
    checkpoint_store: Callable[..., CheckpointStore],
) -> None:
    store = checkpoint_store("demo")
    store.reset()
    assert store.state.is_fresh


def test_checkpoint_dict_is_stable_and_versioned() -> None:
    document = Checkpoint(
        connector_id="demo", cursor="c", last_timestamp=NOW, seen_ids=["a"]
    ).as_dict()
    assert document["state_version"] == STATE_VERSION
    assert document["last_timestamp"] == "2026-10-22T09:00:00.000Z"
    assert document["seen_ids"] == ["a"]
    assert "updated_at" in document


def test_a_fresh_checkpoint_reports_itself() -> None:
    assert Checkpoint(connector_id="demo").is_fresh
    assert not Checkpoint(connector_id="demo", seen_ids=["a"]).is_fresh
    assert not Checkpoint(connector_id="demo", cursor="c").is_fresh
