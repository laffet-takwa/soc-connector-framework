"""Checkpointed cursor state, so a restart does not re-read or skip a window.

At-least-once is the honest guarantee: a connector reads, forwards, then persists its cursor.
A crash between forwarding and persisting replays a few events on the next start, which the
bounded seen-id window below and ``EcsEvent.identity_key()`` absorb. The reverse ordering
would lose events, which is why it is not offered.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_connectors.exceptions import CheckpointError, MalformedEventError
from soc_connectors.logging_setup import get_logger
from soc_connectors.utils.io import atomic_write_json, file_size, read_text
from soc_connectors.utils.time import parse_timestamp, to_iso_z, utc_now

STATE_VERSION = 1
DEFAULT_MAX_SEEN_IDS = 2000

#: Corrupt state is never deleted: it is moved aside so the operator can see what the
#: connector last believed before it stopped believing it.
CORRUPT_SUFFIX = "corrupt"

logger = get_logger("checkpoint")


@dataclass(slots=True)
class Checkpoint:
    """The durable position of one connector."""

    connector_id: str
    cursor: str | None = None
    last_timestamp: datetime | None = None
    #: De-duplication window, ordered oldest -> newest — the same order the in-memory
    #: deque uses, so what is on disk and what is live cannot disagree about which end to evict.
    seen_ids: list[str] = field(default_factory=list)
    updated_at: datetime = field(default_factory=utc_now)

    def as_dict(self) -> dict[str, Any]:
        return {
            "state_version": STATE_VERSION,
            "connector_id": self.connector_id,
            "cursor": self.cursor,
            "last_timestamp": None
            if self.last_timestamp is None
            else to_iso_z(self.last_timestamp),
            "seen_ids": list(self.seen_ids),
            "updated_at": to_iso_z(self.updated_at),
        }

    @property
    def is_fresh(self) -> bool:
        return self.cursor is None and self.last_timestamp is None and not self.seen_ids


def _quarantine(path: Path) -> Path:
    target = path.with_name(f"{path.name}.{utc_now().strftime('%Y%m%dT%H%M%S')}.{CORRUPT_SUFFIX}")
    try:
        path.replace(target)
    except OSError as exc:
        raise CheckpointError(
            f"state file {path} is corrupt and could not be moved aside: {exc}"
        ) from exc
    return target


class CheckpointStore:
    """One JSON state file per connector, rewritten atomically.

    The seen-id window is bounded on purpose: a set of every event id ever read would grow
    forever and eventually make the state file slower to load than the source is to poll.
    Eviction is oldest-first, so replays are absorbed for the recent window a restart or a
    lagging cursor actually produces.
    """

    def __init__(
        self, path: Path, connector_id: str, *, max_seen_ids: int = DEFAULT_MAX_SEEN_IDS
    ) -> None:
        if max_seen_ids < 1:
            raise CheckpointError("max_seen_ids must be at least 1")
        self.path = Path(path)
        self.connector_id = connector_id
        self.max_seen_ids = max_seen_ids
        self._state = Checkpoint(connector_id=connector_id)
        self._window: deque[str] = deque()
        self._index: set[str] = set()
        self._loaded = False

    # -- state -------------------------------------------------------------

    @property
    def state(self) -> Checkpoint:
        if not self._loaded:
            self.load()
        return self._state

    def load(self) -> Checkpoint:
        """Read state from disk, tolerating a missing file but not a half-written one."""
        text = read_text(self.path)
        self._state = Checkpoint(connector_id=self.connector_id)
        self._reset_window()
        self._loaded = True
        if text is None:
            return self._state
        try:
            payload = json.loads(text)
        except ValueError as exc:
            moved = _quarantine(self.path)
            logger.warning(
                "state file is not valid JSON; starting from scratch",
                extra={"path": str(self.path), "quarantined_to": str(moved), "error": str(exc)},
            )
            return self._state
        if not isinstance(payload, Mapping):
            moved = _quarantine(self.path)
            logger.warning(
                "state file is not an object; starting from scratch",
                extra={"path": str(self.path), "quarantined_to": str(moved)},
            )
            return self._state
        self._state = self._parse(payload)
        for key in self._state.seen_ids:
            self._remember(key)
        return self._state

    def _parse(self, payload: Mapping[str, Any]) -> Checkpoint:
        cursor = payload.get("cursor")
        raw_ids = payload.get("seen_ids") or []
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, Iterable):
            raw_ids = []
        seen = [str(key) for key in raw_ids if isinstance(key, (str, int, float))]
        seen = seen[-self.max_seen_ids :]
        last_timestamp = None
        value = payload.get("last_timestamp")
        if value is not None:
            try:
                last_timestamp = parse_timestamp(value, field_name="last_timestamp")
            except MalformedEventError:
                last_timestamp = None
        return Checkpoint(
            connector_id=str(payload.get("connector_id") or self.connector_id),
            cursor=None if cursor is None else str(cursor),
            last_timestamp=last_timestamp,
            seen_ids=seen,
            updated_at=utc_now(),
        )

    # -- de-duplication ------------------------------------------------------

    def is_duplicate(self, key: str) -> bool:
        if not self._loaded:
            self.load()
        return key in self._index

    def remember(self, keys: Iterable[str]) -> int:
        """Record ids as seen, returning how many were new."""
        if not self._loaded:
            self.load()
        added = 0
        for key in keys:
            if self._remember(key):
                added += 1
        if added:
            self._state.seen_ids = list(self._window)
        return added

    def _remember(self, key: str) -> bool:
        if not key or key in self._index:
            return False
        self._window.append(key)
        self._index.add(key)
        while len(self._window) > self.max_seen_ids:
            self._index.discard(self._window.popleft())
        return True

    def _reset_window(self) -> None:
        self._window.clear()
        self._index.clear()

    # -- advancing ----------------------------------------------------------

    def advance(
        self,
        *,
        cursor: str | None = None,
        last_timestamp: datetime | None = None,
        seen_ids: Iterable[str] = (),
    ) -> Checkpoint:
        """Fold a cycle's progress into the in-memory state without touching disk.

        ``None`` means "this cycle did not learn a new position", not "clear it" — a source
        that returns no page must not erase the cursor it is still replaying from.
        """
        if not self._loaded:
            self.load()
        if cursor is not None:
            self._state.cursor = str(cursor)
        if last_timestamp is not None:
            self._state.last_timestamp = last_timestamp
        self.remember(seen_ids)
        self._state.updated_at = utc_now()
        return self._state

    def save(self) -> Checkpoint:
        state = self.state
        try:
            atomic_write_json(self.path, state.as_dict())
        except OSError as exc:
            raise CheckpointError(f"could not write state file {self.path}: {exc}") from exc
        logger.debug("state saved", extra={"path": str(self.path), "cursor": state.cursor})
        return state

    def reset(self) -> None:
        """Forget the position on disk and in memory (used by `soc-connectors reset`)."""
        self._state = Checkpoint(connector_id=self.connector_id)
        self._reset_window()
        self._loaded = True
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise CheckpointError(f"could not remove state file {self.path}: {exc}") from exc

    @property
    def size(self) -> int:
        return file_size(self.path)
