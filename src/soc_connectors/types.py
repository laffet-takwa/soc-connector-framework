"""Value objects exchanged between the pipeline stages.

``RawEvent`` is everything a connector read from a source, before interpretation;
``ParsedEvent`` is a record whose source fields are extracted but still named the way the
source names them; ``EcsEvent`` (``schema.ecs_models``) is the only thing a forwarder may
receive.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from soc_connectors.exceptions import MalformedEventError

Payload = str | bytes | bytearray | Mapping[str, Any]
Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class RawEvent:
    """One unit as read from a source: log line, JSON record, datagram, object body."""

    connector_id: str
    payload: Payload
    received_at: datetime
    cursor: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def as_text(self, *, encoding: str = "utf-8") -> str:
        if isinstance(self.payload, str):
            return self.payload
        if isinstance(self.payload, (bytes, bytearray)):
            try:
                return self.payload.decode(encoding)
            except UnicodeDecodeError as exc:
                raise MalformedEventError(
                    f"payload is not {encoding}-decodable", raw=self, field="payload"
                ) from exc
        return json.dumps(self.payload, default=str, ensure_ascii=False)

    def as_mapping(self) -> dict[str, Any]:
        """Return the payload as a dict, whatever shape the source delivered it in."""
        if isinstance(self.payload, Mapping):
            return dict(self.payload)
        text = self.as_text()
        try:
            decoded = json.loads(text)
        except ValueError as exc:
            raise MalformedEventError(
                "payload is not valid JSON", raw=self, field="payload"
            ) from exc
        if not isinstance(decoded, Mapping):
            raise MalformedEventError(
                f"payload decoded to {type(decoded).__name__}, expected a JSON object",
                raw=self,
                field="payload",
            )
        return dict(decoded)

    @property
    def size_hint(self) -> int:
        if isinstance(self.payload, (bytes, bytearray, str)):
            return len(self.payload)
        return len(json.dumps(self.payload, default=str))


@dataclass(frozen=True, slots=True)
class ParsedEvent:
    """A record whose source fields are extracted but not yet ECS."""

    raw: RawEvent
    fields: Mapping[str, Any]
    source_event_type: str

    def get(self, name: str, default: Any = None) -> Any:
        value = self.fields.get(name, default)
        return default if value is None else value


@dataclass(frozen=True, slots=True)
class CycleReport:
    """Outcome of one pipeline cycle for one connector, for logs and the CLI summary."""

    connector_id: str
    fetched: int
    normalized: int
    forwarded: int
    dead_lettered: int
    duplicates: int
    cursor: str | None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "fetched": self.fetched,
            "normalized": self.normalized,
            "forwarded": self.forwarded,
            "dead_lettered": self.dead_lettered,
            "duplicates": self.duplicates,
            "cursor": self.cursor,
            "error": self.error,
        }
