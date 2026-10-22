"""The reference connector: ECS-shaped records from a local JSON Lines file.

This is the connector a newcomer reads before writing their own, and the one ``self-test`` and
the Docker demo use, because it exercises fetch/parse/normalize and the cursor contract with
no credentials, no network and no third-party service. Its input records already name their
fields with ECS paths; a real source needs a mapping table, which is exactly the difference
this file makes visible.

The cursor is a byte offset. Offsets rather than line numbers because a log file is appended
to, never inserted into, so an offset stays valid for the life of the file — and because a
truncated half-line at EOF must be left for the next cycle instead of being parsed as JSON.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from soc_connectors.connectors.base import BaseConnector, ConnectorContext
from soc_connectors.exceptions import ConfigError
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.schema.mapping import from_flat
from soc_connectors.types import ParsedEvent, RawEvent

CURSOR_SEPARATOR = ":"


class SampleJsonlConnector(BaseConnector):
    type_name: ClassVar[str] = "sample_jsonl"
    summary: ClassVar[str] = (
        "Reads ECS-path-named JSON Lines records from a local file (reference/demo source)."
    )

    def __init__(self, context: ConnectorContext) -> None:
        super().__init__(context)
        self.path = Path(str(self.require_option("path"))).expanduser()
        if not self.path.exists():
            raise ConfigError(f"connector {self.id!r}: sample file {self.path} does not exist")
        self.dataset: str = str(self.option("dataset", "sample.events"))
        self.id_field: str | None = self.option("id_field")
        self.max_records: int = int(self.option("max_records_per_cycle", 500))

    def _start_offset(self) -> int:
        state = self.checkpoint.state
        if not state.cursor:
            return 0
        _, _, tail = state.cursor.rpartition(CURSOR_SEPARATOR)
        if not tail.isdigit():
            raise ConfigError(f"connector {self.id!r} has an unparsable cursor {state.cursor!r}")
        return int(tail)

    def fetch(self) -> Iterator[RawEvent]:
        """Yield complete lines appended since the checkpointed offset."""
        if not self.path.exists():
            raise ConfigError(f"connector {self.id!r}: sample file {self.path} disappeared")
        offset = self._start_offset()
        size = self.path.stat().st_size
        if offset > size:
            # Truncated or rotated underneath us: an offset past EOF means start over, and say so.
            self.log.warning(
                "source shrank below the stored offset; restarting",
                extra={"offset": offset, "size": size},
            )
            offset = 0
        produced = 0
        with self.path.open("rb") as handle:
            handle.seek(offset)
            while produced < self.max_records:
                line = handle.readline()
                if not line:
                    break  # EOF — nothing more has been written
                if not line.endswith(b"\n"):
                    self.log.debug(
                        "leaving unterminated line for the next cycle", extra={"bytes": len(line)}
                    )
                    break
                offset += len(line)
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                produced += 1
                yield self.make_raw(text, cursor=f"{self.path}{CURSOR_SEPARATOR}{offset}")

    def parse(self, raw: RawEvent) -> ParsedEvent:
        record = raw.as_mapping()
        return ParsedEvent(
            raw=raw, fields=record, source_event_type=str(record.get("event.kind", "event"))
        )

    def normalize(self, parsed: ParsedEvent) -> EcsEvent:
        fields: dict[str, Any] = dict(parsed.fields)
        if self.id_field and self.id_field in fields:
            fields["event.id"] = fields.pop(self.id_field)
        fields.setdefault("event.dataset", self.dataset)
        fields.setdefault("event.module", "sample")
        fields.setdefault("raw", dict(parsed.fields))
        return from_flat(fields)
