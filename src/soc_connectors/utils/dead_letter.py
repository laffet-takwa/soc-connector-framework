"""Dead-letter storage for events that could not be produced or delivered.

An event that fails permanently must not be dropped and must not stop the pipeline. It is
appended here as JSONL with the reason, so a mapping bug discovered on Tuesday can still be
replayed after the fix. The file is append-only and fsynced: it is frequently the only
remaining copy of the record.

This is sensitive data at rest. It inherits the redaction policy applied at write time, and
``data/dead_letter/`` is gitignored so it cannot be committed by accident.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.logging_setup import get_logger
from soc_connectors.schema.redaction import RedactionSettings, redact_document
from soc_connectors.types import RawEvent
from soc_connectors.utils.io import append_jsonl, ensure_directory, file_size
from soc_connectors.utils.time import to_iso_z, utc_now

DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_PAYLOAD_LIMIT = 4096
TRUNCATED_MARKER = "payload_truncated"

logger = get_logger("dead_letter")


class DeadLetterQueue:
    """Append-only JSONL sink with a size ceiling and timestamped rotation."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        payload_limit: int = DEFAULT_PAYLOAD_LIMIT,
        redaction: RedactionSettings | None = None,
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.payload_limit = payload_limit
        self.redaction = redaction
        self._dropped_by_cap = 0
        ensure_directory(self.path.parent)

    @property
    def size(self) -> int:
        return file_size(self.path)

    @property
    def dropped_by_cap(self) -> int:
        """Records refused because rotation itself failed — always zero unless logged."""
        return self._dropped_by_cap

    def write(
        self,
        *,
        connector_id: str,
        stage: str,
        reason: str,
        error: BaseException | None = None,
        raw: RawEvent | None = None,
        document: Mapping[str, Any] | None = None,
        identity: str | None = None,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        """Persist one failure record and return what was written."""
        record: dict[str, Any] = {
            "logged_at": to_iso_z(at or utc_now()),
            "connector_id": connector_id,
            "stage": stage,
            "reason": reason,
            "error_type": None if error is None else type(error).__name__,
            "identity": identity,
        }
        if error is not None:
            record["error"] = str(error)[:512]
        if document is not None:
            record["event"] = self._prepare_document(document)
        payload = self._payload_for(raw, error)
        if payload is not None:
            record["payload"] = payload
        if raw is not None and raw.cursor:
            record["cursor"] = raw.cursor
        self._rotate_if_needed()
        append_jsonl(self.path, [record])
        logger.error(
            "event dead-lettered",
            extra={
                "connector_id": connector_id,
                "stage": stage,
                "reason": reason,
                "path": str(self.path),
            },
        )
        return record

    def _prepare_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        if self.redaction is None:
            return dict(document)
        return redact_document(document, self.redaction)

    def _payload_for(self, raw: RawEvent | None, error: BaseException | None) -> Any:
        """Best-effort copy of the offending record, truncated to ``payload_limit``.

        ``MalformedEventError`` may already carry the raw event, so an unwrapped error still
        leaves evidence behind.
        """
        source = raw
        if source is None and isinstance(error, MalformedEventError):
            source = error.raw
        if source is None:
            return None
        try:
            text = source.as_text()
        except MalformedEventError:
            text = repr(source.payload)
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self.payload_limit:
            return text
        clipped = encoded[: self.payload_limit].decode("utf-8", errors="replace")
        return {TRUNCATED_MARKER: True, "bytes": len(encoded), "text": clipped}

    def _rotate_if_needed(self) -> bool:
        if self.size < self.max_bytes:
            return False
        stamp = utc_now().strftime("%Y%m%dT%H%M%S")
        target = self.path.with_name(f"{self.path.stem}.{stamp}.jsonl")
        try:
            self.path.replace(target)
        except OSError:
            self._dropped_by_cap += 1
            logger.exception(
                "dead-letter rotation failed; refusing to grow the file further",
                extra={"path": str(self.path)},
            )
            return False
        logger.warning("dead-letter file rotated", extra={"path": str(target)})
        return True

    def records(self) -> Iterator[dict[str, Any]]:
        """Yield stored records for inspection or replay. Blank lines are skipped, not fatal."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    decoded = json.loads(stripped)
                except ValueError:
                    logger.warning(
                        "skipping unparseable dead-letter line", extra={"path": str(self.path)}
                    )
                    continue
                if isinstance(decoded, dict):
                    yield decoded

    def count(self) -> int:
        return sum(1 for _ in self.records())
