"""The destination that always accepts — and why the framework needs one.

``type: sink`` takes every event and depends on nothing. It gives ``self-test`` a terminal that
cannot fail for reasons unrelated to the framework, and it lets a connector be developed
against real sources with no Elasticsearch, Wazuh or TheHive reachable. Set ``record_file``
and it writes the exact documents a real destination would have received, which is how the
field-mapping table gets checked without a stack running.

It is registered as ``sink`` rather than ``null`` because YAML 1.1 reads a bare ``null`` as
Python ``None``, and a config file whose destination type is ``None`` fails validation with a
message that tells the operator nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

from soc_connectors.forwarders.base import BaseForwarder, DeliveryResult, ForwarderContext
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.utils.io import append_jsonl, ensure_directory


class SinkForwarder(BaseForwarder):
    type_name: ClassVar[str] = "sink"
    summary: ClassVar[str] = (
        "Accepts every event; optionally records the documents a real destination would receive."
    )

    def __init__(self, context: ForwarderContext) -> None:
        super().__init__(context)
        record = self.option("record_file")
        # A blank `record_file:` in YAML is "", and Path("") is the current directory: the sink
        # would then try to append JSON to a directory and fail naming no setting. Treat blank
        # as absent, the way require_option() treats it as missing.
        text = "" if record is None else str(record).strip()
        self.record_path: Path | None = None if not text else Path(text)
        self.received = 0
        self.written = 0

    def open(self) -> None:
        if self.record_path is not None:
            ensure_directory(self.record_path.parent)

    def send(self, events: Sequence[EcsEvent]) -> DeliveryResult:
        accepted = len(events)
        self.received += accepted
        if self.record_path is not None and events:
            self.written += append_jsonl(
                self.record_path, [self.document_for(event) for event in events]
            )
        return DeliveryResult(accepted=accepted)

    def health(self) -> dict[str, Any]:
        report = dict(super().health())
        report.update(
            {
                "received": self.received,
                "recorded": self.written,
                "record_file": None if self.record_path is None else str(self.record_path),
            }
        )
        return report
