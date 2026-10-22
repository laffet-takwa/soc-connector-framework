"""``BaseForwarder``: one ``send`` and an honest report of what landed.

A forwarder gets ECS events and returns which ones the destination accepted. It must not
assume that "the request succeeded" means "the documents were stored": an Elasticsearch
``_bulk`` call answers 200 with per-item errors, and only the per-item answer tells the
pipeline which events to dead-letter. That is why ``send`` returns a result object rather than
``None``.

Destination-specific concerns (index templates, agent paths, alert templates) live in the
concrete forwarder from M5 onward. Retry and dead-lettering stay in the pipeline.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import SecretStr

from soc_connectors.config import DestinationConfig
from soc_connectors.exceptions import ConfigError
from soc_connectors.metrics import Metrics
from soc_connectors.schema.ecs_models import EcsEvent, to_document
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.retry import RetryPolicy


@dataclass(slots=True)
class DeliveryResult:
    """What a destination did with one batch."""

    accepted: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    """Per-item failures in the destination's own words, each carrying the event identity."""

    attempts: int = 1
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.rejected

    def identities(self) -> list[str]:
        return [str(item.get("identity", "")) for item in self.rejected]


@dataclass(slots=True)
class ForwarderContext:
    forwarder_id: str
    options: Mapping[str, Any]
    retry_policy: RetryPolicy
    metrics: Metrics
    redaction: RedactionSettings


class BaseForwarder(ABC):
    """Sends normalised events to one destination."""

    type_name: ClassVar[str] = ""
    summary: ClassVar[str] = ""

    def __init__(self, context: ForwarderContext) -> None:
        if not type(self).type_name:
            raise ConfigError(f"{type(self).__name__} declares no type_name")
        self.context = context
        self.log = logging.getLogger(f"soc_connectors.forwarder.{context.forwarder_id}")

    @property
    def id(self) -> str:
        return self.context.forwarder_id

    @property
    def metrics(self) -> Metrics:
        return self.context.metrics

    @property
    def redaction(self) -> RedactionSettings:
        return self.context.redaction

    def option(self, name: str, default: Any = None) -> Any:
        return self.context.options.get(name, default)

    def require_option(self, name: str) -> Any:
        value = self.context.options.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ConfigError(f"forwarder {self.id!r} requires option '{name}'")
        return value

    def secret(self, name: str) -> str:
        value = self.context.options.get(name)
        if value is None:
            raise ConfigError(
                f"forwarder {self.id!r} requires secret '{name}' (export it in the environment)"
            )
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        if isinstance(value, str):
            return value
        raise ConfigError(f"forwarder {self.id!r} secret '{name}' is not a string")

    def document_for(self, event: EcsEvent) -> dict[str, Any]:
        """Serialise one event under this pipeline's redaction policy."""
        return to_document(event, self.redaction)

    def open(self) -> None:  # noqa: B027 - optional hook: no connection needed by default
        """Establish the connection or create the output file."""

    @abstractmethod
    def send(self, events: Sequence[EcsEvent]) -> DeliveryResult:
        """Deliver one batch; report every item the destination refused."""

    def health(self) -> dict[str, Any]:
        return {
            "forwarder_id": self.id,
            "type": type(self).type_name,
            "metrics": self.metrics.for_source(self.id),
        }

    def close(self) -> None:  # noqa: B027 - optional hook
        """Flush and release. Must be safe to call twice."""


def context_for(
    config: DestinationConfig,
    *,
    metrics: Metrics,
    retry_policy: RetryPolicy,
    redaction: RedactionSettings,
) -> ForwarderContext:
    return ForwarderContext(
        forwarder_id=config.id,
        options=dict(config.options),
        retry_policy=retry_policy,
        metrics=metrics,
        redaction=redaction,
    )
