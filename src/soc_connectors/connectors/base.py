"""``BaseConnector``: the three stages every source must implement.

A connector's job ends at a normalised ECS event. Retry policy, de-duplication, checkpointing,
dead-lettering and metrics are the pipeline's job, applied uniformly — which is what makes the
fourth connector cost a fraction of the first, and why a connector that "helpfully" retries on
its own is a bug rather than a feature.

The contract, in the order the runner calls it:

``fetch()``
    Yield :class:`RawEvent` objects from where the checkpoint says to resume. No interpretation.
``parse(raw)``
    Turn one payload into source-named fields (:class:`ParsedEvent`). Raise
    :class:`MalformedEventError` for a record this source cannot express.
``normalize(parsed)``
    Map source fields onto ECS. Never invent a value to satisfy a schema.

Failures are typed: :class:`TransientError` is retried; :class:`PermanentError` and
:class:`MalformedEventError` are dead-lettered.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from pydantic import SecretStr

from soc_connectors.exceptions import ConfigError
from soc_connectors.metrics import Metrics
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.types import Clock, ParsedEvent, Payload, RawEvent
from soc_connectors.utils.checkpoint import CheckpointStore
from soc_connectors.utils.rate_limit import RateLimiter
from soc_connectors.utils.retry import RetryPolicy
from soc_connectors.utils.time import utc_now


@dataclass(slots=True)
class ConnectorContext:
    """Everything the pipeline hands a connector, so a connector constructor stays one argument."""

    connector_id: str
    options: Mapping[str, Any]
    checkpoint: CheckpointStore
    retry_policy: RetryPolicy
    metrics: Metrics
    limiter: RateLimiter
    clock: Clock = utc_now


class BaseConnector(ABC):
    """Fetch, parse, normalize — see the module docstring for the contract."""

    type_name: ClassVar[str] = ""
    """Registry key, used as ``type:`` in the config file."""

    summary: ClassVar[str] = ""
    """One line for ``soc-connectors list-sources``."""

    supports_backfill: ClassVar[bool] = False
    """Whether the source can be asked for history, not only what it still holds."""

    def __init__(self, context: ConnectorContext) -> None:
        if not type(self).type_name:
            raise ConfigError(f"{type(self).__name__} declares no type_name")
        self.context = context
        self.log = logging.getLogger(f"soc_connectors.connector.{context.connector_id}")

    # -- convenience ---------------------------------------------------------

    @property
    def id(self) -> str:
        return self.context.connector_id

    @property
    def checkpoint(self) -> CheckpointStore:
        return self.context.checkpoint

    @property
    def metrics(self) -> Metrics:
        return self.context.metrics

    @property
    def now(self) -> datetime:
        return self.context.clock()

    def option(self, name: str, default: Any = None) -> Any:
        return self.context.options.get(name, default)

    def require_option(self, name: str) -> Any:
        value = self.context.options.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ConfigError(f"connector {self.id!r} requires option '{name}'")
        return value

    def secret(self, name: str) -> str:
        """Read a credential option, unwrapping ``SecretStr``.

        The value is returned only to the caller that must put it on the wire. Nothing here
        ever places it in a log record or an exception message.
        """
        value = self.context.options.get(name)
        if value is None:
            raise ConfigError(
                f"connector {self.id!r} requires secret '{name}' (export it in the environment)"
            )
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        if isinstance(value, str):
            return value
        raise ConfigError(f"connector {self.id!r} secret '{name}' is not a string")

    def acquire(self, tokens: int = 1, *, timeout: float | None = None) -> bool:
        """Consume quota; ``False`` means stop and wait for the next polling tick."""
        return self.context.limiter.acquire(tokens, timeout=timeout)

    # -- stage 1: fetch ------------------------------------------------------

    @abstractmethod
    def fetch(self) -> Iterator[RawEvent]:
        """Yield records not yet covered by the checkpoint."""

    # -- stage 2: parse ------------------------------------------------------

    @abstractmethod
    def parse(self, raw: RawEvent) -> ParsedEvent:
        """Extract source-named fields from one payload."""

    # -- stage 3: normalize --------------------------------------------------

    @abstractmethod
    def normalize(self, parsed: ParsedEvent) -> EcsEvent:
        """Map source fields onto ECS."""

    # -- lifecycle -----------------------------------------------------------

    def make_raw(
        self,
        payload: Payload,
        *,
        cursor: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> RawEvent:
        return RawEvent(
            connector_id=self.id,
            payload=payload,
            received_at=self.now,
            cursor=cursor,
            metadata=dict(metadata or {}),
        )

    def health(self) -> dict[str, Any]:
        """Position and counters, for ``status`` and the periodic health log line."""
        state = self.checkpoint.state
        return {
            "connector_id": self.id,
            "type": type(self).type_name,
            "cursor": state.cursor,
            "last_timestamp": None
            if state.last_timestamp is None
            else state.last_timestamp.isoformat(),
            "seen_ids": len(state.seen_ids),
            "metrics": self.metrics.for_source(self.id),
        }

    def close(self) -> None:  # noqa: B027 - optional hook: connectors with no resources stay empty
        """Release sockets, clients and file handles. Must be safe to call twice."""
