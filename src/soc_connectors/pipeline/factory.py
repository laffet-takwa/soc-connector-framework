"""Registry and wiring: validated config in, a running pipeline out.

Adding a source should mean one file and one registration line — nothing else changes. That is
the whole argument for this framework, so the registry is deliberately boring: a name, a class,
and a ``ConfigError`` naming the known types when a config file asks for something that is not
there.

Objects are constructed here rather than in the CLI so a test can build a whole pipeline from a
config dict without touching anything beyond ``tmp_path``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from soc_connectors.config import AppConfig, DestinationConfig, SourceConfig
from soc_connectors.connectors.base import BaseConnector, ConnectorContext
from soc_connectors.connectors.cloudtrail import CloudTrailConnector
from soc_connectors.connectors.sample_jsonl import SampleJsonlConnector
from soc_connectors.exceptions import ConfigError
from soc_connectors.forwarders.base import BaseForwarder, ForwarderContext
from soc_connectors.forwarders.sink import SinkForwarder
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.dispatcher import Dispatcher, Route
from soc_connectors.pipeline.runner import PipelineRunner, RetrySleep, SourceRuntime
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.types import Clock
from soc_connectors.utils.checkpoint import CheckpointStore
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.rate_limit import RateLimiter, build_limiter
from soc_connectors.utils.time import utc_now

CONNECTOR_TYPES: dict[str, type[BaseConnector]] = {}
FORWARDER_TYPES: dict[str, type[BaseForwarder]] = {}

_Registered = TypeVar("_Registered", BaseConnector, BaseForwarder)


def register_connector(cls: type[BaseConnector]) -> type[BaseConnector]:
    """Publish a connector under its ``type_name``."""
    if not cls.type_name:
        raise ConfigError(f"{cls.__name__} cannot be registered: type_name is empty")
    existing = CONNECTOR_TYPES.get(cls.type_name)
    if existing is not None and existing is not cls:
        raise ConfigError(
            f"connector type {cls.type_name!r} is already registered by {existing.__name__}"
        )
    CONNECTOR_TYPES[cls.type_name] = cls
    return cls


def register_forwarder(cls: type[BaseForwarder]) -> type[BaseForwarder]:
    if not cls.type_name:
        raise ConfigError(f"{cls.__name__} cannot be registered: type_name is empty")
    existing = FORWARDER_TYPES.get(cls.type_name)
    if existing is not None and existing is not cls:
        raise ConfigError(
            f"forwarder type {cls.type_name!r} is already registered by {existing.__name__}"
        )
    FORWARDER_TYPES[cls.type_name] = cls
    return cls


def register_builtins() -> None:
    """Idempotent registration of the types shipped in this package."""
    register_connector(SampleJsonlConnector)
    register_connector(CloudTrailConnector)
    register_forwarder(SinkForwarder)


def connector_summaries() -> dict[str, str]:
    register_builtins()
    return {name: cls.summary for name, cls in sorted(CONNECTOR_TYPES.items())}


def forwarder_summaries() -> dict[str, str]:
    register_builtins()
    return {name: cls.summary for name, cls in sorted(FORWARDER_TYPES.items())}


def _resolve(
    registry: Mapping[str, type[_Registered]], kind: str, wanted: str
) -> type[_Registered]:
    try:
        return registry[wanted]
    except KeyError as exc:
        raise ConfigError(
            f"unknown {kind} type {wanted!r}; known: {', '.join(sorted(registry))}"
        ) from exc


@dataclass(slots=True)
class BuiltPipeline:
    """Everything ``run`` needs, with the shutdown order defined once."""

    config: AppConfig
    runner: PipelineRunner
    dispatcher: Dispatcher
    metrics: Metrics
    connectors: list[BaseConnector] = field(default_factory=list)
    forwarders: list[BaseForwarder] = field(default_factory=list)
    checkpoints: dict[str, CheckpointStore] = field(default_factory=dict)
    dead_letters: dict[str, DeadLetterQueue] = field(default_factory=dict)
    _closed: bool = False

    def close(self) -> None:
        """Close connectors first (stop producing), then forwarders (flush what is in flight)."""
        if self._closed:
            return
        self._closed = True
        for connector in self.connectors:
            connector.close()
        for forwarder in self.forwarders:
            forwarder.close()

    def status(self) -> dict[str, Any]:
        return self.runner.status()


def build_checkpoint(config: AppConfig, source: SourceConfig) -> CheckpointStore:
    return CheckpointStore(
        config.state_path(source.id),
        source.id,
        max_seen_ids=config.pipeline.dedup_window,
    )


def build_dead_letter(config: AppConfig, connector_id: str) -> DeadLetterQueue:
    return DeadLetterQueue(config.dead_letter_path(connector_id), redaction=config.redaction)


def build_connector(
    config: AppConfig,
    source: SourceConfig,
    *,
    metrics: Metrics,
    checkpoint: CheckpointStore | None = None,
    limiter: RateLimiter | None = None,
    clock: Clock = utc_now,
) -> BaseConnector:
    register_builtins()
    cls = _resolve(CONNECTOR_TYPES, "source", source.type)
    policy = config.retry_policy_for(source)
    context = ConnectorContext(
        connector_id=source.id,
        options=dict(source.options),
        checkpoint=checkpoint or build_checkpoint(config, source),
        retry_policy=policy,
        metrics=metrics,
        limiter=limiter or build_limiter(source.requests_per_minute),
        clock=clock,
    )
    return cls(context)


def build_forwarder(
    config: AppConfig,
    destination: DestinationConfig,
    *,
    metrics: Metrics,
    redaction: RedactionSettings | None = None,
) -> BaseForwarder:
    register_builtins()
    cls = _resolve(FORWARDER_TYPES, "destination", destination.type)
    context = ForwarderContext(
        forwarder_id=destination.id,
        options=dict(destination.options),
        retry_policy=config.retry_policy_for(destination),
        metrics=metrics,
        redaction=redaction if redaction is not None else config.redaction,
    )
    return cls(context)


def build_pipeline(
    config: AppConfig,
    *,
    metrics: Metrics | None = None,
    clock: Clock = utc_now,
    retry_sleep: RetrySleep | None = None,
    sleeper: Callable[[float], bool] | None = None,
    limiters: Mapping[str, RateLimiter] | None = None,
    checkpoints: Mapping[str, CheckpointStore] | None = None,
) -> BuiltPipeline:
    """Wire every enabled source and destination described by ``config``."""
    register_builtins()
    active_metrics = metrics or Metrics()
    sources: list[SourceRuntime] = []
    connectors: list[BaseConnector] = []
    dead_letters: dict[str, DeadLetterQueue] = {}
    checkpoint_states: dict[str, CheckpointStore] = {}

    for source in config.enabled_sources():
        store = (checkpoints or {}).get(source.id) or build_checkpoint(config, source)
        store.load()
        checkpoint_states[source.id] = store
        dead_letter = build_dead_letter(config, source.id)
        dead_letters[source.id] = dead_letter
        connector = build_connector(
            config,
            source,
            metrics=active_metrics,
            checkpoint=store,
            limiter=(limiters or {}).get(source.id),
            clock=clock,
        )
        connectors.append(connector)
        routed = config.destinations_for(source)
        sources.append(
            SourceRuntime(
                config=source,
                connector=connector,
                dead_letter=dead_letter,
                checkpoint=store,
                retry_policy=config.retry_policy_for(source),
                batch_size=config.batch_size_for(source),
                destinations=(
                    None if source.destinations is None else tuple(item.id for item in routed)
                ),
            )
        )

    forwarders: list[BaseForwarder] = []
    routes: list[Route] = []
    for destination in config.enabled_destinations():
        forwarder = build_forwarder(config, destination, metrics=active_metrics)
        forwarder.open()
        forwarders.append(forwarder)
        routes.append(
            Route(
                forwarder=forwarder,
                severity_min=destination.severity_min,
                batch_size=config.batch_size_for(destination),
                retry_policy=config.retry_policy_for(destination),
            )
        )

    dispatcher = Dispatcher(routes, metrics=active_metrics, redaction=config.redaction)
    runner = PipelineRunner(
        config=config,
        sources=sources,
        dispatcher=dispatcher,
        metrics=active_metrics,
        sleeper=sleeper,
        retry_sleep=time.sleep if retry_sleep is None else retry_sleep,
        clock=clock,
    )
    return BuiltPipeline(
        config=config,
        runner=runner,
        dispatcher=dispatcher,
        metrics=active_metrics,
        connectors=connectors,
        forwarders=forwarders,
        checkpoints=checkpoint_states,
        dead_letters=dead_letters,
    )
