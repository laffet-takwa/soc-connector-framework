"""The registry and the wiring: validated config in, a running pipeline out.

These tests are the proof that "adding a source means one file and one registration line" is
true, and that the factory — not the CLI — is where a pipeline becomes testable: everything here
is built from a config dict and a ``tmp_path``, with no network and no services.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

from soc_connectors.config import AppConfig, DestinationConfig, SourceConfig, parse_config
from soc_connectors.connectors.sample_jsonl import SampleJsonlConnector
from soc_connectors.exceptions import ConfigError
from soc_connectors.forwarders.sink import SinkForwarder
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.factory import (
    CONNECTOR_TYPES,
    FORWARDER_TYPES,
    build_checkpoint,
    build_connector,
    build_dead_letter,
    build_forwarder,
    build_pipeline,
    connector_summaries,
    forwarder_summaries,
    register_builtins,
    register_connector,
    register_forwarder,
)
from soc_connectors.schema.ecs_models import to_document
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.rate_limit import NoLimiter, TokenBucket
from soc_connectors.utils.retry import RetryPolicy

pytestmark = pytest.mark.unit


def base_raw(tmp_path: Path) -> dict[str, Any]:
    """A config dict rooted in ``tmp_path``: a test must not write into the checkout's ``data/``."""
    return {
        "pipeline": {
            "poll_interval_seconds": 1,
            "batch_size": 5,
            "state_dir": str(tmp_path / "state"),
            "dead_letter_dir": str(tmp_path / "dead_letter"),
        },
        "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
    }


class _UnnamedConnector(SampleJsonlConnector):
    type_name: ClassVar[str] = ""


class _UnnamedSink(SinkForwarder):
    type_name: ClassVar[str] = ""


class _HijackSink(SinkForwarder):
    type_name: ClassVar[str] = "sink"


class _HijackConnector(SampleJsonlConnector):
    type_name: ClassVar[str] = "sample_jsonl"


@pytest.fixture
def clean_registries() -> Iterator[None]:
    """Restore the module-level registries: a registry test must not leak into the suite."""
    saved_connectors = dict(CONNECTOR_TYPES)
    saved_forwarders = dict(FORWARDER_TYPES)
    yield
    CONNECTOR_TYPES.clear()
    CONNECTOR_TYPES.update(saved_connectors)
    FORWARDER_TYPES.clear()
    FORWARDER_TYPES.update(saved_forwarders)


@pytest.fixture
def config(tmp_path: Path) -> Callable[..., AppConfig]:
    """A config dict rooted in ``tmp_path`` whose only source and destination are the builtins."""

    def factory(**overrides: Any) -> AppConfig:
        raw: dict[str, Any] = {
            "pipeline": {
                "poll_interval_seconds": 1,
                "batch_size": 5,
                "state_dir": str(tmp_path / "state"),
                "dead_letter_dir": str(tmp_path / "dead_letter"),
            },
            "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
            "sources": [
                {
                    "id": "demo",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                }
            ],
            "destinations": [{"id": "recorded", "type": "sink", "options": {}}],
        }
        raw.update(overrides)
        return parse_config(raw)

    return factory


def write_sample(path: Path, count: int = 1) -> Path:
    records = [
        {
            "@timestamp": "2026-10-22T09:00:00Z",
            "event.action": f"demo-action-{index}",
            "event.severity": 42,
        }
        for index in range(count)
    ]
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
        newline="\n",
    )
    return path


# -- registration -----------------------------------------------------------


def test_registration_publishes_a_class_under_its_type_name(clean_registries: None) -> None:
    register_builtins()
    assert CONNECTOR_TYPES["sample_jsonl"] is SampleJsonlConnector
    assert FORWARDER_TYPES["sink"] is SinkForwarder


def test_registering_the_same_class_twice_is_idempotent(clean_registries: None) -> None:
    register_builtins()
    register_builtins()
    assert len([name for name in CONNECTOR_TYPES if name == "sample_jsonl"]) == 1


@pytest.mark.parametrize(
    ("registrar", "registry", "cls"),
    [
        (register_connector, CONNECTOR_TYPES, _UnnamedConnector),
        (register_forwarder, FORWARDER_TYPES, _UnnamedSink),
    ],
)
def test_a_class_with_no_type_name_cannot_be_registered(
    clean_registries: None, registrar: Any, registry: dict[str, type[Any]], cls: type[Any]
) -> None:
    with pytest.raises(ConfigError, match="cannot be registered: type_name is empty"):
        registrar(cls)
    assert "" not in registry


@pytest.mark.parametrize(
    ("registrar", "cls", "label"),
    [
        (register_connector, _HijackConnector, "connector type"),
        (register_forwarder, _HijackSink, "forwarder type"),
    ],
)
def test_a_second_class_under_a_taken_name_is_refused(
    clean_registries: None, registrar: Any, cls: type[Any], label: str
) -> None:
    register_builtins()
    with pytest.raises(ConfigError, match=f"{label} .* is already registered by"):
        registrar(cls)


def test_the_error_names_the_class_that_already_holds_the_name(clean_registries: None) -> None:
    register_builtins()
    with pytest.raises(ConfigError, match="SampleJsonlConnector"):
        register_connector(_HijackConnector)


def test_summaries_list_every_registered_type_with_its_one_line_description(
    clean_registries: None,
) -> None:
    register_builtins()
    sources = connector_summaries()
    destinations = forwarder_summaries()
    assert list(sources) == sorted(sources)
    assert sources["sample_jsonl"] == SampleJsonlConnector.summary
    assert destinations["sink"] == SinkForwarder.summary
    assert all(summary for summary in sources.values())


# -- resolution -------------------------------------------------------------


def test_an_unknown_source_type_is_reported_with_the_known_names(
    clean_registries: None, config: Callable[..., AppConfig]
) -> None:
    register_builtins()
    source = SourceConfig.model_validate({"id": "ct", "type": "cloudtrail"})
    with pytest.raises(
        ConfigError, match=r"unknown source type 'cloudtrail'; known: .*sample_jsonl"
    ):
        build_connector(config(), source, metrics=Metrics())


def test_an_unknown_destination_type_is_reported_with_the_known_names(
    clean_registries: None, config: Callable[..., AppConfig]
) -> None:
    built = config()
    destination = DestinationConfig.model_validate({"id": "x", "type": "wazuh"})
    with pytest.raises(ConfigError, match=r"unknown destination type 'wazuh'; known: sink"):
        build_forwarder(built, destination, metrics=Metrics())


# -- per-object builders ----------------------------------------------------


def test_build_checkpoint_uses_the_configured_paths_and_window(tmp_path: Path) -> None:
    built = parse_config(
        {
            "pipeline": {"state_dir": str(tmp_path / "state"), "dedup_window": 7},
            "sources": [{"id": "demo", "type": "sample_jsonl"}],
            "destinations": [{"id": "s", "type": "sink"}],
        }
    )
    source = built.sources[0]
    store = build_checkpoint(built, source)
    assert store.path == tmp_path / "state" / "demo.json"
    assert store.connector_id == "demo"
    assert store.max_seen_ids == 7


def test_build_dead_letter_inherits_the_redaction_policy(tmp_path: Path) -> None:
    built = parse_config(
        {
            "pipeline": {"dead_letter_dir": str(tmp_path / "dl")},
            "redaction": {"mode": "drop"},
            "sources": [{"id": "demo", "type": "sample_jsonl"}],
            "destinations": [{"id": "s", "type": "sink"}],
        }
    )
    queue = build_dead_letter(built, "demo")
    assert queue.path == tmp_path / "dl" / "demo.jsonl"
    assert queue.redaction is not None and queue.redaction.mode == "drop"


def test_build_connector_resolves_the_registered_class_and_passes_the_wiring(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl", 2)
    built = config()
    connector = build_connector(built, built.sources[0], metrics=Metrics())
    assert isinstance(connector, SampleJsonlConnector)
    assert connector.id == "demo"
    assert connector.path == tmp_path / "in.jsonl"
    assert connector.checkpoint.path == built.state_path("demo")
    assert connector.context.retry_policy == built.retry
    assert isinstance(connector.context.limiter, NoLimiter)


def test_build_connector_makes_a_bucket_from_a_declared_rate(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = parse_config(
        {
            **base_raw(tmp_path),
            "sources": [
                {
                    "id": "demo",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                    "requests_per_minute": 30,
                }
            ],
            "destinations": [{"id": "recorded", "type": "sink"}],
        }
    )
    connector = build_connector(built, built.sources[0], metrics=Metrics())
    limiter = connector.context.limiter
    assert isinstance(limiter, TokenBucket)
    assert limiter.rate == pytest.approx(0.5), "requests per minute, divided by 60"


def test_build_connector_accepts_an_injected_limiter_and_clock(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    fixed = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)
    built = config()
    limiter = NoLimiter()
    connector = build_connector(
        built, built.sources[0], metrics=Metrics(), limiter=limiter, clock=lambda: fixed
    )
    assert connector.context.limiter is limiter
    assert connector.now == fixed


def test_build_connector_does_not_share_the_option_dictionary_with_config(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = config()
    connector = build_connector(built, built.sources[0], metrics=Metrics())
    assert connector.context.options is not built.sources[0].options


def test_build_forwarder_takes_the_redaction_from_the_config_unless_overridden(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    built = config()
    destination = built.destinations[0]
    default = build_forwarder(built, destination, metrics=Metrics())
    assert default.redaction is built.redaction
    override = RedactionSettings(ip_mode="drop")
    explicit = build_forwarder(built, destination, metrics=Metrics(), redaction=override)
    assert explicit.redaction is override


def test_build_forwarder_uses_the_destinations_own_retry_policy(tmp_path: Path) -> None:
    built = parse_config(
        {
            **base_raw(tmp_path),
            "sources": [{"id": "demo", "type": "sample_jsonl"}],
            "destinations": [
                {
                    "id": "slow",
                    "type": "sink",
                    "retry": {"max_attempts": 9, "base_wait_seconds": 0, "max_wait_seconds": 0},
                }
            ],
        }
    )
    forwarder = build_forwarder(built, built.destinations[0], metrics=Metrics())
    assert forwarder.context.retry_policy == RetryPolicy(
        max_attempts=9, base_wait_seconds=0, max_wait_seconds=0, jitter_ratio=0.5
    )


# -- the whole pipeline -----------------------------------------------------


def test_build_pipeline_wires_one_runtime_per_enabled_source_and_route_per_destination(
    config: Callable[..., AppConfig], tmp_path: Path, metrics: Metrics
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = parse_config(
        {
            **base_raw(tmp_path),
            "sources": [
                {
                    "id": "demo",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                },
                {
                    "id": "off",
                    "type": "sample_jsonl",
                    "enabled": False,
                    "options": {"path": str(tmp_path / "in.jsonl")},
                },
            ],
            "destinations": [
                {"id": "recorded", "type": "sink"},
                {"id": "quiet", "type": "sink", "enabled": False},
            ],
        }
    )
    pipeline = build_pipeline(built, metrics=metrics)
    assert [runtime.connector.id for runtime in pipeline.runner.sources] == ["demo"]
    assert [route.forwarder.id for route in pipeline.dispatcher.routes] == ["recorded"]
    assert pipeline.metrics is metrics
    assert len(pipeline.connectors) == 1 and len(pipeline.forwarders) == 1


def test_build_pipeline_loads_state_and_opens_destinations(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "demo.json").write_text(
        json.dumps({"connector_id": "demo", "cursor": "already-here"}), encoding="utf-8"
    )
    target = tmp_path / "sink" / "received.jsonl"
    built = config(
        destinations=[{"id": "recorded", "type": "sink", "options": {"record_file": str(target)}}]
    )
    pipeline = build_pipeline(built)
    assert pipeline.runner.sources[0].checkpoint.state.cursor == "already-here"
    assert target.parent.is_dir(), "open() ran, so the record directory already exists"
    pipeline.close()


def test_build_pipeline_carries_the_per_source_routing_subset(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = parse_config(
        {
            **base_raw(tmp_path),
            "sources": [
                {
                    "id": "demo",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                    "destinations": ["alerts"],
                },
                {
                    "id": "other",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                },
            ],
            "destinations": [
                {"id": "index", "type": "sink"},
                {"id": "alerts", "type": "sink"},
                {"id": "ignored", "type": "sink", "enabled": False},
            ],
        }
    )
    pipeline = build_pipeline(built)
    runtimes = {runtime.connector.id: runtime for runtime in pipeline.runner.sources}
    assert runtimes["demo"].destinations == ("alerts",)
    assert runtimes["other"].destinations is None
    pipeline.close()


def test_a_source_routed_only_to_disabled_destinations_is_refused(tmp_path: Path) -> None:
    """A routing list that names nothing live would discard every event it reads."""
    with pytest.raises(ConfigError, match=r"routes only to disabled destination\(s\)"):
        parse_config(
            {
                **base_raw(tmp_path),
                "sources": [
                    {"id": "demo", "type": "sample_jsonl", "destinations": ["void", "index"]}
                ],
                "destinations": [
                    {"id": "index", "type": "sink", "enabled": False},
                    {"id": "void", "type": "sink", "enabled": False},
                ],
            }
        )


def test_routes_take_their_floor_batch_and_retry_from_the_destination(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = parse_config(
        {
            **base_raw(tmp_path),
            "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
            "sources": [
                {
                    "id": "demo",
                    "type": "sample_jsonl",
                    "options": {"path": str(tmp_path / "in.jsonl")},
                    "batch_size": 3,
                }
            ],
            "destinations": [
                {"id": "alerts", "type": "sink", "severity_min": 85, "batch_size": 10},
                {"id": "index", "type": "sink"},
            ],
        }
    )
    pipeline = build_pipeline(built)
    routes = {route.forwarder.id: route for route in pipeline.dispatcher.routes}
    assert routes["alerts"].severity_min == 85
    assert routes["alerts"].batch_size == 10
    assert routes["index"].batch_size == 5, "falls back to the pipeline default"
    assert routes["alerts"].retry_policy == built.retry
    assert pipeline.runner.sources[0].batch_size == 3
    pipeline.close()


def test_the_runner_dispatches_only_to_the_sources_own_destinations(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl", 2)
    index_file = tmp_path / "index" / "received.jsonl"
    alerts_file = tmp_path / "alerts" / "received.jsonl"
    built = config(
        sources=[
            {
                "id": "demo",
                "type": "sample_jsonl",
                "options": {"path": str(tmp_path / "in.jsonl")},
                "destinations": ["index"],
            }
        ],
        destinations=[
            {"id": "index", "type": "sink", "options": {"record_file": str(index_file)}},
            {"id": "alerts", "type": "sink", "options": {"record_file": str(alerts_file)}},
        ],
    )
    pipeline = build_pipeline(built)
    pipeline.runner.run(once=True)
    pipeline.close()
    assert len(index_file.read_text(encoding="utf-8").splitlines()) == 2
    assert not alerts_file.exists(), "the alert destination was never asked for these events"


def test_build_pipeline_honours_the_injected_sleeper(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    built = config()
    pipeline = build_pipeline(built, sleeper=lambda _seconds: True)
    assert pipeline.runner.sleeper is not pipeline.runner.stop_event.wait
    state = pipeline.runner.run()
    assert (state.cycles, state.stopped) == (1, True)
    pipeline.close()


def test_close_stops_producing_before_flushing(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    pipeline = build_pipeline(config())
    order: list[str] = []
    pipeline.connectors[0].close = lambda: order.append("connector")  # type: ignore[method-assign]
    pipeline.forwarders[0].close = lambda: order.append("forwarder")  # type: ignore[method-assign]
    pipeline.close()
    pipeline.close()
    assert order == ["connector", "forwarder"], "close() is ordered and runs once"


def test_status_reports_connectors_destinations_and_metrics(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    write_sample(tmp_path / "in.jsonl")
    metrics = Metrics()
    metrics.incr("cycles", source="demo")
    pipeline = build_pipeline(config(), metrics=metrics)
    report = pipeline.status()
    assert set(report) == {"connectors", "destinations", "metrics"}
    assert report["connectors"][0]["connector_id"] == "demo"
    assert report["destinations"][0]["forwarder_id"] == "recorded"
    assert report["metrics"]["totals"]["cycles"] == 1
    pipeline.close()


def test_the_document_a_sink_records_is_the_schema_serialisation_of_a_normalised_event(
    config: Callable[..., AppConfig], tmp_path: Path
) -> None:
    """Wiring sanity: what leaves the pipeline is exactly what ``to_document`` produces."""
    write_sample(tmp_path / "in.jsonl")
    target = tmp_path / "sink" / "received.jsonl"
    built = config(
        destinations=[{"id": "recorded", "type": "sink", "options": {"record_file": str(target)}}]
    )
    pipeline = build_pipeline(built)
    pipeline.runner.run(once=True)
    pipeline.close()

    connector = pipeline.connectors[0]
    connector.checkpoint.reset()  # re-read from byte 0, so the same event can be rebuilt
    raw = next(SampleJsonlConnector(connector.context).fetch())
    assert json.loads(target.read_text(encoding="utf-8")) == to_document(
        connector.normalize(connector.parse(raw))
    )
