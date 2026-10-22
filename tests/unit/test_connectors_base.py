"""``BaseConnector``: the convenience surface a source author gets for free, and its guards."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest
from pydantic import SecretStr

from soc_connectors.connectors.base import BaseConnector, ConnectorContext
from soc_connectors.exceptions import ConfigError
from soc_connectors.metrics import Metrics
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.types import ParsedEvent, RawEvent
from soc_connectors.utils.rate_limit import NoLimiter

pytestmark = pytest.mark.unit

FIXED_NOW = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)
SYNTHETIC = "x" * 32


class MinimalConnector(BaseConnector):
    type_name: ClassVar[str] = "minimal"
    summary: ClassVar[str] = "The smallest connector the contract allows."

    def fetch(self) -> Iterator[RawEvent]:
        yield self.make_raw('{"action": "x"}', cursor="7", metadata={"file": "demo.jsonl"})

    def parse(self, raw: RawEvent) -> ParsedEvent:
        return ParsedEvent(raw=raw, fields={"action": "x"}, source_event_type="minimal")

    def normalize(self, parsed: ParsedEvent) -> EcsEvent:
        return EcsEvent.model_validate(
            {"@timestamp": parsed.raw.received_at, "event": {"action": parsed.fields["action"]}}
        )


class UnnamedConnector(MinimalConnector):
    type_name: ClassVar[str] = ""


@pytest.fixture
def options() -> dict[str, Any]:
    return {"path": "data/sample/events.jsonl", "blank": "   ", "zero": 0, "count": 3}


@pytest.fixture
def context(
    checkpoint_store: Callable[..., Any],
    metrics: Metrics,
    retry_policy: Any,
    options: dict[str, Any],
) -> ConnectorContext:
    return ConnectorContext(
        connector_id="minimal",
        options=options,
        checkpoint=checkpoint_store("minimal"),
        retry_policy=retry_policy,
        metrics=metrics,
        limiter=NoLimiter(),
        clock=lambda: FIXED_NOW,
    )


@pytest.fixture
def connector(context: ConnectorContext) -> MinimalConnector:
    return MinimalConnector(context)


def test_a_connector_must_implement_the_three_stages(context: ConnectorContext) -> None:
    with pytest.raises(TypeError, match="abstract"):
        BaseConnector(context)  # type: ignore[abstract]


def test_a_type_name_is_mandatory_or_the_registry_cannot_find_it(context: ConnectorContext) -> None:
    with pytest.raises(ConfigError, match="declares no type_name"):
        UnnamedConnector(context)


def test_the_context_is_reachable_through_short_properties(connector: MinimalConnector) -> None:
    assert connector.id == "minimal"
    assert connector.metrics is connector.context.metrics
    assert connector.checkpoint is connector.context.checkpoint
    assert connector.now == FIXED_NOW
    assert isinstance(connector.log, logging.Logger)
    assert connector.log.name == f"soc_connectors.connector.{connector.id}"


def test_option_reads_with_a_default(connector: MinimalConnector) -> None:
    assert connector.option("count") == 3
    assert connector.option("absent", "fallback") == "fallback"
    assert connector.option("zero") == 0


def test_require_option_refuses_missing_and_blank(connector: MinimalConnector) -> None:
    assert connector.require_option("path") == "data/sample/events.jsonl"
    with pytest.raises(ConfigError, match="requires option 'absent'"):
        connector.require_option("absent")
    with pytest.raises(ConfigError, match="requires option 'blank'"):
        connector.require_option("blank")


def test_require_option_accepts_a_falsy_value_that_is_a_real_setting(
    connector: MinimalConnector,
) -> None:
    """``0`` is an answer, not an absence: only missing and blank text are refused."""
    assert connector.require_option("zero") == 0


def test_secret_unwraps_the_masked_value(
    connector: MinimalConnector, context: ConnectorContext, options: dict[str, Any]
) -> None:
    options["client_secret"] = SecretStr(SYNTHETIC)
    assert connector.secret("client_secret") == SYNTHETIC
    assert SYNTHETIC not in repr(options["client_secret"])


def test_secret_accepts_a_plain_string_when_a_test_supplied_one(
    connector: MinimalConnector,
) -> None:
    assert connector.secret("path") == "data/sample/events.jsonl"


def test_secret_refuses_to_invent_a_credential(connector: MinimalConnector) -> None:
    with pytest.raises(ConfigError, match="requires secret 'api_key'"):
        connector.secret("api_key")


def test_secret_refuses_a_non_string(connector: MinimalConnector) -> None:
    with pytest.raises(ConfigError, match="is not a string"):
        connector.secret("count")


def test_acquire_asks_the_pipeline_limiter_for_quota(connector: MinimalConnector) -> None:
    limiter = connector.context.limiter
    assert isinstance(limiter, NoLimiter)
    assert connector.acquire() is True
    assert connector.acquire(2, timeout=0.5) is True
    assert limiter.granted == 3, "the connector must not keep its own counter"


def test_a_bad_acquire_request_fails_loudly(connector: MinimalConnector) -> None:
    with pytest.raises(ValueError):
        connector.acquire(0)
    with pytest.raises(ValueError):
        connector.acquire(1, timeout=-1)


def test_make_raw_stamps_the_connector_and_the_clock(connector: MinimalConnector) -> None:
    raw = next(connector.fetch())
    assert raw.connector_id == connector.id
    assert raw.received_at == FIXED_NOW
    assert raw.cursor == "7"
    assert raw.metadata == {"file": "demo.jsonl"}
    assert raw.as_text() == '{"action": "x"}'


def test_make_raw_defaults_metadata_to_an_empty_mapping(connector: MinimalConnector) -> None:
    raw = connector.make_raw("payload")
    assert raw.metadata == {}
    assert raw.cursor is None


def test_health_reports_the_position_and_the_counters(
    connector: MinimalConnector, metrics: Metrics
) -> None:
    metrics.incr("fetched", source=connector.id, by=4)
    connector.checkpoint.advance(cursor="offset:4096", seen_ids=["a", "b"])
    assert connector.health() == {
        "connector_id": "minimal",
        "type": "minimal",
        "cursor": "offset:4096",
        "last_timestamp": None,
        "seen_ids": 2,
        "metrics": {"fetched": 4},
    }


def test_health_includes_the_timestamp_the_source_reached(connector: MinimalConnector) -> None:
    connector.checkpoint.advance(last_timestamp=FIXED_NOW)
    assert connector.health()["last_timestamp"] == FIXED_NOW.isoformat()


def test_close_is_an_optional_hook_and_safe_twice(connector: MinimalConnector) -> None:
    connector.close()
    connector.close()
