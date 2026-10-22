"""``BaseForwarder`` and ``DeliveryResult``: one honest report per batch."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any, ClassVar, cast

import pytest
from pydantic import SecretStr

from soc_connectors.config import interpolate_env, parse_config
from soc_connectors.exceptions import ConfigError
from soc_connectors.forwarders.base import (
    BaseForwarder,
    DeliveryResult,
    ForwarderContext,
    context_for,
)
from soc_connectors.metrics import Metrics
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.retry import RetryPolicy

pytestmark = pytest.mark.unit

SYNTHETIC = "x" * 32

DESTINATION: dict[str, Any] = {
    "id": "demo-sink",
    "type": "sink",
    "options": {"url": "https://soc.example"},
}


class MinimalForwarder(BaseForwarder):
    type_name: ClassVar[str] = "minimal"

    def send(self, events: Sequence[EcsEvent]) -> DeliveryResult:
        return DeliveryResult(accepted=len(events))


class UnnamedForwarder(MinimalForwarder):
    type_name: ClassVar[str] = ""


@pytest.fixture
def options() -> dict[str, Any]:
    return {"url": "https://soc.example", "blank": "", "zero": 0, "count": 3}


@pytest.fixture
def context(
    options: dict[str, Any], metrics: Metrics, retry_policy: RetryPolicy
) -> ForwarderContext:
    return ForwarderContext(
        forwarder_id="minimal",
        options=options,
        retry_policy=retry_policy,
        metrics=metrics,
        redaction=RedactionSettings(),
    )


@pytest.fixture
def forwarder(context: ForwarderContext) -> MinimalForwarder:
    return MinimalForwarder(context)


# -- DeliveryResult --------------------------------------------------------


def test_a_clean_batch_is_ok() -> None:
    result = DeliveryResult(accepted=3)
    assert result.ok
    assert result.attempts == 1
    assert result.rejected == []
    assert result.identities() == []


def test_a_refused_item_is_not_ok_even_without_an_error() -> None:
    """A 200 response with per-item failures is the Elasticsearch case this exists for."""
    result = DeliveryResult(accepted=1, rejected=[{"identity": "evt-2", "status": 400}])
    assert not result.ok
    assert result.identities() == ["evt-2"]


def test_a_transport_error_is_not_ok() -> None:
    assert not DeliveryResult(error="connection reset").ok


def test_an_identity_missing_from_the_destination_response_is_reported_as_blank() -> None:
    result = DeliveryResult(rejected=[{"status": 500}, {"identity": None}])
    assert result.identities() == ["", "None"]


def test_accepted_and_rejected_can_both_be_nonzero() -> None:
    result = DeliveryResult(
        accepted=2, rejected=[{"identity": "evt-3"}], attempts=3, error="partial"
    )
    assert (result.accepted, result.identities(), result.attempts, result.error) == (
        2,
        ["evt-3"],
        3,
        "partial",
    )


# -- the base class --------------------------------------------------------


def test_a_forwarder_must_implement_send(context: ForwarderContext) -> None:
    with pytest.raises(TypeError, match="abstract"):
        BaseForwarder(context)  # type: ignore[abstract]


def test_a_type_name_is_mandatory(context: ForwarderContext) -> None:
    with pytest.raises(ConfigError, match="declares no type_name"):
        UnnamedForwarder(context)


def test_the_context_is_reachable_through_short_properties(forwarder: MinimalForwarder) -> None:
    assert forwarder.id == "minimal"
    assert forwarder.metrics is forwarder.context.metrics
    assert forwarder.redaction is forwarder.context.redaction
    assert forwarder.log.name == "soc_connectors.forwarder.minimal"
    assert isinstance(forwarder.log, logging.Logger)


def test_option_reads_with_a_default(forwarder: MinimalForwarder) -> None:
    assert forwarder.option("count") == 3
    assert forwarder.option("absent", "fallback") == "fallback"


def test_require_option_refuses_missing_and_blank_but_not_zero(
    forwarder: MinimalForwarder,
) -> None:
    assert forwarder.require_option("zero") == 0
    with pytest.raises(ConfigError, match="forwarder 'minimal' requires option 'index'"):
        forwarder.require_option("index")
    with pytest.raises(ConfigError, match="requires option 'blank'"):
        forwarder.require_option("blank")


def test_secret_unwraps_and_masks(context: ForwarderContext, options: dict[str, Any]) -> None:
    options["api_key"] = SecretStr(SYNTHETIC)
    forwarder = MinimalForwarder(context)
    assert forwarder.secret("api_key") == SYNTHETIC
    assert SYNTHETIC not in repr(options["api_key"])


def test_secret_refuses_to_invent_a_credential(forwarder: MinimalForwarder) -> None:
    with pytest.raises(ConfigError, match="requires secret 'api_key'"):
        forwarder.secret("api_key")


def test_secret_refuses_a_non_string(forwarder: MinimalForwarder) -> None:
    with pytest.raises(ConfigError, match="is not a string"):
        forwarder.secret("count")


# -- redaction belongs to the destination, not the source ------------------


def test_document_for_applies_this_pipeline_s_redaction_policy(
    forwarder: MinimalForwarder,
    context: ForwarderContext,
    options: dict[str, Any],
    make_event: Callable[..., EcsEvent],
) -> None:
    context.redaction = RedactionSettings(fields=["user.name"], mode="mask")
    document = forwarder.document_for(make_event(user={"name": "svc-demo"}))
    assert document["user"]["name"] == "***"
    assert "svc-demo" not in str(document)


def test_the_same_event_is_recorded_differently_by_two_policies(
    forwarder: MinimalForwarder, context: ForwarderContext, make_event: Callable[..., EcsEvent]
) -> None:
    """A destination may be allowed less detail than another one, from the same event."""
    event = make_event(destination={"ip": "203.0.113.7"})
    context.redaction = RedactionSettings(ip_mode="keep")
    assert forwarder.document_for(event)["destination"]["ip"] == "203.0.113.7"
    context.redaction = RedactionSettings(ip_mode="drop")
    assert "destination" not in forwarder.document_for(event)


# -- lifecycle and health --------------------------------------------------


def test_open_and_close_are_optional_hooks(forwarder: MinimalForwarder) -> None:
    forwarder.open()
    forwarder.close()
    forwarder.close()


def test_health_names_the_destination_and_its_counters(
    forwarder: MinimalForwarder, metrics: Metrics
) -> None:
    metrics.incr("forwarded", source="minimal", by=7)
    assert forwarder.health() == {
        "forwarder_id": "minimal",
        "type": "minimal",
        "metrics": {"forwarded": 7},
    }


# -- context_for -----------------------------------------------------------


def test_context_for_copies_the_configured_options(
    metrics: Metrics, retry_policy: RetryPolicy
) -> None:
    config = parse_config(
        {"sources": [{"id": "demo", "type": "sample_jsonl"}], "destinations": [DESTINATION]}
    )
    destination = config.destinations[0]
    built = context_for(
        destination, metrics=metrics, retry_policy=retry_policy, redaction=RedactionSettings()
    )
    assert built.forwarder_id == "demo-sink"
    assert built.options == {"url": "https://soc.example"}
    assert isinstance(destination.options.get("url"), str)
    mutable = cast("dict[str, Any]", built.options)
    mutable["url"] = "changed"
    assert destination.options["url"] == "https://soc.example", "a copy, not a live view"


def test_context_for_carries_a_secret_as_a_masked_value(metrics: Metrics) -> None:
    """``${VAR}`` in the file, ``SecretStr`` in the context, the value only on the wire."""
    raw = interpolate_env(
        {
            "sources": [{"id": "demo", "type": "sample_jsonl"}],
            "destinations": [
                {"id": "hive", "type": "sink", "options": {"api_key": "${SOC_API_KEY}"}}
            ],
        },
        env={"SOC_API_KEY": SYNTHETIC},
    )
    destination = parse_config(raw).destinations[0]
    built = context_for(
        destination, metrics=metrics, retry_policy=RetryPolicy(), redaction=RedactionSettings()
    )
    assert isinstance(built.options["api_key"], SecretStr)
    assert SYNTHETIC not in repr(built.options)
    assert MinimalForwarder(built).secret("api_key") == SYNTHETIC


def test_a_forwarder_can_be_built_from_a_named_context(
    forwarder_context: Callable[[str], Any],
) -> None:
    class Demo(MinimalForwarder):
        type_name: ClassVar[str] = "demo"

    built = Demo(forwarder_context("demo"))
    assert built.health()["type"] == "demo"
