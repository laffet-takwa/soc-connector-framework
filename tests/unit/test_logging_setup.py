"""Structured logging: parseable by the SOC tools it feeds, and mute about credentials."""

from __future__ import annotations

import io
import json
import logging
import re
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

from soc_connectors.logging_setup import (
    REDACTED,
    ROOT_LOGGER_NAME,
    ConsoleFormatter,
    JsonFormatter,
    bind,
    configure_logging,
    get_logger,
    sanitize,
)

pytestmark = pytest.mark.unit

# Short and synthetic on purpose. The mask keys off the field *name*, so the value under test
# carries no information, and this file is scanned for credential-shaped literals like every
# other file in the repository.
KEY = "abc12"


@pytest.fixture
def package_logger() -> Iterator[logging.Logger]:
    """The real package logger, restored to its prior state afterwards."""
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    saved_handlers = list(logger.handlers)
    saved_level = logger.level
    saved_propagate = logger.propagate
    for handler in saved_handlers:
        logger.removeHandler(handler)
    yield logger
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    for handler in saved_handlers:
        logger.addHandler(handler)
    logger.setLevel(saved_level)
    logger.propagate = saved_propagate


def record(
    level: int = logging.INFO,
    msg: str = "forwarded a batch",
    *,
    name: str = "soc_connectors.forwarder",
    **extra: Any,
) -> logging.LogRecord:
    prepared = logging.LogRecord(name, level, "path.py", 1, msg, None, None)
    for key, value in extra.items():
        setattr(prepared, key, value)
    return prepared


def to_payload(formatter: logging.Formatter, rec: logging.LogRecord) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(formatter.format(rec))
    return payload


def to_payload_from_stream(stream: io.StringIO) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(stream.getvalue())
    return payload


# -- sanitize --------------------------------------------------------------


def test_a_credential_shaped_key_is_masked_wherever_it_sits() -> None:
    assert sanitize({"client_secret": KEY}) == {"client_secret": REDACTED}
    # The mask is applied to the leaf that names the credential, not to its parent.
    assert sanitize({"nested": {"access_key": KEY}}) == {"nested": {"access_key": REDACTED}}
    assert sanitize({"options": {"password": {"deep": "x"}}}) == {"options": {"password": REDACTED}}


@pytest.mark.parametrize(
    "key",
    ["secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "cookie"],
)
def test_the_masked_names_cover_the_ones_a_connector_can_carry(key: str) -> None:
    assert sanitize({key: "value"}) == {key: REDACTED}


def test_an_ordinary_key_keeps_its_value() -> None:
    assert sanitize({"connector_id": "cloudtrail", "batch_size": 20}) == {
        "connector_id": "cloudtrail",
        "batch_size": 20,
    }


def test_lists_are_walked_but_not_masked_by_their_own_name() -> None:
    assert sanitize({"related": ["a", {"token": "x"}]}) == {"related": ["a", {"token": REDACTED}]}
    assert sanitize(["plain", 1, None]) == ["plain", 1, None]


def test_datetimes_become_iso_z_so_logs_and_ecs_agree() -> None:
    aware = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)
    naive = datetime(2026, 10, 22, 9, 0)
    assert sanitize({"at": aware}) == {"at": "2026-10-22T09:00:00.000Z"}
    assert sanitize({"at": naive}) == {"at": "2026-10-22T09:00:00.000Z"}


def test_an_object_that_is_not_json_is_stringified_not_dropped() -> None:
    class Pathlike:
        def __str__(self) -> str:
            return "data/state/demo.json"

    assert sanitize({"path": Pathlike()}) == {"path": "data/state/demo.json"}


# -- the formatters --------------------------------------------------------


def test_json_output_is_one_parseable_object_per_line() -> None:
    payload = to_payload(JsonFormatter(), record(connector_id="demo", batch_size=3))
    assert payload["message"] == "forwarded a batch"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "soc_connectors.forwarder"
    assert payload["connector_id"] == "demo"
    assert payload["batch_size"] == 3
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", payload["@timestamp"])


def test_json_output_never_leaks_a_credential_from_extra() -> None:
    line = JsonFormatter().format(record(client_secret=KEY, token=KEY))
    payload = json.loads(line)
    assert payload["client_secret"] == REDACTED
    assert payload["token"] == REDACTED
    assert KEY not in line


def test_the_record_s_own_bookkeeping_stays_out_of_the_document() -> None:
    assert set(to_payload(JsonFormatter(), record())) == {
        "@timestamp",
        "level",
        "logger",
        "message",
    }


def test_private_extra_keys_are_dropped() -> None:
    assert "_scratch" not in to_payload(JsonFormatter(), record(_scratch="temp"))


def test_an_exception_becomes_one_field_not_a_multiline_blob() -> None:
    try:
        raise ValueError("cursor went backwards")
    except ValueError:
        line = JsonFormatter().format(
            record(logging.ERROR, "fetch failed", exc_info=sys.exc_info())
        )
    assert "\n" not in line, "a traceback must not break one-object-per-line"
    payload = json.loads(line)
    assert payload["exception"].startswith("Traceback (most recent call last):")
    assert payload["exception"].endswith("ValueError: cursor went backwards")
    assert payload["message"] == "fetch failed"
    assert payload["level"] == "ERROR"


def test_a_stack_trace_is_kept_as_one_field_too() -> None:
    stack = "Stack (most recent call last):\n  File demo"
    payload = to_payload(JsonFormatter(), record(stack_info=stack))
    assert payload["stack_info"] == stack


def test_unicode_survives_instead_of_becoming_escape_noise() -> None:
    assert to_payload(JsonFormatter(), record(msg="denied — 東京"))["message"] == "denied — 東京"


def test_console_output_is_a_line_with_the_context_appended() -> None:
    line = ConsoleFormatter().format(record(level=logging.WARNING, connector_id="demo"))
    assert "WARNING" in line
    assert "soc_connectors.forwarder" in line
    assert line.startswith("2")
    assert "connector_id" in line and "demo" in line


def test_console_output_without_context_is_just_the_message() -> None:
    line = ConsoleFormatter().format(record())
    assert line.endswith("forwarded a batch")
    assert "{" not in line


def test_console_output_also_masks_credentials() -> None:
    line = ConsoleFormatter().format(record(api_key=KEY))
    assert KEY not in line
    assert REDACTED in line


# -- configure_logging -----------------------------------------------------


def test_configure_logging_attaches_exactly_one_handler(package_logger: logging.Logger) -> None:
    stream = io.StringIO()
    logger = configure_logging(level="INFO", log_format="json", stream=stream)
    assert logger is package_logger
    assert len(logger.handlers) == 1
    logger.warning("still working")
    assert to_payload_from_stream(stream)["level"] == "WARNING"


def test_configuring_twice_replaces_the_previous_handler(
    package_logger: logging.Logger,
) -> None:
    first, second = io.StringIO(), io.StringIO()
    configure_logging(stream=first)
    configure_logging(stream=second)
    assert len(package_logger.handlers) == 1
    get_logger().info("routed once")
    assert first.getvalue() == ""
    assert second.getvalue() != ""


def test_the_level_decides_what_reaches_the_stream(package_logger: logging.Logger) -> None:
    stream = io.StringIO()
    configure_logging(level="WARNING", stream=stream)
    get_logger("runner").info("dropped by level")
    get_logger("runner").error("kept")
    assert stream.getvalue().count("\n") == 1
    assert json.loads(stream.getvalue())["message"] == "kept"


def test_an_unreadable_level_falls_back_to_info(package_logger: logging.Logger) -> None:
    configure_logging(level="VERBOSE")
    assert package_logger.level == logging.INFO


def test_console_format_is_selectable(package_logger: logging.Logger) -> None:
    stream = io.StringIO()
    configure_logging(log_format="console", stream=stream)
    get_logger("cli").info("hello")
    assert "INFO" in stream.getvalue()
    with pytest.raises(json.JSONDecodeError):
        json.loads(stream.getvalue())


def test_package_loggers_do_not_escape_to_the_root(package_logger: logging.Logger) -> None:
    """``propagate = False`` keeps a library import from writing into an application's logs."""
    configure_logging(level="ERROR")
    assert package_logger.propagate is False
    child = get_logger("pipeline.runner")
    assert child.propagate is True
    assert child.getEffectiveLevel() == logging.ERROR, "children inherit the configured level"


# -- bind ------------------------------------------------------------------


def isolated_logger(name: str) -> tuple[logging.Logger, io.StringIO]:
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger, stream


def test_bind_adds_stable_fields_to_every_record() -> None:
    logger, stream = isolated_logger("soc_connectors.test.bound")
    bound = bind(logger, connector_id="demo", forwarder_id="sink")
    bound.info("cycle finished")
    bound.info("cycle finished", extra={"forwarder_id": "override"})

    payloads: list[dict[str, Any]] = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert payloads[0]["connector_id"] == "demo"
    assert payloads[0]["forwarder_id"] == "sink"
    assert payloads[1]["forwarder_id"] == "override"
    assert "extra" not in payloads[1]


def test_bind_leaves_the_underlying_logger_untouched() -> None:
    logger, stream = isolated_logger("soc_connectors.test.unbound")
    bind(logger, connector_id="demo")
    logger.info("plain")
    assert "connector_id" not in stream.getvalue()
