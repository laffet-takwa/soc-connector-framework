"""Structured logging: one JSON object per line, no secrets in it.

A SOC tool should be readable by the very systems it feeds, so the default format is JSON
with an ECS-ish ``@timestamp``. Extra context arrives through ``extra=`` and is copied into
the JSON document; keys that look like credentials are masked before serialization because
a connector bug should not be able to write a token into a log aggregator.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from typing import Any

from soc_connectors.utils.time import to_iso_z

ROOT_LOGGER_NAME = "soc_connectors"
REDACTED = "***"
SENSITIVE_KEY = re.compile(
    r"(secret|password|passwd|token|api[_-]?key|access[_-]?key|authorization|credential|cookie|session[_-]?id)",
    re.IGNORECASE,
)
_RESERVED = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}


def sanitize(value: Any, *, key_hint: str = "") -> Any:
    """Recursively mask anything whose key looks like a credential."""
    if SENSITIVE_KEY.search(key_hint):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(key): sanitize(item, key_hint=str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, datetime):
        return to_iso_z(value.astimezone(UTC) if value.tzinfo else value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _record_time(record: logging.LogRecord) -> str:
    """The record's creation instant, in the same ISO-8601 ``Z`` form ECS documents use."""
    return to_iso_z(datetime.fromtimestamp(record.created, tz=UTC))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "@timestamp": _record_time(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = sanitize(value, key_hint=key)
        return json.dumps(payload, ensure_ascii=False, default=str, sort_keys=True)


class ConsoleFormatter(logging.Formatter):
    """Human-readable alternative for ``SOC_LOG_FORMAT=console`` while debugging locally."""

    def format(self, record: logging.LogRecord) -> str:
        context = {
            key: sanitize(value, key_hint=key)
            for key, value in record.__dict__.items()
            if key not in _RESERVED and not key.startswith("_")
        }
        suffix = f" {context}" if context else ""
        head = f"{_record_time(record)} {record.levelname:<7} {record.name}:"
        return f"{head} {record.getMessage()}{suffix}"


def configure_logging(
    *,
    level: str = "INFO",
    log_format: str = "json",
    stream: Any = None,
) -> logging.Logger:
    """Attach exactly one handler to the package logger and return it."""
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    suffix = log_format.lower()
    formatter: logging.Formatter = ConsoleFormatter() if suffix == "console" else JsonFormatter()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_logger(suffix: str = "") -> logging.Logger:
    """Return a logger under the package root so it always inherits our handlers."""
    if suffix:
        return logging.getLogger(f"{ROOT_LOGGER_NAME}.{suffix}")
    return logging.getLogger(ROOT_LOGGER_NAME)


def bind(logger: logging.Logger, **context: Any) -> logging.LoggerAdapter[logging.Logger]:
    """Attach stable fields (``connector_id``, ``forwarder_id``) to every record."""

    class _Adapter(logging.LoggerAdapter[logging.Logger]):
        def process(
            self, msg: str, kwargs: MutableMapping[str, Any]
        ) -> tuple[str, MutableMapping[str, Any]]:
            extra: dict[str, Any] = dict(self.extra or {})
            extra.update(kwargs.get("extra") or {})
            kwargs["extra"] = extra
            return msg, kwargs

    return _Adapter(logger, context)
