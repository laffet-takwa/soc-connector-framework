"""YAML configuration, with secrets resolved from the environment at load time.

Nothing in a config file may be a credential. A value written as ``${SOC_ENTRA_CLIENT_SECRET}``
is replaced from the process environment while the raw mapping is still unvalidated, so the
secret never appears in a committed file, a log line or a ``repr``. A missing reference is a
startup error naming the variable — never its value.

Keys that are known credentials are then wrapped in ``SecretStr``, so debugging output prints
``**********`` where a plain string would print the secret. Connectors read them through
``ConnectorContext.secret()``, which unwraps them at the one place they are needed.

Interpolation runs before validation, which is why a resolved value is marked
:class:`EnvResolved`: without the mark, the literal-credential guard could not tell the
secret it just fetched from the environment from one somebody pasted into the file.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from soc_connectors.exceptions import ConfigError
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.retry import RetryPolicy

CONFIG_VERSION = 1
ENV_PATTERN = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}")
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: Option keys whose value is a credential, so a literal here is refused and a resolved
#: reference is wrapped in ``SecretStr``.
SENSITIVE_OPTION_KEYS = frozenset(
    {
        "client_secret",
        "api_key",
        "apikey",
        "token",
        "access_key",
        "secret_key",
        "password",
        "bearer_token",
        "auth_token",
    }
)


class EnvResolved(str):
    """A config string that arrived from the environment through a ``${VAR}`` reference.

    Interpolation happens before validation, so by the time the literal-credential guard sees
    ``client_secret`` it holds the secret itself and cannot tell a resolved reference from a
    pasted value. Subclassing ``str`` keeps the value usable everywhere a config string is, and
    gives the guard something it can trust. A ``${VAR:-fallback}`` that fell back is *not*
    marked: its text came from the file.
    """


def interpolate_env(value: Any, *, env: Mapping[str, str] | None = None) -> Any:
    """Replace every ``${VAR}`` or ``${VAR:-default}`` in a config tree with its env value."""
    environ = os.environ if env is None else env
    if isinstance(value, str):
        return _interpolate_string(value, environ)
    if isinstance(value, Mapping):
        return {key: interpolate_env(item, env=environ) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [interpolate_env(item, env=environ) for item in value]
    return value


def _interpolate_string(text: str, environ: Mapping[str, str]) -> Any:
    missing: list[str] = []
    used_fallback = False

    def replace(match: re.Match[str]) -> str:
        nonlocal used_fallback
        name = match.group("name")
        default = match.group("default")
        if name in environ:
            return environ[name]
        if default is not None:
            used_fallback = True
            return default
        missing.append(name)
        return ""

    result = ENV_PATTERN.sub(replace, text)
    if missing:
        raise ConfigError(
            "environment variable(s) referenced by the configuration are not set: "
            + ", ".join(sorted(set(missing)))
            + ". Export them, or add them to your .env file (never commit the values)."
        )
    if ENV_PATTERN.search(text) and not used_fallback:
        return EnvResolved(result)
    return result


def _check_identifier(value: str) -> str:
    if not ID_PATTERN.match(value):
        raise ValueError(f"{value!r} is not a lowercase id matching {ID_PATTERN.pattern}")
    return value


def _reject_literal_secrets(options: Mapping[str, Any], *, where: str) -> None:
    """Refuse an option that looks like a literal credential instead of an env reference.

    This cannot prove a value is real, and does not try to: it stops the common accident of
    pasting a secret into a config file by making the indirection mandatory. A value that
    interpolation marked as environment-resolved is the intended flow, so it passes through.
    """
    for key, value in options.items():
        if key.split(".")[-1].lower() not in SENSITIVE_OPTION_KEYS:
            continue
        if not isinstance(value, str) or not value:
            continue
        if isinstance(value, EnvResolved) or ENV_PATTERN.search(value):
            continue
        raise ConfigError(
            f"{where}: option '{key}' looks like a literal credential. "
            f"Use ${{{key.upper().replace('.', '_')}}} and export it in the environment instead."
        )


def _wrap_secrets(options: dict[str, Any]) -> dict[str, Any]:
    for key, value in options.items():
        if key.split(".")[-1].lower() in SENSITIVE_OPTION_KEYS and isinstance(value, str) and value:
            options[key] = SecretStr(value)
    return options


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PipelineSettings(_Section):
    poll_interval_seconds: float = Field(default=30, ge=1, le=86_400)
    batch_size: int = Field(default=200, ge=1, le=10_000)
    max_pages_per_cycle: int = Field(default=20, ge=1, le=1_000)
    state_dir: Path = Path("data/state")
    dead_letter_dir: Path = Path("data/dead_letter")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    shutdown_grace_seconds: float = Field(default=10, ge=0, le=300)
    dedup_window: int = Field(default=2000, ge=1, le=100_000)
    """How many recent event identities the checkpoint remembers for de-duplication."""


class SourceConfig(_Section):
    id: str
    type: str
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)
    retry: RetryPolicy | None = None
    batch_size: int | None = Field(default=None, ge=1, le=10_000)
    destinations: list[str] | None = None
    """Fan-out subset; ``None`` means every enabled destination."""

    requests_per_minute: float | None = Field(default=None, gt=0)
    """Declared quota for the source's API; ``None`` means unlimited."""

    @field_validator("id", "type")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _check_identifier(value)

    @model_validator(mode="after")
    def _guard_secrets(self) -> SourceConfig:
        _reject_literal_secrets(self.options, where=f"source {self.id}")
        _wrap_secrets(self.options)
        return self


class DestinationConfig(_Section):
    id: str
    type: str
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)
    retry: RetryPolicy | None = None
    batch_size: int | None = Field(default=None, ge=1, le=10_000)
    severity_min: int = Field(default=0, ge=0, le=99)
    """Route only events at or above this ECS severity — how TheHive sees alerts, not noise."""

    requests_per_minute: float | None = Field(default=None, gt=0)

    @field_validator("id", "type")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _check_identifier(value)

    @model_validator(mode="after")
    def _guard_secrets(self) -> DestinationConfig:
        _reject_literal_secrets(self.options, where=f"destination {self.id}")
        _wrap_secrets(self.options)
        return self


class AppConfig(_Section):
    version: int = CONFIG_VERSION
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    sources: list[SourceConfig] = Field(default_factory=list)
    destinations: list[DestinationConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> AppConfig:
        for label, items in (("source", self.sources), ("destination", self.destinations)):
            seen: set[str] = set()
            for item in items:
                if item.id in seen:
                    raise ValueError(f"duplicate {label} id: {item.id!r}")
                seen.add(item.id)
        destination_ids = {item.id for item in self.destinations}
        enabled_ids = {item.id for item in self.destinations if item.enabled}
        for source in self.sources:
            if source.destinations is not None and not source.destinations:
                raise ValueError(
                    f"source {source.id!r} routes to an empty destination list; "
                    "omit the key to route to every enabled destination"
                )
            routed = set(source.destinations or ())
            unknown = routed - destination_ids
            if unknown:
                raise ValueError(
                    f"source {source.id!r} routes to unknown destination(s): {sorted(unknown)}"
                )
            if source.enabled and routed and routed.isdisjoint(enabled_ids):
                raise ValueError(
                    f"source {source.id!r} routes only to disabled destination(s): "
                    f"{sorted(routed - enabled_ids)}; the events it reads would be discarded"
                )
        if not any(item.enabled for item in self.sources):
            raise ValueError("no enabled sources configured")
        if not any(item.enabled for item in self.destinations):
            raise ValueError(
                "no enabled destinations configured: the pipeline would read events and "
                "deliver nothing"
            )
        return self

    def enabled_sources(self) -> list[SourceConfig]:
        return [item for item in self.sources if item.enabled]

    def enabled_destinations(self) -> list[DestinationConfig]:
        return [item for item in self.destinations if item.enabled]

    def destinations_for(self, source: SourceConfig) -> list[DestinationConfig]:
        enabled = self.enabled_destinations()
        if source.destinations is None:
            return enabled
        wanted = set(source.destinations)
        return [item for item in enabled if item.id in wanted]

    def retry_policy_for(self, item: SourceConfig | DestinationConfig) -> RetryPolicy:
        return item.retry or self.retry

    def batch_size_for(self, item: SourceConfig | DestinationConfig) -> int:
        return item.batch_size or self.pipeline.batch_size

    def state_path(self, connector_id: str) -> Path:
        return self.pipeline.state_dir / f"{connector_id}.json"

    def dead_letter_path(self, connector_id: str) -> Path:
        return self.pipeline.dead_letter_dir / f"{connector_id}.jsonl"

    def describe(self) -> dict[str, Any]:
        """A secret-free summary for ``validate-config``."""
        return {
            "version": self.version,
            "pipeline": {
                "poll_interval_seconds": self.pipeline.poll_interval_seconds,
                "batch_size": self.pipeline.batch_size,
                "max_pages_per_cycle": self.pipeline.max_pages_per_cycle,
                "state_dir": str(self.pipeline.state_dir),
                "dead_letter_dir": str(self.pipeline.dead_letter_dir),
                "log_level": self.pipeline.log_level,
                "log_format": self.pipeline.log_format,
                "dedup_window": self.pipeline.dedup_window,
            },
            "retry": self.retry.model_dump(),
            "redaction": self.redaction.model_dump(),
            "sources": [
                {
                    "id": item.id,
                    "type": item.type,
                    "enabled": item.enabled,
                    "option_keys": sorted(item.options),
                    "routes_to": item.destinations,
                }
                for item in self.sources
            ],
            "destinations": [
                {
                    "id": item.id,
                    "type": item.type,
                    "enabled": item.enabled,
                    "severity_min": item.severity_min,
                    "option_keys": sorted(item.options),
                }
                for item in self.destinations
            ],
        }


def parse_config(raw: Mapping[str, Any]) -> AppConfig:
    try:
        return AppConfig.model_validate(dict(raw))
    except ValidationError as exc:
        raise ConfigError(_render_validation_error(exc)) from exc


def _render_validation_error(exc: ValidationError) -> str:
    lines = [f"configuration is invalid ({exc.error_count()} problem(s)):"]
    for issue in exc.errors():
        location = ".".join(str(part) for part in issue.get("loc", ())) or "<root>"
        lines.append(f"  - {location}: {issue.get('msg')}")
    return "\n".join(lines)


def load_config(path: Path, *, env: Mapping[str, str] | None = None) -> AppConfig:
    """Read, interpolate and validate a config file.

    ``env`` is passed explicitly by the tests so a missing-secret failure is reproducible
    without mutating the real process environment.
    """
    source = Path(path)
    if not source.exists():
        raise ConfigError(f"configuration file not found: {source}")
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read configuration file {source}: {exc}") from exc
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"configuration file {source} is not valid YAML: {exc}") from exc
    if loaded is None:
        raise ConfigError(f"configuration file {source} is empty")
    if not isinstance(loaded, Mapping):
        raise ConfigError(f"configuration file {source} must contain a mapping at the top level")
    return parse_config(interpolate_env(loaded, env=env))
