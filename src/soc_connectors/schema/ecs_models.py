"""The ECS document every connector produces and every forwarder consumes.

Elastic Common Schema is a naming contract, not a fixed object: a source is free to fill any
subset of it as long as the fields it does fill mean what ECS says they mean. This module
therefore models the field sets the three demo sources actually produce, keeps unknown extra
fields (``extra="allow"``) instead of silently dropping them, and always serialises with ECS
aliases so the output is what a normal ECS consumer expects.

Field sets are nested objects rather than flattened dotted keys. Elasticsearch maps
``{"source": {"ip": ...}}`` and ``"source.ip": ...`` to the same field, so the nested form is
both valid ECS and easier to type-check.

The names below are ECS's own, verbatim — `cloud.region`, not a `cloud.region_name` shorthand —
and that has to be checked rather than assumed: because the models keep unknown extra fields, a
wrong name is never an error, it is a field that silently indexes nowhere.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.schema.redaction import RedactionSettings, redact_document
from soc_connectors.schema.severity import band, clamp
from soc_connectors.utils.time import ensure_utc, parse_timestamp, to_iso_z, utc_now

#: Version of ECS this schema targets. Bump deliberately: it is written into every document
#: so consumers can tell which contract a stored event was normalised against.
ECS_VERSION = "9.5.0"


class EventKind(StrEnum):
    ALERT = "alert"
    EVENT = "event"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventCategory(StrEnum):
    """The ECS ``event.category`` values this framework's sources can produce."""

    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    FILE = "file"
    HOST = "host"
    NETWORK = "network"
    PROCESS = "process"
    SESSION = "session"
    WEB = "web"

    @classmethod
    def values(cls) -> tuple[str, ...]:
        return tuple(member.value for member in cls)


class NetworkDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"
    INTERNAL = "internal"
    EXTERNAL = "external"


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")


def _string_list(value: Any) -> list[str]:
    """Coerce a scalar, sequence or enum into a de-duplicated lowercase string list."""
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        items: list[Any] = [value]
    else:
        items = list(value)
    seen: list[str] = []
    for item in items:
        text = str(getattr(item, "value", item)).strip().lower()
        if text and text not in seen:
            seen.append(text)
    return seen


def _enum_text(value: Any) -> Any:
    return None if value is None else str(getattr(value, "value", value)).strip().lower()


class EcsVersion(_Model):
    version: str = ECS_VERSION


class EventFieldSet(_Model):
    kind: EventKind | None = None
    category: list[str] = Field(default_factory=list)
    """ECS allows several categories per event; sources rarely use more than one."""

    type: list[str] = Field(default_factory=list)
    action: str | None = None
    outcome: EventOutcome | None = None
    severity: int | None = None
    dataset: str | None = None
    module: str | None = None
    provider: str | None = None
    id: str | None = None
    code: str | None = None
    hash: str | None = None
    duration: int | None = None
    created: datetime | None = None
    reason: str | None = None
    risk_score: float | None = None

    @field_validator("category", "type", mode="before")
    @classmethod
    def _as_string_list(cls, value: Any) -> list[str]:
        return _string_list(value)

    @field_validator("kind", "outcome", mode="before")
    @classmethod
    def _lowercase_enum(cls, value: Any) -> Any:
        return _enum_text(value)

    @field_validator("created", mode="before")
    @classmethod
    def _parse_created(cls, value: Any) -> Any:
        return None if value is None else parse_timestamp(value, field_name="event.created")


class NatInfo(_Model):
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


class Endpoint(_Model):
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    mac: str | None = None
    domain: str | None = None
    nat: NatInfo | None = None


class UserGroupFieldSet(_Model):
    """ECS models `user.group` as an object, so a source that only names the group fills `name`."""

    name: str | None = None
    id: str | None = None
    domain: str | None = None


class UserFieldSet(_Model):
    name: str | None = None
    id: str | None = None
    email: str | None = None
    full_name: str | None = None
    domain: str | None = None
    roles: list[str] = Field(default_factory=list)
    group: UserGroupFieldSet | None = None

    @field_validator("roles", mode="before")
    @classmethod
    def _as_string_list(cls, value: Any) -> list[str]:
        return _string_list(value)


class CloudAccountFieldSet(_Model):
    id: str | None = None
    name: str | None = None


class CloudServiceFieldSet(_Model):
    name: str | None = None


class CloudFieldSet(_Model):
    provider: str | None = None
    region: str | None = None
    availability_zone: str | None = None
    account: CloudAccountFieldSet | None = None
    service: CloudServiceFieldSet | None = None


class NetworkFieldSet(_Model):
    direction: NetworkDirection | None = None
    protocol: str | None = None
    transport: str | None = None
    """Layer-4 name as ECS expects it: ``tcp``, ``udp``, ``icmp``."""

    packets: int | None = None
    bytes: int | None = None
    community_id: str | None = None

    @field_validator("direction", mode="before")
    @classmethod
    def _lowercase_enum(cls, value: Any) -> Any:
        return _enum_text(value)


class RuleFieldSet(_Model):
    name: str | None = None
    category: str | None = None
    author: list[str] = Field(default_factory=list)
    ruleset: str | None = None
    reference: str | None = None


class HostFieldSet(_Model):
    name: str | None = None
    hostname: str | None = None
    id: str | None = None
    ip: list[str] = Field(default_factory=list)


class TlsFieldSet(_Model):
    version: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    fingerprint: str | None = None


class RelatedFieldSet(_Model):
    user: list[str] = Field(default_factory=list)
    ip: list[str] = Field(default_factory=list)

    @field_validator("user", "ip", mode="before")
    @classmethod
    def _as_string_list(cls, value: Any) -> list[str]:
        return _string_list(value)


class ErrorFieldSet(_Model):
    """A cloud API's own failure, which is the payload of most detection rules about that API."""

    code: str | None = None
    message: str | None = None


class UserAgentFieldSet(_Model):
    original: str | None = None


class UrlFieldSet(_Model):
    domain: str | None = None


class EcsEvent(_Model):
    """One normalised event. Forwarders must accept this and nothing else."""

    timestamp: datetime = Field(default_factory=utc_now, alias="@timestamp")
    event: EventFieldSet = Field(default_factory=EventFieldSet)
    ecs: EcsVersion = Field(default_factory=EcsVersion)
    message: str | None = None
    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    raw: Mapping[str, Any] | None = None

    cloud: CloudFieldSet | None = None
    host: HostFieldSet | None = None
    source: Endpoint | None = None
    destination: Endpoint | None = None
    client: Endpoint | None = None
    server: Endpoint | None = None
    user: UserFieldSet | None = None
    network: NetworkFieldSet | None = None
    rule: RuleFieldSet | None = None
    tls: TlsFieldSet | None = None
    related: RelatedFieldSet | None = None
    error: ErrorFieldSet | None = None
    user_agent: UserAgentFieldSet | None = None
    url: UrlFieldSet | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: Any) -> datetime:
        return parse_timestamp(value, field_name="@timestamp")

    @field_validator("tags", mode="before")
    @classmethod
    def _as_string_list(cls, value: Any) -> list[str]:
        return _string_list(value)

    @field_validator("labels", mode="before")
    @classmethod
    def _as_string_map(cls, value: Any) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise TypeError("labels must be a mapping of string to string")
        return {str(key): str(item) for key, item in value.items()}

    @property
    def score(self) -> int:
        """Severity on the ECS 0-99 scale, defaulted for consumers that require one."""
        return clamp(self.event.severity)

    @property
    def severity_band(self) -> str:
        return band(self.score)

    def is_high(self, threshold: int) -> bool:
        return self.score >= clamp(threshold)

    def identity_key(self) -> str:
        """Stable dedup key: the source's own event id when it has one, else a content hash.

        CloudTrail ships ``eventID``, Graph ships ``id`` and syslog ships nothing, so a
        connector that knows its id passes it through ``event.id`` and dedup becomes exact.
        Without one the hash covers only identity-bearing fields that survive normalisation,
        which makes a duplicate of the same line collapse while a different line does not.
        """
        explicit = self.event.id
        if explicit:
            dataset = self.event.dataset or self.event.module or ""
            return f"{dataset}:{explicit}"
        probe = {
            "@timestamp": to_iso_z(self.timestamp),
            "action": self.event.action,
            "outcome": None if self.event.outcome is None else self.event.outcome.value,
            "source": None if self.source is None else self.source.ip,
            "destination": None if self.destination is None else self.destination.ip,
            "user": None if self.user is None else self.user.name,
            "rule": None if self.rule is None else self.rule.name,
            "dataset": self.event.dataset,
            "message": self.message,
        }
        encoded = json.dumps(probe, sort_keys=True, default=str).encode("utf-8")
        return f"h:{hashlib.sha256(encoded).hexdigest()[:32]}"


def build_event(**fields: Any) -> EcsEvent:
    """Construct an :class:`EcsEvent`, reporting schema problems as parse failures.

    Normalisers call this rather than the model directly: a mapping bug in a connector should
    look like a malformed source event (and land in the dead-letter file), not like a crash.
    """
    try:
        return EcsEvent.model_validate(fields)
    except ValidationError as exc:
        raise MalformedEventError(f"not a valid ECS document: {exc}", field="ecs") from exc


def _strip_empty(value: Any) -> Any:
    """Remove nothing-bearing fields so a document carries only what the source actually said."""
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalised = _strip_empty(item)
            if normalised is None or normalised in ({}, [], ""):
                continue
            cleaned[str(key)] = normalised
        return cleaned
    if isinstance(value, (list, tuple)):
        return [
            entry
            for entry in (_strip_empty(item) for item in value)
            if entry not in (None, {}, [], "")
        ]
    return value


def to_document(event: EcsEvent, redaction: RedactionSettings | None = None) -> dict[str, Any]:
    """Serialise for a destination: ECS aliases, ISO-Z timestamp, no empty fields.

    Redaction is applied here — the last point before the document leaves the process — so an
    operator can lower the sensitivity of what leaves without changing any connector.
    """
    document = event.model_dump(mode="json", by_alias=True, exclude_none=True)
    document["@timestamp"] = to_iso_z(ensure_utc(event.timestamp))
    document["event"]["severity"] = event.score
    cleaned: dict[str, Any] = _strip_empty(document)
    if redaction is None:
        return cleaned
    return redact_document(cleaned, redaction)
