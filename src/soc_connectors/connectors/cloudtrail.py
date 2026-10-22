"""CloudTrail: the log files AWS delivers, read without losing the ones that arrive late.

Two facts about CloudTrail delivery shape this connector.

**A log file is immutable and self-describing.** Its name carries the delivery minute
(``AccountID_CloudTrail_RegionName_YYYYMMDDTHHmmZ_UniqueString.json.gz``), so a cursor can be
``(delivery time, key)`` rather than a byte offset, and a file never changes underneath us.

**Delivery order is not name order.** A bucket collects files from every region — and for an
organization trail, every account — and the S3 key puts region *before* date
(``AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/``). Any single-valued cursor over
that key space drops a file whose delivery stamp is older than the cursor but which arrives
after it. So the cursor is a high-water mark *plus a re-read overlap*: each cycle re-reads the
last ``rescan_overlap_minutes`` of files and the pipeline's seen-id window — keyed on the
record's own ``eventID``, which CloudTrail repeats across duplicate deliveries — absorbs them.
A wider overlap costs GET requests, a narrower one costs events; the default is a trade, not a
law, and the README states it as a known limitation.

A file that cannot be read at all (truncated gzip, an object a lifecycle rule deleted between
listing and fetch, an object over ``max_object_bytes``) becomes one dead-lettered sentinel
carrying the reason, so the cycle moves past it instead of failing on the same file every
polling tick forever. Transient S3 failures deliberately do *not* take that path: they stop the
cycle with the cursor where it was, which is what makes the next tick a retry.
"""

from __future__ import annotations

import gzip
import json
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Protocol, cast

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from soc_connectors.connectors.base import BaseConnector, ConnectorContext
from soc_connectors.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigError,
    MalformedEventError,
    PermanentError,
    RateLimitedError,
    SocConnectorError,
    TransientError,
)
from soc_connectors.schema.ecs_models import EcsEvent
from soc_connectors.schema.mapping import from_flat
from soc_connectors.types import ParsedEvent, RawEvent
from soc_connectors.utils.network import optional_ip
from soc_connectors.utils.pagination import Page, paginate
from soc_connectors.utils.time import ensure_utc, parse_retry_after, parse_timestamp

CURSOR_SEPARATOR = "|"
CURSOR_STAMP_FORMAT = "%Y%m%dT%H%M%S"
#: The cursor stamp is fixed-width on purpose: ``strptime`` would happily read the *minute* stamp
#: copied out of a file name, ``20261022T0905``, as 09:00:05, and a hand-edited state file would
#: move the re-read window by an hour without saying so.
CURSOR_STAMP = re.compile(r"\d{8}T\d{6}")
#: ``..._20261022T0905Z_AAAAAAAAAAAAAAAA.json.gz`` is the documented name; the older files still
#: sitting in buckets join the stamp and the unique string without the underscore.
NAME_STAMP = re.compile(r"_(?P<stamp>\d{8}T\d{4})Z_?[A-Za-z0-9]*\.json(?:\.gz)?$", re.IGNORECASE)
_NAME_STAMP_FORMAT = "%Y%m%dT%H%M"
LOG_SUFFIXES = (".json.gz", ".json")
MODES = ("files", "s3")

#: Written by :meth:`CloudTrailConnector.fetch` for a file it could not read; ``parse`` turns it
#: back into a :class:`MalformedEventError` so the reason reaches the dead-letter file.
FILE_ERROR_FIELD = "__cloudtrail_file_error__"

#: The record schema this mapping was written against. A higher minor version only adds fields,
#: which ``raw`` keeps; a different major version means the names may have moved, and guessing
#: would be worse than dead-lettering.
EVENT_VERSION_MAJOR = 1
REVIEWED_EVENT_MINOR = 11

MANAGEMENT = "management"
INSIGHT = "insight"
NETWORK_ACTIVITY = "network-activity"
DIGEST = "digest"
AGGREGATED = "aggregated"
SKIPPED_FLAVORS = frozenset({DIGEST, AGGREGATED})

_GZIP_MAGIC = b"\x1f\x8b"


def classify(key: str) -> str:
    """Which kind of CloudTrail object this key is, from the words in its path or file name.

    Substring matching rather than a fixed folder list because the flavour appears in both the
    folder (``CloudTrail-Insight``) and the file name, and a local directory may carry neither.
    """
    collapsed = key.casefold().replace("-", "").replace("_", "")
    if "digest" in collapsed:
        return DIGEST
    if "insight" in collapsed:
        return INSIGHT
    if "aggregated" in collapsed:
        return AGGREGATED
    if "networkactivity" in collapsed:
        return NETWORK_ACTIVITY
    return MANAGEMENT


def is_log_file_name(name: str) -> bool:
    return name.casefold().endswith(LOG_SUFFIXES)


@dataclass(frozen=True, slots=True)
class LogFile:
    """One CloudTrail object or local file, and the minute CloudTrail says it was delivered."""

    key: str
    delivered_at: datetime
    flavor: str
    size: int | None = None

    @property
    def position(self) -> tuple[datetime, str]:
        return (self.delivered_at, self.key)

    def as_cursor(self) -> str:
        return f"{self.delivered_at.strftime(CURSOR_STAMP_FORMAT)}{CURSOR_SEPARATOR}{self.key}"


class S3Api(Protocol):
    """The calls this connector makes to S3, and nothing else — so a test can fake them."""

    def list_objects_v2(self, **params: Any) -> dict[str, Any]: ...

    def get_object(self, **params: Any) -> dict[str, Any]: ...

    def close(self) -> None: ...


#: Looked up by class name instead of importing one exception class per failure mode: botocore
#: raises these from inside its own event handlers, and a name table is cheaper to keep honest
#: than an import list that drifts with each release. Anything unlisted is treated as transient.
_BOTO_ERROR_BY_NAME: dict[str, type[SocConnectorError]] = {
    "NoRegionError": ConfigError,
    "ProfileNotFound": AuthenticationError,
    "NoCredentialsError": AuthenticationError,
    "PartialCredentialsError": AuthenticationError,
    "CredentialRetrievalError": AuthenticationError,
    "EndpointConnectionError": TransientError,
    "ConnectTimeoutError": TransientError,
    "ReadTimeoutError": TransientError,
    "HTTPClientError": TransientError,
    "ResponseStreamingError": TransientError,
    "ParamValidationError": PermanentError,
}

_THROTTLED_CODES = frozenset(
    {
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "TooManyRequests",
        "RequestThrottled",
        "RequestThrottledException",
        "ProvisionedRateInvalid",
    }
)
_DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException"})
_UNAUTHENTICATED_CODES = frozenset(
    {"InvalidAccessKeyId", "InvalidClientTokenId", "SignatureDoesNotMatch", "TokenRefreshRequired"}
)
_MISSING_CODES = frozenset({"NoSuchBucket", "NoSuchKey", "NoSuchVersion"})
_UNAVAILABLE_CODES = frozenset(
    {"InternalError", "InternalServerError", "ServiceUnavailable", "RequestTimeout", "503"}
)

#: S3 statuses that say what a code says. A response can carry one and not the other, so both
#: are consulted: 429/5xx can clear on their own, 401/403/404 never will.
HTTP_UNAUTHENTICATED = 401
HTTP_DENIED = 403
HTTP_MISSING = 404
HTTP_THROTTLED = 429
HTTP_SERVER_ERROR = 500

#: ``eventCategory`` -> the tag every document from that channel carries. A dataset per channel
#: would be tidier, but one dataset keeps a trail's events searchable as one stream.
_CATEGORY_TAGS = {
    "management": MANAGEMENT,
    "data": "data",
    "insight": INSIGHT,
    "networkactivity": NETWORK_ACTIVITY,
}

#: ``event.type`` families by ``eventName`` prefix, in the order they are tried: the first match
#: wins, so the more specific deletion list is checked before the general change list.
_CREATION_PREFIXES = ("create", "run", "import", "copy", "allocate", "register", "purchase")
_DELETION_PREFIXES = ("delete", "destroy", "terminate", "remove", "deregister", "release", "revoke")
_CHANGE_PREFIXES = (
    "modify",
    "update",
    "put",
    "set",
    "attach",
    "detach",
    "add",
    "tag",
    "untag",
    "enable",
    "disable",
    "apply",
    "assign",
    "associate",
    "disassociate",
    "replace",
    "reset",
    "start",
    "stop",
    "restart",
    "invoke",
    "assume",
    "change",
    "transition",
    "send",
    "sign",
)
_INFO_PREFIXES = ("get", "describe", "list", "read", "lookup", "head", "prefetch")


def _text(value: Any) -> str:
    """A source scalar as trimmed text; ``None`` and bools never become the string ``"None"``."""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _service_name(event_source: str) -> str | None:
    """``ec2.amazonaws.com`` -> ``ec2``: ECS wants the service; the domain is ``event.provider``."""
    if "." not in event_source:
        return None
    head = event_source.split(".", 1)[0].strip()
    return head or None


def _event_types(action: str, read_only: bool) -> list[str]:
    """ECS ``event.type`` from the API action name, falling back to ``readOnly``."""
    lowered = action.casefold()
    for prefix, kind in (
        *((p, "creation") for p in _CREATION_PREFIXES),
        *((p, "deletion") for p in _DELETION_PREFIXES),
        *((p, "change") for p in _CHANGE_PREFIXES),
    ):
        if lowered.startswith(prefix):
            return [kind]
    if any(lowered.startswith(prefix) for prefix in _INFO_PREFIXES):
        return ["info"]
    return ["info"] if read_only else ["change"]


def _data_categories(source: str) -> list[str]:
    """A data event is a database or a file access only when the service says so.

    ``eventCategory: "Data"`` covers S3 object reads, DynamoDB table streams and a dozen other
    services with no common ECS category, so anything not recognisably one of the two is left
    uncategorised rather than guessed at.
    """
    if "dynamodb" in source:
        return ["database"]
    if source.endswith("s3.amazonaws.com"):
        return ["file"]
    return []


def _event_categories(record: Mapping[str, Any], source: str, is_insight: bool) -> list[str]:
    """ECS ``event.category``: from CloudTrail's own ``eventCategory``, narrowed by the service.

    An insight measures an API *rate*, which is none of the ECS categories, so an insight event
    is left uncategorised rather than filed under something it does not mean.
    """
    declared = _text(record.get("eventCategory")).casefold()
    if is_insight or declared == "insight":
        return []
    if declared == "data":
        return _data_categories(source)
    if declared == "networkactivity":
        return ["network"]
    if _text(record.get("eventType")).casefold() == "awsconsolesignin":
        return ["authentication"]
    return ["configuration"]


def _user_fields(identity: Mapping[str, Any]) -> dict[str, Any]:
    """``userIdentity`` -> ``user.*``. ``accessKeyId`` is deliberately not mapped: AWS documents
    it as a field that must not be used to identify a session, and it stays in ``raw``.

    ``sessionIssuer`` sits inside ``sessionContext``, and for an assumed-role or federated session
    it is the only name worth publishing — ``principalId`` is the role session, which changes
    every time somebody signs in.
    """
    session = identity.get("sessionContext")
    session = session if isinstance(session, Mapping) else {}
    issuer = session.get("sessionIssuer")
    issuer = issuer if isinstance(issuer, Mapping) else {}
    name = _text(identity.get("userName")) or _text(issuer.get("userName"))
    fields: dict[str, Any] = {
        "user.id": _text(identity.get("principalId")),
        "user.name": name,
    }
    if name:
        fields["related.user"] = [name]
    return fields


def _source_endpoint(source_address: Any) -> dict[str, Any]:
    """``sourceIPAddress``, which CloudTrail also fills with service principal names.

    ``s3.amazonaws.com`` in an address field is not a malformed address, it is a service: ECS
    has ``source.domain`` for exactly that, so the value is kept instead of dropped.
    """
    ip = optional_ip(source_address)
    if ip is not None:
        return {"source.ip": ip, "related.ip": [ip]}
    host = _text(source_address)
    if host and "." in host and " " not in host:
        return {"source.domain": host}
    return {}


def _labels(record: Mapping[str, Any], identity: Mapping[str, Any]) -> dict[str, str]:
    """Values ECS has no field for, kept as labels because ``raw`` is for forensics, not queries.

    There is no ECS field for a principal type, an MFA assertion or a VPC endpoint id, and
    dropping them would remove the two things an analyst filters CloudTrail on.
    """
    labels: dict[str, str] = {}
    principal_type = _text(identity.get("type"))
    if principal_type:
        labels["cloudtrail_principal_type"] = principal_type
    session = identity.get("sessionContext")
    session = session if isinstance(session, Mapping) else {}
    attributes = session.get("attributes")
    attributes = attributes if isinstance(attributes, Mapping) else {}
    additional = record.get("additionalEventData")
    additional = additional if isinstance(additional, Mapping) else {}
    mfa = _text(additional.get("MFAUsed")) or _text(attributes.get("mfaAuthenticated"))
    if mfa:
        labels["cloudtrail_mfa"] = mfa
    if _text(record.get("sessionCredentialFromConsole")).casefold() == "true":
        labels["cloudtrail_session_from_console"] = "true"
    endpoint = _text(record.get("vpcEndpointId"))
    if endpoint:
        labels["cloudtrail_vpc_endpoint_id"] = endpoint
    insight = record.get("insightDetails")
    if isinstance(insight, Mapping) and _text(insight.get("state")):
        labels["cloudtrail_insight_state"] = _text(insight.get("state"))
    return labels


def map_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """One CloudTrail record to ``ECS path -> value``, using only ECS's own names.

    Absent source values become ``""`` here and are dropped by :func:`from_flat`, so a field the
    record does not carry is missing from the document rather than empty in it. Nothing is
    inferred from context: no severity is invented, no category is guessed for a service this
    table does not know.
    """
    timestamp = record.get("eventTime")
    if timestamp in (None, ""):
        raise MalformedEventError(
            "CloudTrail record has no eventTime; refusing to timestamp it with the read time",
            field="eventTime",
        )
    error_code = _text(record.get("errorCode"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    insight = record.get("insightDetails")
    insight = insight if isinstance(insight, Mapping) else {}
    declared_type = _text(record.get("eventType")).casefold()
    is_insight = declared_type == "awscloudtrailinsight" or (
        _text(record.get("eventCategory")).casefold() == "insight"
    )
    source = _text(insight.get("eventSource")) or _text(record.get("eventSource"))
    action = _text(insight.get("eventName")) or _text(record.get("eventName"))
    read_only = str(record.get("readOnly", "")).casefold() == "true"
    tls = record.get("tlsDetails")
    tls = tls if isinstance(tls, Mapping) else {}
    declared_category = _text(record.get("eventCategory")).casefold()

    fields: dict[str, Any] = {
        "@timestamp": timestamp,
        "event.kind": "alert" if is_insight else "event",
        "event.category": _event_categories(record, source, is_insight),
        "event.type": _event_types(action, read_only),
        "event.action": action,
        "event.provider": source,
        "event.id": _text(record.get("eventID")),
        "event.code": _text(record.get("requestID")),
        "event.hash": _text(record.get("sharedEventID")),
        "event.outcome": "failure" if error_code else "success",
        "cloud.region": _text(record.get("awsRegion")),
        "cloud.service.name": _service_name(source),
        "cloud.account.id": _text(record.get("recipientAccountId"))
        or _text(identity.get("accountId")),
        "user_agent.original": _text(record.get("userAgent")),
        "error.code": error_code,
        "error.message": _text(record.get("errorMessage")),
        "tls.version": _text(tls.get("tlsVersion")),
        "tls.cipher": _text(tls.get("cipherSuite")),
        "url.domain": _text(tls.get("clientProvidedHostHeader")),
        "rule.name": _text(insight.get("insightType")),
        "tags": ["cloudtrail", _CATEGORY_TAGS.get(declared_category, MANAGEMENT)],
        "labels": _labels(record, identity),
        "raw": dict(record),
    }
    if declared_type == "awsconsolesignin":
        fields["event.type"] = ["start"]
    fields.update(_user_fields(identity))
    fields.update(_source_endpoint(record.get("sourceIPAddress")))
    return {key: value for key, value in fields.items() if value not in (None, "", [], {})}


def _records_of(document: Any) -> list[dict[str, Any]]:
    """The records inside one log file: CloudTrail delivers ``{"Records": [...]}``."""
    if isinstance(document, list):
        items = document
    elif isinstance(document, Mapping) and isinstance(document.get("Records"), list):
        items = document["Records"]
    else:
        raise MalformedEventError(
            "log file holds no 'Records' array; it is not a CloudTrail log file",
            field="Records",
        )
    records: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise MalformedEventError(
                f"record is a {type(item).__name__}, expected a JSON object", field="Records"
            )
        records.append(item)
    return records


class CloudTrailConnector(BaseConnector):
    type_name: ClassVar[str] = "cloudtrail"
    summary: ClassVar[str] = (
        "Reads CloudTrail log files from an S3 bucket or a local directory and maps them to ECS."
    )
    supports_backfill: ClassVar[bool] = True

    def __init__(self, context: ConnectorContext) -> None:
        super().__init__(context)
        self.mode = str(self.option("mode", "files")).casefold()
        if self.mode not in MODES:
            raise ConfigError(
                f"connector {self.id!r}: mode must be one of {', '.join(MODES)}, got {self.mode!r}"
            )
        self.dataset = str(self.option("dataset", "aws.cloudtrail"))
        self.lookback_days = self._number("lookback_days", 1.0)
        self.rescan_overlap_minutes = self._number("rescan_overlap_minutes", 15.0)
        self.since = self._since()
        self.max_files = self._integer("max_files_per_cycle", 20, minimum=1)
        self.max_records = self._integer("max_records_per_cycle", 2000, minimum=1)
        self.max_object_bytes = self._integer(
            "max_object_bytes", 33_554_432, minimum=128, maximum=268_435_456
        )
        self.page_size = self._integer("page_size", 1000, minimum=1, maximum=1000)
        self.max_listing_pages = self._integer("max_listing_pages", 20, minimum=1)
        self.include_insights = self._flag("include_insights", False)
        self.include_network_activity = self._flag("include_network_activity", False)
        self._warned_versions: set[str] = set()
        self._client: S3Api | None = None

        self.path: Path | None = None
        self.bucket = ""
        self.prefix = ""
        if self.mode == "files":
            path = Path(str(self.require_option("path"))).expanduser()
            if not path.exists():
                raise ConfigError(f"connector {self.id!r}: CloudTrail path {path} does not exist")
            self.path = path
        else:
            self.bucket = str(self.require_option("bucket")).strip()
            self.prefix = _normalize_prefix(self.option("prefix", "AWSLogs/"))
            self.region = str(self.option("region") or "") or None
            self.endpoint_url = str(self.option("endpoint_url") or "") or None

    # -- option parsing --------------------------------------------------------

    def _integer(self, name: str, default: int, *, minimum: int, maximum: int = 10_000_000) -> int:
        raw = self.option(name, default)
        try:
            value = int(str(raw).strip()) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"connector {self.id!r}: option '{name}' is not a number") from exc
        if not minimum <= value <= maximum:
            raise ConfigError(
                f"connector {self.id!r}: option '{name}' must be between {minimum} and {maximum}"
            )
        return value

    def _number(self, name: str, default: float) -> float:
        raw = self.option(name, default)
        try:
            value = float(str(raw).strip()) if isinstance(raw, str) else float(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"connector {self.id!r}: option '{name}' is not a number") from exc
        if value < 0:
            raise ConfigError(f"connector {self.id!r}: option '{name}' cannot be negative")
        return value

    def _flag(self, name: str, default: bool) -> bool:
        raw = self.option(name, default)
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().casefold()
        if text in {"true", "1", "yes", "on"}:
            return True
        if text in {"false", "0", "no", "off", ""}:
            return False
        raise ConfigError(f"connector {self.id!r}: option '{name}' is not a true/false value")

    def _since(self) -> datetime | None:
        """The ``since`` option, as the floor for a first run that predates the cursor.

        A timestamp the operator mistyped is a configuration mistake, so it is reported as one at
        startup rather than as a per-record parse failure the pipeline would dead-letter forever.
        """
        value = self.option("since")
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        try:
            return parse_timestamp(value, field_name="since")
        except MalformedEventError as exc:
            raise ConfigError(
                f"connector {self.id!r}: option 'since' is not a timestamp ({exc})"
            ) from exc

    # -- stage 1: fetch --------------------------------------------------------

    def fetch(self) -> Iterator[RawEvent]:
        produced = 0
        opened = 0
        for log_file in self._scan():
            # Both caps are checked before a file is opened, never while reading it: the cursor
            # claims "this file was read", and a half-read file would make that a lie.
            if opened >= self.max_files or produced >= self.max_records:
                self.log.info(
                    "cycle cap reached, resuming next tick",
                    extra={"connector_id": self.id, "files": opened, "records": produced},
                )
                return
            opened += 1
            try:
                records = self._read(log_file)
            except TransientError:
                # S3 blipped. Stop the cycle with the cursor where it is: the next tick reads
                # the same file, and a dead-letter entry would only hide a temporary failure.
                raise
            except (MalformedEventError, PermanentError, OSError, ValueError) as exc:
                produced += 1
                yield self._unreadable(log_file, str(exc))
                continue
            produced += len(records)
            for record in records:
                yield self.make_raw(
                    record,
                    cursor=log_file.as_cursor(),
                    metadata={"source_key": log_file.key},
                )

    def _unreadable(self, log_file: LogFile, reason: str) -> RawEvent:
        """One sentinel record for a file no record can come out of.

        It carries the reason and the key, not the bytes: the file stays where it is, and the
        dead-letter entry says which operator action is needed.
        """
        self.log.warning(
            "CloudTrail log file could not be read; dead-lettering the file",
            extra={"connector_id": self.id, "key": log_file.key, "error": reason},
        )
        payload = {FILE_ERROR_FIELD: reason, "key": log_file.key}
        return self.make_raw(payload, cursor=log_file.as_cursor(), metadata={"stage": "file"})

    # -- the scan: which files are due -----------------------------------------

    def _scan(self) -> Iterator[LogFile]:
        cursor = self._cursor_position()
        floor = self._floor(cursor)
        for log_file in sorted(self._candidates(), key=lambda item: item.position):
            if log_file.delivered_at < floor:
                continue
            if cursor is not None and log_file.key == cursor[1]:
                continue
            if not self._wanted(log_file):
                self.log.debug(
                    "skipping a CloudTrail file this source does not read",
                    extra={"connector_id": self.id, "key": log_file.key, "flavor": log_file.flavor},
                )
                continue
            yield log_file

    def _floor(self, cursor: tuple[datetime, str] | None) -> datetime:
        """Oldest file this cycle may read.

        With a cursor this is the overlap window, not the cursor itself: a file delivered late
        with an older stamp must still be read, and the seen-id window is what stops its records
        being forwarded twice. Without one, a first run reads only ``lookback_days`` (or
        ``since``) rather than every year of history in the bucket.
        """
        if cursor is not None:
            return cursor[0] - timedelta(minutes=self.rescan_overlap_minutes)
        if self.since is not None:
            return self.since
        return ensure_utc(self.now) - timedelta(days=self.lookback_days)

    def _wanted(self, log_file: LogFile) -> bool:
        if log_file.flavor in SKIPPED_FLAVORS:
            return False
        if log_file.flavor == INSIGHT:
            return self.include_insights
        if log_file.flavor == NETWORK_ACTIVITY:
            return self.include_network_activity
        return True

    def _cursor_position(self) -> tuple[datetime, str] | None:
        raw = self.checkpoint.state.cursor
        if not raw:
            return None
        stamp, separator, key = str(raw).rpartition(CURSOR_SEPARATOR)
        if not separator or not key or not CURSOR_STAMP.fullmatch(stamp):
            raise ConfigError(f"connector {self.id!r} has an unparsable cursor {raw!r}")
        try:
            delivered = datetime.strptime(stamp, CURSOR_STAMP_FORMAT).replace(tzinfo=UTC)
        except ValueError as exc:
            raise ConfigError(f"connector {self.id!r} has an unparsable cursor {raw!r}") from exc
        return delivered, key

    def _candidates(self) -> list[LogFile]:
        if self.mode == "files":
            return self._local_candidates()
        return self._s3_candidates()

    def _local_candidates(self) -> list[LogFile]:
        root = self.path
        if root is None:  # defensive: mode 'files' always sets it in __init__
            raise ConfigError(f"connector {self.id!r}: files mode has no path option")
        paths = (
            [root]
            if root.is_file()
            else [
                item for item in root.rglob("*") if item.is_file() and is_log_file_name(item.name)
            ]
        )
        found: list[LogFile] = []
        for path in paths:
            stat = path.stat()
            delivered = _delivered_from_name(path.name) or datetime.fromtimestamp(
                stat.st_mtime, UTC
            )
            found.append(LogFile(str(path), delivered, classify(str(path)), stat.st_size))
        return found

    def _s3_candidates(self) -> list[LogFile]:
        client = self._get_client()
        pages = list(
            paginate(
                lambda token: self._list_page(client, token),
                max_pages=self.max_listing_pages,
            )
        )
        if pages and pages[-1].next_cursor is not None:
            # A truncated listing is not a smaller window, it is a lie about one: the files we
            # did not see may sort before the ones we did, and advancing past them would lose
            # them. Fail the cycle and let the operator narrow the prefix instead.
            raise TransientError(
                f"connector {self.id!r}: listing s3://{self.bucket}/{self.prefix} was cut at "
                f"{self.max_listing_pages} pages; raise max_listing_pages or narrow prefix"
            )
        found: list[LogFile] = []
        for page in pages:
            for item in page.items:
                key = str(item.get("Key") or "")
                if not key or not is_log_file_name(key.rsplit("/", 1)[-1]):
                    continue
                delivered = _delivered_from_name(key)
                if delivered is None:
                    modified = item.get("LastModified")
                    if modified is None:
                        continue
                    delivered = ensure_utc(parse_timestamp(modified, field_name="LastModified"))
                found.append(
                    LogFile(key, delivered, classify(key), _optional_size(item.get("Size")))
                )
        return found

    def _list_page(self, client: S3Api, token: str | None) -> Page:
        if not self.acquire():
            raise TransientError(
                f"connector {self.id!r}: rate budget exhausted while listing "
                f"s3://{self.bucket}/{self.prefix}"
            )
        params: dict[str, Any] = {
            "Bucket": self.bucket,
            "Prefix": self.prefix,
            "MaxKeys": self.page_size,
        }
        if token:
            params["ContinuationToken"] = token
        response = self._call(client.list_objects_v2, **params)
        contents = response.get("Contents") or []
        items = [item for item in contents if isinstance(item, Mapping)]
        return Page(items=items, next_cursor=response.get("NextContinuationToken"))

    # -- stage 1b: reading one file --------------------------------------------

    def _read(self, log_file: LogFile) -> list[dict[str, Any]]:
        if log_file.size is not None and log_file.size > self.max_object_bytes:
            raise PermanentError(
                f"log file {log_file.key} is {log_file.size} bytes, above max_object_bytes "
                f"({self.max_object_bytes})"
            )
        body = self._read_body(log_file)
        if body[:2] == _GZIP_MAGIC:
            # Magic bytes, not the extension: a CloudTrail file renamed to ``.json`` is still
            # gzip, and refusing it would lose the events rather than the naming convention.
            body = gzip.decompress(body)
        document = json.loads(body.decode("utf-8"))
        return _records_of(document)

    def _read_body(self, log_file: LogFile) -> bytes:
        if self.mode == "files":
            return Path(log_file.key).read_bytes()
        client = self._get_client()
        response = self._call(client.get_object, Bucket=self.bucket, Key=log_file.key)
        stream = response.get("Body")
        if stream is None:
            raise PermanentError(f"get_object for {log_file.key} returned no Body")
        data: Any = stream.read()
        return data if isinstance(data, bytes) else str(data).encode("utf-8")

    # -- stage 2: parse --------------------------------------------------------

    def parse(self, raw: RawEvent) -> ParsedEvent:
        fields = raw.as_mapping()
        reason = fields.get(FILE_ERROR_FIELD)
        if isinstance(reason, str):
            raise MalformedEventError(
                f"CloudTrail log file {fields.get('key', raw.cursor)} could not be read: {reason}",
                raw=raw,
                field="file",
            )
        return ParsedEvent(
            raw=raw,
            fields=fields,
            source_event_type=_text(fields.get("eventType")) or "AwsApiCall",
        )

    # -- stage 3: normalize ----------------------------------------------------

    def normalize(self, parsed: ParsedEvent) -> EcsEvent:
        record: dict[str, Any] = dict(parsed.fields)
        self._check_event_version(record, raw=parsed.raw)
        fields = map_record(record)
        return from_flat(
            fields,
            defaults={
                "cloud.provider": "aws",
                "event.module": "aws",
                "event.dataset": self.dataset,
            },
        )

    def _check_event_version(self, record: Mapping[str, Any], *, raw: RawEvent) -> None:
        """Refuse a major version this mapping has not been reviewed against; warn on a new minor.

        A minor bump adds fields, and ``raw`` already carries those; a major bump can rename
        them, at which point every mapped path is a guess and the events should stop, not drift.
        """
        value = record.get("eventVersion")
        if value is None:
            return
        text = str(value).strip()
        major, dot, minor = text.partition(".")
        if not dot or not major.isdigit():
            raise MalformedEventError(
                f"unrecognised CloudTrail eventVersion {text!r}", raw=raw, field="eventVersion"
            )
        if int(major) != EVENT_VERSION_MAJOR:
            raise MalformedEventError(
                f"CloudTrail eventVersion {text!r} is a major version this mapping has not been "
                "reviewed against; field names may have moved",
                raw=raw,
                field="eventVersion",
            )
        if (
            minor.isdigit()
            and int(minor) > REVIEWED_EVENT_MINOR
            and text not in self._warned_versions
        ):
            self._warned_versions.add(text)
            self.log.warning(
                "CloudTrail record schema is newer than this mapping was reviewed against; "
                "unknown fields are kept in raw",
                extra={"connector_id": self.id, "eventVersion": text},
            )

    # -- the S3 client ---------------------------------------------------------

    def _get_client(self) -> S3Api:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> S3Api:
        # Credentials come from the default chain (environment, shared config, instance role).
        # There is deliberately no access-key option: a framework that can take a secret from a
        # config file will get one, and this one is only ever meant to read the environment.
        kwargs: dict[str, Any] = {}
        if self.region:
            kwargs["region_name"] = self.region
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        try:
            client = boto3.client("s3", **kwargs)
        except BotoCoreError as exc:
            raise _classify_boto_error(exc, connector_id=self.id) from exc
        return cast("S3Api", client)

    def _call(self, func: Callable[..., dict[str, Any]], **params: Any) -> dict[str, Any]:
        try:
            return func(**params)
        except ClientError as exc:
            raise _classify_client_error(exc, connector_id=self.id, prefix=self.prefix) from exc
        except BotoCoreError as exc:
            raise _classify_boto_error(exc, connector_id=self.id) from exc

    def close(self) -> None:
        """Drop the S3 client. Safe twice: a closed client is simply rebuilt on the next read."""
        client = self._client
        self._client = None
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover - closing must never fail the shutdown path
                self.log.debug("S3 client close failed", extra={"connector_id": self.id})


# -- helpers ----------------------------------------------------------------


def _normalize_prefix(value: Any) -> str:
    prefix = str(value or "").strip().lstrip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix


def _optional_size(value: Any) -> int | None:
    try:
        size = int(str(value).strip()) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return size if size >= 0 else None


def _delivered_from_name(key: str) -> datetime | None:
    match = NAME_STAMP.search(key.rsplit("/", 1)[-1])
    if match is None:
        return None
    try:
        return datetime.strptime(match["stamp"], _NAME_STAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _error_code(exc: ClientError) -> str:
    return _text(exc.response.get("Error", {}).get("Code"))


def _http_status(exc: ClientError) -> int:
    """The HTTP status of an S3 failure, or 0 when the response carries no metadata at all."""
    metadata = exc.response.get("ResponseMetadata", {})
    status = metadata.get("HTTPStatusCode")
    return int(status) if isinstance(status, (int, str)) else 0


def _classify_client_error(
    exc: ClientError, *, connector_id: str, prefix: str
) -> SocConnectorError:
    """Turn a botocore ``ClientError`` into the framework's retry/permanent distinction.

    S3 reports throttling as ``503 Slow Down`` and permissions as ``403 AccessDenied``, and both
    are ordinary for a connector polling a busy bucket — so the distinction is made from the
    code and status, not from the message text.
    """
    code = _error_code(exc)
    status = _http_status(exc)
    where = f"connector {connector_id!r}: s3 call for prefix {prefix!r} failed ({code or status})"
    if code in _UNAUTHENTICATED_CODES or status == HTTP_UNAUTHENTICATED:
        return AuthenticationError(f"{where}: the credentials offered were rejected")
    if code in _DENIED_CODES or status == HTTP_DENIED:
        return AuthorizationError(
            f"{where}: the bucket policy or IAM role does not allow this read"
        )
    if code in _MISSING_CODES or status == HTTP_MISSING:
        return PermanentError(f"{where}: no such object or bucket")
    if code in _THROTTLED_CODES or status == HTTP_THROTTLED:
        headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        retry_after = headers.get("retry-after") or headers.get("x-amz-retry-after")
        return RateLimitedError(
            f"{where}: S3 is throttling this request",
            retry_after_seconds=parse_retry_after(
                str(retry_after) if retry_after is not None else None
            ),
        )
    if code in _UNAVAILABLE_CODES or status >= HTTP_SERVER_ERROR:
        return TransientError(f"{where}: S3 returned a server-side failure")
    return PermanentError(f"{where}: S3 rejected the request")


#: botocore's own messages name a missing key or an unset region; an operator needs to know
#: which knob to turn, so the failure classes worth fixing get a hint instead.
_FIX_HINTS = {
    "credential": "export AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or attach an instance role",
    "NoRegionError": "set the 'region' option or the AWS_REGION environment variable",
}


def _classify_boto_error(exc: BotoCoreError, *, connector_id: str) -> SocConnectorError:
    """Connection and credential failures, which never carry an S3 error code."""
    name = type(exc).__name__
    target = _BOTO_ERROR_BY_NAME.get(name, TransientError)
    hint = _FIX_HINTS.get(name)
    if hint is None and issubclass(target, AuthenticationError):
        hint = _FIX_HINTS["credential"]
    detail = hint if hint is not None else str(exc)
    return target(f"connector {connector_id!r}: {name}: {detail}")
