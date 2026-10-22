"""CloudTrail: the delivery facts, the cursor, and one row of the mapping table per record shape.

Three behaviours carry the risk here, and each gets its own group of tests. The cursor is a
(delivery minute, key) high-water mark *plus* a re-read overlap, because S3 key order is not
delivery order. A file no record can come out of becomes one dead-lettered sentinel instead of
failing the same cycle forever. And every mapped path must be a field CloudTrail actually
documents and ECS actually has.

Nothing here is captured from a real tenant: the account ids are the ones AWS uses in its own
examples, the principals are invented, and every address is from RFC 5737.
"""

from __future__ import annotations

import gzip
import json
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    ParamValidationError,
)
from moto import mock_aws

from soc_connectors.connectors import cloudtrail as cloudtrail_module
from soc_connectors.connectors.base import ConnectorContext
from soc_connectors.connectors.cloudtrail import (
    FILE_ERROR_FIELD,
    REVIEWED_EVENT_MINOR,
    CloudTrailConnector,
    LogFile,
    classify,
    is_log_file_name,
    map_record,
)
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
from soc_connectors.pipeline.factory import connector_summaries, register_builtins
from soc_connectors.schema.ecs_models import EcsEvent, to_document
from soc_connectors.types import RawEvent

pytestmark = pytest.mark.unit

ACCOUNT = "123456789012"
BUCKET = "trail-bucket"
THIS_MORNING = "20261022T0855"
MakeContext = Callable[..., ConnectorContext]

#: The folder CloudTrail uses per channel; ``classify`` reads these words, not a fixed layout.
FLAVOR_FOLDERS = {
    "management": "CloudTrail",
    "insight": "CloudTrail-Insight",
    "network-activity": "CloudTrail-NetworkActivity",
    "digest": "CloudTrail-Digest",
    "aggregated": "CloudTrail-AggregatedRecords",
}


def trail_record(index: int = 0, /, **overrides: Any) -> dict[str, Any]:
    """A management write event in the shape AWS documents, with a test's overrides applied.

    Passing ``None`` removes a field rather than emptying it: "the source did not send this" and
    "the source sent nothing" must not be the same fixture.
    """
    record: dict[str, Any] = {
        "eventVersion": 1.11,
        "eventID": f"evt-{index}",
        "requestID": f"req-{index}",
        "eventType": "AwsApiCall",
        "eventCategory": "Management",
        "eventTime": "2026-10-22T08:55:11Z",
        "eventName": "RunInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "readOnly": False,
        "recipientAccountId": ACCOUNT,
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE7T526QEXAMPLE",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/svc-demo",
            "accountId": ACCOUNT,
            "userName": "svc-demo",
        },
    }
    record.update(overrides)
    return {key: value for key, value in record.items() if value is not None}


def insight_record(index: int = 0, /, **overrides: Any) -> dict[str, Any]:
    """An insight: a rate anomaly, not an API call, named only inside ``insightDetails``."""
    record: dict[str, Any] = {
        "eventVersion": 1.11,
        "eventID": f"ins-{index}",
        "sharedEventID": f"shared-{index}",
        "eventType": "AwsCloudTrailInsight",
        "eventCategory": "Insight",
        "eventTime": "2026-10-22T08:50:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": ACCOUNT,
        "insightDetails": {
            "state": "Start",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "insightType": "ApiCallRateInsight",
            "insightContext": {
                "statistics": {"baseline": {"average": 12.0}, "insight": {"average": 340.0}}
            },
            "insightDuration": 5,
        },
    }
    record.update(overrides)
    return {key: value for key, value in record.items() if value is not None}


def log_name(stamp: str, *, region: str = "us-east-1", unique: str = "Mu0KsOhtH1ar15ZZ") -> str:
    """The documented name: account, region, delivery minute, a 16-character string, .json.gz."""
    return f"{ACCOUNT}_CloudTrail_{region}_{stamp}Z_{unique}.json.gz"


def trail_bytes(records: Sequence[Mapping[str, Any]], *, gzipped: bool = True) -> bytes:
    payload = json.dumps({"Records": [dict(item) for item in records]}, ensure_ascii=False)
    body = payload.encode("utf-8")
    return gzip.compress(body) if gzipped else body


class TrailTree:
    """A directory shaped like a bucket: ``AWSLogs/<account>/<channel>/<region>/<y>/<m>/<d>``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def folder(self, flavor: str, region: str, stamp: str) -> Path:
        delivered = datetime.strptime(stamp, "%Y%m%dT%H%M").replace(tzinfo=UTC)
        path = (
            self.root
            / "AWSLogs"
            / ACCOUNT
            / FLAVOR_FOLDERS[flavor]
            / region
            / f"{delivered:%Y}"
            / f"{delivered:%m}"
            / f"{delivered:%d}"
        )
        path.mkdir(parents=True, exist_ok=True)
        return path

    def add(
        self,
        *records: Mapping[str, Any],
        stamp: str = THIS_MORNING,
        region: str = "us-east-1",
        flavor: str = "management",
        gzipped: bool = True,
        name: str | None = None,
    ) -> Path:
        path = self.folder(flavor, region, stamp) / (name or log_name(stamp, region=region))
        path.write_bytes(trail_bytes(records, gzipped=gzipped))
        return path

    def add_raw(self, data: bytes, **kwargs: Any) -> Path:
        """Overwrite a written log file byte for byte: truncated gzip, stray text, wrong shape."""
        path = self.add(**kwargs)
        path.write_bytes(data)
        return path

    def set_mtime(self, path: Path, stamp: str) -> Path:
        delivered = datetime.strptime(stamp, "%Y%m%dT%H%M").replace(tzinfo=UTC)
        os.utime(path, (delivered.timestamp(), delivered.timestamp()))
        return path


def event_ids(raws: Iterable[RawEvent]) -> list[str]:
    return [str(raw.as_mapping().get("eventID")) for raw in raws]


def file_errors(raws: Iterable[RawEvent]) -> list[tuple[str, str]]:
    """``(key, reason)`` for every unreadable-file sentinel a fetch produced."""
    found = []
    for raw in raws:
        fields = raw.as_mapping()
        reason = fields.get(FILE_ERROR_FIELD)
        if isinstance(reason, str):
            found.append((str(fields.get("key")), reason))
    return found


class BytesBody:
    """What boto3 hands back as ``Body``: an object with a ``read()``."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeS3:
    """The three calls this connector makes to S3, with scripted pages, objects and failures.

    Faking the client rather than the transport keeps the error-classification tests honest: they
    raise the same ``ClientError`` botocore raises, so the path from an HTTP status to "retryable"
    or "dead-letter" is exercised end to end.
    """

    def __init__(
        self,
        *,
        pages: Sequence[Mapping[str, Any]] = (),
        objects: Mapping[str, Any] | None = None,
        list_error: BaseException | None = None,
        get_error: BaseException | None = None,
    ) -> None:
        self.pages = [dict(page) for page in pages]
        self.objects = dict(objects or {})
        self.list_error = list_error
        self.get_error = get_error
        self.list_params: list[dict[str, Any]] = []
        self.get_keys: list[str] = []
        self.closed = 0
        self._page = 0

    def list_objects_v2(self, **params: Any) -> dict[str, Any]:
        self.list_params.append(params)
        if self.list_error is not None:
            raise self.list_error
        if self._page >= len(self.pages):
            return {"Contents": []}
        page = self.pages[self._page]
        self._page += 1
        return page

    def get_object(self, **params: Any) -> dict[str, Any]:
        key = str(params.get("Key"))
        self.get_keys.append(key)
        if self.get_error is not None:
            raise self.get_error
        body = self.objects.get(key)
        if isinstance(body, Mapping):
            return dict(body)
        if body is None:
            raise client_error("NoSuchKey", 404)
        return {"Body": BytesBody(bytes(body))}

    def close(self) -> None:
        self.closed += 1


def s3_key(name: str, *, prefix: str = "AWSLogs/", region: str = "us-east-1") -> str:
    return f"{prefix}{ACCOUNT}/CloudTrail/{region}/{name}"


def s3_item(key: str, *, size: int | None = None, modified: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"Key": key}
    if size is not None:
        item["Size"] = size
    if modified is not None:
        item["LastModified"] = modified
    return item


def client_error(
    code: str, status: int, *, message: str = "no detail", retry_after: str | None = None
) -> ClientError:
    headers: dict[str, str] = {}
    if retry_after is not None:
        headers["x-amz-retry-after"] = retry_after
    # ``Any`` on purpose: botocore's stub demands HostId/RequestId/RetryAttempts, and a real S3
    # error response often carries none of them. The connector must not rely on them being there.
    response: Any = {
        "Error": {"Code": code, "Message": message},
        "ResponseMetadata": {"HTTPStatusCode": status, "HTTPHeaders": headers},
    }
    return ClientError(response, "GetObject")


class EmptyLimiter:
    """A limiter that always says no: the source must stop rather than spin against a quota."""

    def __init__(self) -> None:
        self.attempts = 0

    def try_acquire(self, tokens: int = 1) -> bool:
        self.attempts += 1
        return False

    def wait_time(self, tokens: int = 1) -> float:
        return 0.0

    def acquire(self, tokens: int = 1, *, timeout: float | None = None) -> bool:
        self.attempts += 1
        return False


def normalize_one(connector: CloudTrailConnector, record: Mapping[str, Any]) -> EcsEvent:
    """Run one record through the last two stages, the way the runner would."""
    raw = RawEvent(connector_id=connector.id, payload=dict(record), received_at=connector.now)
    return connector.normalize(connector.parse(raw))


@pytest.fixture
def trail_dir(tmp_path: Path) -> TrailTree:
    return TrailTree(tmp_path / "cloudtrail")


@pytest.fixture
def files_connector(context_factory: MakeContext) -> Callable[..., CloudTrailConnector]:
    """A files-mode connector over the given tree, with any extra options."""

    def factory(tree: TrailTree, **options: Any) -> CloudTrailConnector:
        return CloudTrailConnector(
            context_factory("ct", options={"path": str(tree.root), **options})
        )

    return factory


@pytest.fixture
def s3_connector(context_factory: MakeContext) -> Callable[..., CloudTrailConnector]:
    """An s3-mode connector wired to a fake client instead of boto3.

    ``_client`` is the connector's own lazy seam: assigning it here keeps these tests off the
    network without adding a test-only constructor argument to shipped code.
    """

    def factory(fake: FakeS3, **options: Any) -> CloudTrailConnector:
        connector = CloudTrailConnector(
            context_factory("ct", options={"mode": "s3", "bucket": BUCKET, **options})
        )
        connector._client = fake
        return connector

    return factory


# -- construction and option validation --------------------------------------


def test_files_mode_refuses_a_path_that_does_not_exist(
    context_factory: MakeContext, tmp_path: Path
) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        CloudTrailConnector(context_factory("ct", options={"path": str(tmp_path / "nope")}))


@pytest.mark.parametrize("options", [{}, {"mode": "s3"}])
def test_mode_selects_which_options_are_required(
    context_factory: MakeContext, options: dict[str, Any]
) -> None:
    with pytest.raises(ConfigError, match="requires option"):
        CloudTrailConnector(context_factory("ct", options=options))


def test_an_unknown_mode_lists_the_two_that_exist(
    context_factory: MakeContext, trail_dir: TrailTree
) -> None:
    with pytest.raises(ConfigError, match=r"mode must be one of files, s3, got 'tablestore'"):
        CloudTrailConnector(
            context_factory("ct", options={"path": str(trail_dir.root), "mode": "tablestore"})
        )


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"max_files_per_cycle": "many"}, "is not a number"),
        ({"max_files_per_cycle": 0}, "must be between"),
        ({"page_size": 5000}, "must be between"),
        ({"rescan_overlap_minutes": -1}, "cannot be negative"),
        ({"include_insights": "maybe"}, "not a true/false value"),
        ({"since": "last tuesday"}, "since"),
    ],
)
def test_a_bad_option_fails_at_construction_not_mid_cycle(
    context_factory: MakeContext,
    trail_dir: TrailTree,
    options: dict[str, Any],
    expected: str,
) -> None:
    with pytest.raises(ConfigError, match=expected):
        CloudTrailConnector(context_factory("ct", options={"path": str(trail_dir.root), **options}))


def test_options_written_as_strings_are_parsed(
    context_factory: MakeContext, trail_dir: TrailTree
) -> None:
    """A YAML file quotes a number and an operator still means it."""
    connector = CloudTrailConnector(
        context_factory(
            "ct",
            options={
                "path": str(trail_dir.root),
                "max_files_per_cycle": "3",
                "rescan_overlap_minutes": "5.5",
                "include_insights": "yes",
                "since": "2026-10-21T00:00:00Z",
            },
        )
    )
    assert connector.max_files == 3
    assert connector.rescan_overlap_minutes == 5.5
    assert connector.include_insights is True
    assert connector.since == datetime(2026, 10, 21, tzinfo=UTC)


def test_a_trail_prefix_gets_exactly_one_slash(context_factory: MakeContext) -> None:
    connector = CloudTrailConnector(
        context_factory("ct", options={"mode": "s3", "bucket": BUCKET, "prefix": "/AWSLogs/acme"})
    )
    assert connector.prefix == "AWSLogs/acme/"


def test_the_type_declares_itself_to_the_registry() -> None:
    assert CloudTrailConnector.type_name == "cloudtrail"
    assert CloudTrailConnector.supports_backfill is True
    assert "CloudTrail" in CloudTrailConnector.summary


# -- name and channel parsing --------------------------------------------------


@pytest.mark.parametrize(
    ("key", "flavor"),
    [
        (f"AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/2026-10-22/x.json.gz", "management"),
        (f"AWSLogs/{ACCOUNT}/CloudTrail-Insight/us-east-1/x.json.gz", "insight"),
        (f"AWSLogs/{ACCOUNT}/CloudTrail-NetworkActivity/us-east-1/x.json.gz", "network-activity"),
        (f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/us-east-1/x.json.gz", "digest"),
        ("AWSLogs/CloudTrail-AggregatedRecords/x.json.gz", "aggregated"),
        ("someone/renamed/trail.json.gz", "management"),
    ],
)
def test_classify_reads_the_channel_from_the_path(key: str, flavor: str) -> None:
    assert classify(key) == flavor


@pytest.mark.parametrize(
    ("name", "wanted"),
    [
        ("123456789012_CloudTrail_us-east-1_20261022T0905Z_Mu0KsOhtH1ar15ZZ.json.gz", True),
        ("copied-by-a-script.json", True),
        ("Digest.json.zip", False),
        ("MFABucketPolicies.csv", False),
    ],
)
def test_is_log_file_name_accepts_only_the_two_delivered_suffixes(name: str, wanted: bool) -> None:
    assert is_log_file_name(name) is wanted


def test_the_delivery_minute_comes_out_of_the_documented_example_name() -> None:
    """The file name from AWS's own example parses to the minute that example claims."""
    key = "111122223333_CloudTrail_us-east-2_20150801T0210Z_Mu0KsOhtH1ar15ZZ.json.gz"
    assert cloudtrail_module._delivered_from_name(key) == datetime(2015, 8, 1, 2, 10, tzinfo=UTC)


def test_a_name_with_an_impossible_minute_is_not_a_delivery_time() -> None:
    """A file that merely looks like a trail keeps its real mtime instead of a fake 25:99."""
    key = "123456789012_CloudTrail_us-east-1_20261399T9961Z_Mu0KsOhtH1ar15ZZ.json.gz"
    assert cloudtrail_module._delivered_from_name(key) is None


def test_a_log_file_positions_and_cursors_by_delivery_minute() -> None:
    delivered = datetime(2026, 10, 22, 9, 5, tzinfo=UTC)
    log_file = LogFile("some/key.json.gz", delivered, "management", 10)
    assert log_file.position == (delivered, "some/key.json.gz")
    assert log_file.as_cursor() == "20261022T090500|some/key.json.gz"


# -- files mode: which files a cycle reads ------------------------------------


def test_a_first_cycle_reads_gzip_and_plain_files_in_delivery_order(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    trail_dir.add(trail_record(1, eventID="evt-1"), stamp="20261022T0845")
    trail_dir.add(
        trail_record(2, eventID="evt-2"),
        stamp="20261022T0810",
        region="eu-central-1",
        gzipped=False,
    )
    assert event_ids(files_connector(trail_dir).fetch()) == ["evt-2", "evt-1"]


def test_the_cursor_is_the_delivery_minute_and_the_key(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    newest = trail_dir.add(trail_record(1), stamp="20261022T0845")
    trail_dir.add(trail_record(2, eventID="evt-2"), stamp="20261022T0810")
    raws = list(files_connector(trail_dir).fetch())
    assert raws[-1].cursor == f"20261022T084500|{newest}"
    assert raws[-1].metadata["source_key"] == str(newest)


def test_ordering_follows_delivery_time_not_key_order(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """The reason a cursor cannot simply be the key: region sorts before the date does."""
    late = trail_dir.add(trail_record(1, eventID="evt-late"), stamp="20261022T0801", region="aaa")
    early = trail_dir.add(trail_record(2, eventID="evt-early"), stamp="20261022T0859", region="zzz")
    assert str(early) > str(late)
    assert event_ids(files_connector(trail_dir).fetch()) == ["evt-late", "evt-early"]


def test_the_next_cycle_re_reads_the_overlap_but_not_the_cursor_file(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """The whole trade: a late file with an older stamp is still read; dedup absorbs the rest."""
    newest = trail_dir.add(trail_record(0, eventID="evt-new"), stamp="20261022T0905")
    trail_dir.add(trail_record(1, eventID="evt-overlap"), stamp="20261022T0859")
    trail_dir.add(trail_record(2, eventID="evt-old"), stamp="20261022T0840")
    connector = files_connector(trail_dir, rescan_overlap_minutes=15)
    connector.checkpoint.advance(cursor=f"20261022T090500|{newest}")
    assert event_ids(connector.fetch()) == ["evt-overlap"]


def test_a_file_delivered_late_with_an_older_stamp_is_not_lost(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """CloudTrail documents delayed delivery; a key-ordered cursor would have skipped this file."""
    newest = trail_dir.add(trail_record(0, eventID="evt-new"), stamp="20261022T0905")
    trail_dir.add_raw(
        trail_bytes([trail_record(1, eventID="evt-late-arrival")]),
        stamp="20261022T0858",
        region="aaa",
    )
    connector = files_connector(trail_dir)
    connector.checkpoint.advance(cursor=f"20261022T090500|{newest}")
    assert event_ids(connector.fetch()) == ["evt-late-arrival"]


def test_the_cursor_file_itself_is_never_read_twice(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    only = trail_dir.add(trail_record(0), stamp="20261022T0905")
    connector = files_connector(trail_dir)
    connector.checkpoint.advance(cursor=f"20261022T090500|{only}")
    assert list(connector.fetch()) == []


@pytest.mark.parametrize(
    "cursor", ["20261022T090500", "20261022T0905|some/key", "nonsense|some/key"]
)
def test_an_unparsable_cursor_is_refused_instead_of_restarting_the_world(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree, cursor: str
) -> None:
    """Treating a damaged cursor as "no cursor" would re-read every file in the bucket."""
    connector = files_connector(trail_dir)
    connector.checkpoint.advance(cursor=cursor)
    with pytest.raises(ConfigError, match="unparsable cursor"):
        list(connector.fetch())


def test_lookback_days_bounds_a_first_run(
    context_factory: MakeContext, trail_dir: TrailTree
) -> None:
    trail_dir.add(trail_record(1, eventID="evt-old"), stamp="20261020T1000")
    trail_dir.add(trail_record(2, eventID="evt-recent"), stamp="20261022T0830")
    narrow = CloudTrailConnector(context_factory("ct", options={"path": str(trail_dir.root)}))
    assert event_ids(narrow.fetch()) == ["evt-recent"]
    wide = CloudTrailConnector(
        context_factory("ct", options={"path": str(trail_dir.root), "lookback_days": 30})
    )
    assert event_ids(wide.fetch()) == ["evt-old", "evt-recent"]


def test_since_is_the_floor_for_a_backfill(
    context_factory: MakeContext, trail_dir: TrailTree
) -> None:
    trail_dir.add(trail_record(1, eventID="evt-old"), stamp="20261015T1000")
    trail_dir.add(trail_record(2, eventID="evt-recent"), stamp="20261022T0830")
    wide = CloudTrailConnector(
        context_factory(
            "ct", options={"path": str(trail_dir.root), "since": "2026-10-14T00:00:00Z"}
        )
    )
    assert event_ids(wide.fetch()) == ["evt-old", "evt-recent"]
    narrow = CloudTrailConnector(
        context_factory(
            "ct", options={"path": str(trail_dir.root), "since": "2026-10-20T00:00:00Z"}
        )
    )
    assert event_ids(narrow.fetch()) == ["evt-recent"]


def test_max_files_per_cycle_stops_at_a_file_boundary(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    trail_dir.add(trail_record(1, eventID="evt-1"), stamp="20261022T0805")
    trail_dir.add(trail_record(2, eventID="evt-2"), stamp="20261022T0810")
    assert event_ids(files_connector(trail_dir, max_files_per_cycle=1).fetch()) == ["evt-1"]


def test_max_records_per_cycle_never_splits_a_file(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """The cap is checked before opening, so a cursor never claims a half-read file."""
    trail_dir.add(
        trail_record(1, eventID="evt-1a"),
        trail_record(2, eventID="evt-2a"),
        stamp="20261022T0805",
    )
    trail_dir.add(trail_record(3, eventID="evt-3b"), stamp="20261022T0810")
    connector = files_connector(trail_dir, max_records_per_cycle=1)
    assert event_ids(connector.fetch()) == ["evt-1a", "evt-2a"]


def test_a_file_without_a_stamp_in_its_name_falls_back_to_its_mtime(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    path = trail_dir.add(trail_record(0), name="copied-by-a-script.json.gz")
    trail_dir.set_mtime(path, "20261022T0730")
    raws = list(files_connector(trail_dir).fetch())
    assert event_ids(raws) == ["evt-0"]
    assert raws[0].cursor == f"20261022T073000|{path}"


@pytest.mark.parametrize(
    ("flavor", "options", "expected"),
    [
        ("digest", {}, []),
        ("aggregated", {}, []),
        ("insight", {}, []),
        ("insight", {"include_insights": True}, ["ins-0"]),
        ("network-activity", {}, []),
        ("network-activity", {"include_network_activity": True}, ["evt-0"]),
    ],
)
def test_only_the_channels_the_operator_asked_for_are_read(
    files_connector: Callable[..., CloudTrailConnector],
    trail_dir: TrailTree,
    flavor: str,
    options: dict[str, Any],
    expected: list[str],
) -> None:
    record = insight_record(0) if flavor == "insight" else trail_record(0)
    trail_dir.add(record, stamp="20261022T0850", flavor=flavor)
    assert event_ids(files_connector(trail_dir, **options).fetch()) == expected


def test_one_file_can_be_the_path_for_a_one_off_backfill(
    context_factory: MakeContext, trail_dir: TrailTree
) -> None:
    path = trail_dir.add(trail_record(0), stamp="20261022T0850")
    connector = CloudTrailConnector(context_factory("ct", options={"path": str(path)}))
    assert event_ids(connector.fetch()) == ["evt-0"]


# -- unreadable files ---------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"\x1f\x8b but not really gzip", "Unknown compression method"),
        (b"this is not json", "Expecting value"),
        (b'{"Records": "not a list"}', "no 'Records' array"),
        (b'{"Records": ["a string"]}', "expected a JSON object"),
    ],
)
def test_a_file_that_yields_no_records_becomes_one_sentinel(
    files_connector: Callable[..., CloudTrailConnector],
    trail_dir: TrailTree,
    data: bytes,
    reason: str,
) -> None:
    path = trail_dir.add_raw(data, stamp="20261022T0850")
    errors = file_errors(files_connector(trail_dir).fetch())
    assert len(errors) == 1
    assert errors[0][0] == str(path)
    assert reason in errors[0][1]


def test_the_sentinel_dead_letters_with_the_reason_and_the_key(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    path = trail_dir.add_raw(b"this is not json", stamp="20261022T0850")
    connector = files_connector(trail_dir)
    raw = next(iter(connector.fetch()))
    assert raw.cursor == f"20261022T085000|{path}"
    with pytest.raises(MalformedEventError, match="could not be read") as raised:
        connector.parse(raw)
    assert "Expecting value" in str(raised.value)
    assert str(path) in str(raised.value)


def test_a_file_above_max_object_bytes_is_never_decoded(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    path = trail_dir.add(trail_record(0), stamp="20261022T0850")
    errors = file_errors(files_connector(trail_dir, max_object_bytes=128).fetch())
    assert len(errors) == 1
    assert "max_object_bytes" in errors[0][1]
    assert path.stat().st_size > 128


def test_a_healthy_file_after_an_unreadable_one_is_still_read(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """One bad file must not end the cycle: the events after it are the ones an analyst wants."""
    trail_dir.add_raw(b"not json", stamp="20261022T0805")
    trail_dir.add(trail_record(1, eventID="evt-good"), stamp="20261022T0810")
    raws = list(files_connector(trail_dir).fetch())
    assert len(file_errors(raws)) == 1
    assert event_ids(raws)[-1] == "evt-good"


def test_a_renamed_gzip_file_is_still_read_as_gzip(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """Magic bytes decide, not the extension: a renamed file must not lose its events."""
    path = trail_dir.folder("management", "us-east-1", "20261022T0850") / "trail.json"
    path.write_bytes(trail_bytes([trail_record(0)]))
    assert event_ids(files_connector(trail_dir).fetch()) == ["evt-0"]


# -- s3 mode ------------------------------------------------------------------


def test_s3_mode_pages_the_listing_then_reads_each_object(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    older = s3_key(log_name("20261022T0810"))
    newer = s3_key(log_name("20261022T0845"))
    fake = FakeS3(
        pages=[
            {"Contents": [s3_item(older)], "NextContinuationToken": "p2"},
            {"Contents": [s3_item(newer)]},
        ],
        objects={
            older: trail_bytes([trail_record(1, eventID="evt-old")]),
            newer: trail_bytes([trail_record(2, eventID="evt-new")]),
        },
    )
    raws = list(s3_connector(fake, page_size=2).fetch())
    assert event_ids(raws) == ["evt-old", "evt-new"]
    assert [item.get("ContinuationToken") for item in fake.list_params] == [None, "p2"]
    assert fake.list_params[0]["Bucket"] == BUCKET
    assert fake.list_params[0]["MaxKeys"] == 2
    assert raws[-1].cursor == f"20261022T084500|{newer}"


def test_s3_mode_ignores_keys_that_are_not_log_files(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    wanted = s3_key(log_name("20261022T0845"))
    fake = FakeS3(
        pages=[
            {
                "Contents": [
                    s3_item("AWSLogs/notes.txt"),
                    s3_item("AWSLogs/MFABucketPolicies.json.zip"),
                    s3_item(wanted),
                ]
            }
        ],
        objects={wanted: trail_bytes([trail_record(0)])},
    )
    assert event_ids(s3_connector(fake).fetch()) == ["evt-0"]
    assert fake.get_keys == [wanted]


def test_s3_mode_falls_back_to_last_modified_for_an_unnamed_object(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    key = s3_key("hand-copied.json.gz")
    fake = FakeS3(
        pages=[{"Contents": [s3_item(key, modified="2026-10-22T07:30:00Z")]}],
        objects={key: trail_bytes([trail_record(0)])},
    )
    raws = list(s3_connector(fake).fetch())
    assert event_ids(raws) == ["evt-0"]
    assert raws[0].cursor == f"20261022T073000|{key}"


def test_an_object_with_neither_a_stamp_nor_a_last_modified_is_skipped(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    fake = FakeS3(pages=[{"Contents": [s3_item(s3_key("mystery.json.gz"))]}])
    assert list(s3_connector(fake).fetch()) == []
    assert fake.get_keys == []


def test_a_truncated_listing_refuses_to_advance_past_files_it_did_not_see(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    """Cutting a listing short and then moving the cursor forward would silently lose events."""
    fake = FakeS3(
        pages=[
            {
                "Contents": [s3_item(s3_key(log_name("20261022T0845")))],
                "NextContinuationToken": "p2",
            },
            {"Contents": []},
        ]
    )
    with pytest.raises(TransientError, match="was cut at 1 pages"):
        list(s3_connector(fake, max_listing_pages=1).fetch())


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (client_error("AccessDenied", 403), AuthorizationError),
        (client_error("InvalidAccessKeyId", 401), AuthenticationError),
        (client_error("SignatureDoesNotMatch", 400), AuthenticationError),
        (client_error("NoSuchBucket", 404), PermanentError),
        (client_error("SlowDown", 503), RateLimitedError),
        (client_error("ServiceUnavailable", 503), TransientError),
        (client_error("MalformedXML", 400), PermanentError),
        (client_error("Forbidden", 403), AuthorizationError),
    ],
)
def test_an_s3_failure_becomes_the_framework_class_it_means(
    s3_connector: Callable[..., CloudTrailConnector],
    error: BaseException,
    expected: type[SocConnectorError],
) -> None:
    connector = s3_connector(FakeS3(list_error=error))
    with pytest.raises(expected):
        list(connector.fetch())


def test_a_throttled_response_hands_the_server_wait_to_the_retry_layer(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    connector = s3_connector(FakeS3(list_error=client_error("SlowDown", 503, retry_after="7")))
    with pytest.raises(RateLimitedError) as raised:
        list(connector.fetch())
    assert raised.value.retry_after_seconds == 7


def test_a_credential_failure_tells_the_operator_which_knob_to_turn(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    connector = s3_connector(FakeS3(list_error=NoCredentialsError()))
    with pytest.raises(AuthenticationError, match="AWS_ACCESS_KEY_ID"):
        list(connector.fetch())


def test_a_missing_region_is_a_config_error_not_a_network_failure(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    connector = s3_connector(FakeS3(list_error=NoRegionError()))
    with pytest.raises(ConfigError, match="AWS_REGION"):
        list(connector.fetch())


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (EndpointConnectionError(endpoint_url="https://s3.example"), TransientError),
        (ConnectTimeoutError(endpoint_url="https://s3.example"), TransientError),
        (ParamValidationError(report="bad key"), PermanentError),
    ],
)
def test_botocore_failures_without_an_s3_code_are_classified_by_name(
    s3_connector: Callable[..., CloudTrailConnector],
    error: BaseException,
    expected: type[SocConnectorError],
) -> None:
    connector = s3_connector(FakeS3(list_error=error))
    with pytest.raises(expected):
        list(connector.fetch())


def test_a_transient_read_failure_stops_the_cycle_and_keeps_the_cursor(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    """A blip must not dead-letter: the next tick reads the same file and the events are saved."""
    key = s3_key(log_name("20261022T0845"))
    fake = FakeS3(pages=[{"Contents": [s3_item(key)]}], get_error=TransientError("reset by peer"))
    connector = s3_connector(fake)
    with pytest.raises(TransientError):
        list(connector.fetch())
    assert connector.checkpoint.state.cursor is None


def test_an_object_response_without_a_body_dead_letters(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    key = s3_key(log_name("20261022T0845"))
    fake = FakeS3(pages=[{"Contents": [s3_item(key)]}], objects={key: {}})
    errors = file_errors(s3_connector(fake).fetch())
    assert len(errors) == 1
    assert "no Body" in errors[0][1]


def test_an_object_deleted_between_listing_and_read_dead_letters(
    s3_connector: Callable[..., CloudTrailConnector],
) -> None:
    """A lifecycle rule can win the race; the cycle has to move past it, not stall on it."""
    key = s3_key(log_name("20261022T0845"))
    fake = FakeS3(pages=[{"Contents": [s3_item(key)]}], objects={})
    errors = file_errors(s3_connector(fake).fetch())
    assert len(errors) == 1
    assert "NoSuchKey" in errors[0][1]


def test_the_rate_budget_is_spent_before_each_listing_page(
    context_factory: MakeContext,
) -> None:
    limiter = EmptyLimiter()
    connector = CloudTrailConnector(
        context_factory("ct", options={"mode": "s3", "bucket": BUCKET}, limiter=limiter)
    )
    connector._client = FakeS3(pages=[{"Contents": []}])
    with pytest.raises(TransientError, match="rate budget exhausted"):
        list(connector.fetch())
    assert limiter.attempts == 1


def test_the_client_is_built_from_the_default_credential_chain(
    context_factory: MakeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No option can carry a key: the only inputs to the client are the region and the endpoint.

    This is the security rule stated as a test — a connector that accepts a secret from a config
    file will get one, and this one is only ever meant to read the environment.
    """
    captured: dict[str, Any] = {}

    class StubBoto3:
        @staticmethod
        def client(service: str, **kwargs: Any) -> FakeS3:
            captured["service"] = service
            captured.update(kwargs)
            return FakeS3()

    monkeypatch.setattr(cloudtrail_module, "boto3", StubBoto3)
    connector = CloudTrailConnector(
        context_factory(
            "ct",
            options={
                "mode": "s3",
                "bucket": BUCKET,
                "region": "eu-west-1",
                "endpoint_url": "https://localhost:4566",
                "aws_access_key_id": "<aws-access-key-id>",
                "aws_secret_access_key": "<aws-secret-access-key>",
            },
        )
    )
    assert isinstance(connector._get_client(), FakeS3)
    assert captured == {
        "service": "s3",
        "region_name": "eu-west-1",
        "endpoint_url": "https://localhost:4566",
    }


def test_close_releases_the_client_once(context_factory: MakeContext) -> None:
    fake = FakeS3()
    connector = CloudTrailConnector(context_factory("ct", options={"mode": "s3", "bucket": BUCKET}))
    connector._client = fake
    connector.close()
    connector.close()
    assert fake.closed == 1
    assert connector._client is None


def test_close_is_safe_in_files_mode(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """Files mode never had a client, and shutdown still calls close on every source."""
    connector = files_connector(trail_dir)
    connector.close()
    assert connector._client is None


# -- the mapping table --------------------------------------------------------


def test_a_management_write_event_maps_onto_ecs_paths() -> None:
    fields = map_record(trail_record())
    assert fields["@timestamp"] == "2026-10-22T08:55:11Z"
    assert fields["event.kind"] == "event"
    assert fields["event.category"] == ["configuration"]
    assert fields["event.type"] == ["creation"]
    assert fields["event.action"] == "RunInstances"
    assert fields["event.provider"] == "ec2.amazonaws.com"
    assert fields["event.id"] == "evt-0"
    assert fields["event.code"] == "req-0"
    assert fields["event.outcome"] == "success"
    assert fields["cloud.region"] == "us-east-1"
    assert fields["cloud.service.name"] == "ec2"
    assert fields["cloud.account.id"] == ACCOUNT
    assert fields["user.id"] == "AIDAEXAMPLE7T526QEXAMPLE"
    assert fields["user.name"] == "svc-demo"
    assert fields["related.user"] == ["svc-demo"]
    assert fields["source.ip"] == "192.0.2.10"
    assert fields["related.ip"] == ["192.0.2.10"]
    assert fields["tags"] == ["cloudtrail", "management"]
    assert fields["labels"] == {"cloudtrail_principal_type": "IAMUser"}
    assert fields["raw"]["eventID"] == "evt-0"


@pytest.mark.parametrize(
    ("action", "read_only", "expected"),
    [
        ("CreateTrail", False, ["creation"]),
        ("RunInstances", False, ["creation"]),
        ("DeleteTrail", False, ["deletion"]),
        ("TerminateInstances", False, ["deletion"]),
        ("PutObject", False, ["change"]),
        ("AssumeRole", False, ["change"]),
        ("DescribeTrails", True, ["info"]),
        ("GetBucketPolicy", True, ["info"]),
        ("ListTags", False, ["info"]),
        ("WeirdAction", True, ["info"]),
        ("WeirdAction", False, ["change"]),
    ],
)
def test_event_type_comes_from_the_action_name_then_from_read_only(
    action: str, read_only: bool, expected: list[str]
) -> None:
    record = trail_record(0, eventName=action, readOnly=read_only)
    assert map_record(record)["event.type"] == expected


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (trail_record(0), ["configuration"]),
        (trail_record(0, eventCategory="Data", eventSource="s3.amazonaws.com"), ["file"]),
        (
            trail_record(0, eventCategory="Data", eventSource="dynamodb.amazonaws.com"),
            ["database"],
        ),
        (trail_record(0, eventCategory="Data", eventSource="lambda.amazonaws.com"), None),
        (
            trail_record(0, eventCategory="NetworkActivity", eventType="AwsVpceEvents"),
            ["network"],
        ),
        (
            trail_record(0, eventType="AwsConsoleSignIn", eventName="ConsoleLogin"),
            ["authentication"],
        ),
        (insight_record(0), None),
    ],
)
def test_event_category_is_only_claimed_when_the_source_names_it(
    record: dict[str, Any], expected: list[str] | None
) -> None:
    """Uncategorised is absence, not an empty array: a document never carries ``"category": []``."""
    fields = map_record(record)
    assert fields.get("event.category") == expected


def test_a_console_sign_in_is_a_start_that_keeps_the_mfa_assertion() -> None:
    fields = map_record(
        trail_record(
            0,
            eventType="AwsConsoleSignIn",
            eventName="ConsoleLogin",
            additionalEventData={"MFAUsed": "Yes"},
            userAgent="Mozilla/5.0 (X11; Linux x86_64)",
        )
    )
    assert fields["event.type"] == ["start"]
    assert fields["labels"]["cloudtrail_mfa"] == "Yes"
    assert fields["user_agent.original"] == "Mozilla/5.0 (X11; Linux x86_64)"
    assert "tls.version" not in fields


def test_a_denied_request_carries_the_services_own_error() -> None:
    fields = map_record(
        trail_record(0, errorCode="AccessDenied", errorMessage="not authorized to perform")
    )
    assert fields["event.outcome"] == "failure"
    assert fields["error.code"] == "AccessDenied"
    assert fields["error.message"] == "not authorized to perform"


def test_an_assumed_role_session_is_attributed_to_the_role_not_to_the_access_key() -> None:
    fields = map_record(
        trail_record(
            0,
            userIdentity={
                "type": "AssumedRole",
                "principalId": "AROEXAMPLE:ci-deploy",
                "accessKeyId": "<temporary-access-key-id>",
                "sessionContext": {
                    "sessionIssuer": {"type": "Role", "userName": "ci-deploy-role"},
                    "attributes": {"mfaAuthenticated": "false"},
                },
            },
            sessionCredentialFromConsole="true",
        )
    )
    assert fields["user.name"] == "ci-deploy-role"
    assert fields["user.id"] == "AROEXAMPLE:ci-deploy"
    assert fields["labels"]["cloudtrail_principal_type"] == "AssumedRole"
    assert fields["labels"]["cloudtrail_session_from_console"] == "true"
    assert fields["labels"]["cloudtrail_mfa"] == "false"


def test_a_false_console_flag_is_not_recorded_as_a_console_session() -> None:
    """AWS documents this field as the string "true" or "false"; presence is not a yes."""
    fields = map_record(trail_record(0, sessionCredentialFromConsole="false"))
    assert "cloudtrail_session_from_console" not in fields["labels"]


def test_an_access_key_id_never_reaches_a_queryable_field() -> None:
    """AWS documents ``accessKeyId`` as unusable for identifying a session; it stays in ``raw``."""
    fields = map_record(
        trail_record(
            0,
            userIdentity={
                "type": "IAMUser",
                "accessKeyId": "<access-key-id>",
                "userName": "svc-demo",
            },
        )
    )
    mapped = [value for key, value in fields.items() if key != "raw"]
    assert all("<access-key-id>" not in str(value) for value in mapped)
    assert fields["raw"]["userIdentity"]["accessKeyId"] == "<access-key-id>"


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("192.0.2.10", {"source.ip": "192.0.2.10", "related.ip": ["192.0.2.10"]}),
        ("s3.amazonaws.com", {"source.domain": "s3.amazonaws.com"}),
        ("AWS Internal/123456789", {}),
        ("", {}),
    ],
)
def test_the_source_field_keeps_a_service_principal_instead_of_dropping_it(
    address: str, expected: dict[str, Any]
) -> None:
    fields = map_record(trail_record(0, sourceIPAddress=address))
    for key, value in expected.items():
        assert fields[key] == value
    assert {"source.ip", "source.domain"} & set(fields) == set(expected) & {
        "source.ip",
        "source.domain",
    }


def test_tls_details_and_the_host_header_are_mapped() -> None:
    fields = map_record(
        trail_record(
            0,
            tlsDetails={
                "tlsVersion": "TLSv1.2",
                "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "clientProvidedHostHeader": "s3.amazonaws.com",
            },
        )
    )
    assert fields["tls.version"] == "TLSv1.2"
    assert fields["tls.cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert fields["url.domain"] == "s3.amazonaws.com"


def test_a_cross_account_event_keeps_both_ids_distinct() -> None:
    """``sharedEventID`` links the two accounts; ``eventID`` stays this delivery's dedup key."""
    fields = map_record(
        trail_record(0, sharedEventID="shared-abc", recipientAccountId="222222222222")
    )
    assert fields["event.hash"] == "shared-abc"
    assert fields["event.id"] == "evt-0"
    assert fields["cloud.account.id"] == "222222222222"


def test_an_insight_record_is_an_alert_that_categorises_nothing() -> None:
    fields = map_record(insight_record(0))
    assert fields["event.kind"] == "alert"
    assert "event.category" not in fields
    assert fields["event.action"] == "GetObject"
    assert fields["event.provider"] == "s3.amazonaws.com"
    assert fields["event.hash"] == "shared-0"
    assert fields["rule.name"] == "ApiCallRateInsight"
    assert fields["tags"] == ["cloudtrail", "insight"]
    assert fields["labels"]["cloudtrail_insight_state"] == "Start"
    assert "user.name" not in fields


def test_a_vpc_endpoint_id_is_kept_as_a_label() -> None:
    fields = map_record(trail_record(0, vpcEndpointId="vpce-0abcdef1234567890"))
    assert fields["labels"]["cloudtrail_vpc_endpoint_id"] == "vpce-0abcdef1234567890"


def test_a_record_without_an_event_time_is_refused_not_stamped_with_the_read_time() -> None:
    with pytest.raises(MalformedEventError, match="no eventTime") as raised:
        map_record(trail_record(0, eventTime=None))
    assert raised.value.field == "eventTime"


def test_a_record_with_no_user_identity_still_maps() -> None:
    fields = map_record(trail_record(0, userIdentity=None))
    assert "user.name" not in fields
    assert "user.id" not in fields
    assert fields["cloud.account.id"] == ACCOUNT


def test_a_service_principal_as_the_source_keeps_the_account_from_the_recipient_field() -> None:
    fields = map_record(
        trail_record(0, sourceIPAddress="lambda.amazonaws.com", userAgent=None, requestID=None)
    )
    assert fields["source.domain"] == "lambda.amazonaws.com"
    assert "event.code" not in fields
    assert "user_agent.original" not in fields


# -- normalize: the version gate, defaults, the document ----------------------


def test_normalize_adds_the_provider_dataset_and_module(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    event = normalize_one(files_connector(trail_dir), trail_record(0))
    assert event.cloud is not None and event.cloud.provider == "aws"
    assert event.event is not None and event.event.module == "aws"
    assert event.event.dataset == "aws.cloudtrail"


def test_the_dataset_option_changes_the_dedup_key(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    connector = files_connector(trail_dir, dataset="aws.trail.prod")
    assert normalize_one(connector, trail_record(0)).identity_key() == "aws.trail.prod:evt-0"


def test_the_document_is_serialised_on_ecs_paths_with_no_empty_fields(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    document = to_document(normalize_one(files_connector(trail_dir), trail_record(0)))
    assert document["@timestamp"] == "2026-10-22T08:55:11.000Z"
    assert document["cloud"] == {
        "provider": "aws",
        "region": "us-east-1",
        "account": {"id": ACCOUNT},
        "service": {"name": "ec2"},
    }
    assert document["event"]["severity"] == 50
    assert document["tags"] == ["cloudtrail", "management"]
    assert document["labels"] == {"cloudtrail_principal_type": "IAMUser"}
    assert "error" not in document and "tls" not in document
    assert document["raw"]["eventName"] == "RunInstances"


def test_the_same_event_id_twice_is_one_identity(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    """Duplicate deliveries are how CloudTrail works; the seen-id window is what makes them safe."""
    connector = files_connector(trail_dir)
    first = normalize_one(connector, trail_record(0))
    second = normalize_one(connector, trail_record(0, requestID="another-request"))
    assert first.identity_key() == second.identity_key()


@pytest.mark.parametrize("version", ["1.08", 1.09, "1.11"])
def test_versions_this_mapping_was_reviewed_against_pass_silently(
    files_connector: Callable[..., CloudTrailConnector],
    trail_dir: TrailTree,
    capture_logs: Callable[[str], list[Any]],
    version: Any,
) -> None:
    connector = files_connector(trail_dir)
    records = capture_logs("connector.ct")
    normalize_one(connector, trail_record(0, eventVersion=version))
    assert records == []


def test_a_newer_major_version_stops_instead_of_guessing(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree
) -> None:
    connector = files_connector(trail_dir)
    with pytest.raises(MalformedEventError, match="major version this mapping has not been"):
        normalize_one(connector, trail_record(0, eventVersion="2.0"))


@pytest.mark.parametrize("version", ["latest", 1])
def test_an_unrecognised_version_is_refused(
    files_connector: Callable[..., CloudTrailConnector], trail_dir: TrailTree, version: Any
) -> None:
    connector = files_connector(trail_dir)
    with pytest.raises(MalformedEventError, match="unrecognised CloudTrail eventVersion"):
        normalize_one(connector, trail_record(0, eventVersion=version))


def test_a_newer_minor_version_warns_once_and_keeps_unknown_fields_in_raw(
    files_connector: Callable[..., CloudTrailConnector],
    trail_dir: TrailTree,
    capture_logs: Callable[[str], list[Any]],
) -> None:
    newer = f"1.{REVIEWED_EVENT_MINOR + 1}"
    connector = files_connector(trail_dir)
    records = capture_logs("connector.ct")
    first = normalize_one(
        connector,
        trail_record(0, eventVersion=newer, eventContext={"tagContext": {"tags": ["owner"]}}),
    )
    normalize_one(connector, trail_record(1, eventVersion=newer))
    warnings = [item for item in records if "newer than this mapping" in item.getMessage()]
    assert len(warnings) == 1
    assert first.raw is not None
    assert first.raw["eventContext"] == {"tagContext": {"tags": ["owner"]}}


# -- the real client, and the registry ---------------------------------------


def test_s3_mode_reads_a_delivered_file_from_a_mocked_bucket(
    context_factory: MakeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """moto, not a fixture: this is what proves a real boto3 client satisfies ``S3Api``.

    No real tenant is involved and nothing here was captured from one — the bucket, the key and
    the record are all constructed by this test.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    key = s3_key(log_name("20261022T0845"))
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        client.put_object(Bucket=BUCKET, Key=key, Body=trail_bytes([trail_record(0)]))
        connector = CloudTrailConnector(
            context_factory("ct", options={"mode": "s3", "bucket": BUCKET, "region": "us-east-1"})
        )
        try:
            raws = list(connector.fetch())
        finally:
            connector.close()
    assert event_ids(raws) == ["evt-0"]
    assert raws[0].cursor == f"20261022T084500|{key}"


def test_cloudtrail_is_a_registered_builtin_type() -> None:
    register_builtins()
    assert "cloudtrail" in connector_summaries()
