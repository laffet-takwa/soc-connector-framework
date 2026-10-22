"""Command line: run, validate, inspect — and a self-test that needs no services.

Exit codes are stable because CI depends on them:

=====  ======================================================
0      success
1      configuration or usage error (nothing was run)
2      the pipeline ran and something failed (dead-lettered or errored)
=====  ======================================================

Secrets are never command-line arguments. They are read from the environment by
``${VAR}`` references in the config file, so they cannot leak into ``ps`` output, shell
history, or a CI log line that echoes the command.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import sys
import tempfile
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final

from soc_connectors.config import AppConfig, load_config, parse_config
from soc_connectors.exceptions import ConfigError, SocConnectorError
from soc_connectors.logging_setup import configure_logging, get_logger
from soc_connectors.pipeline.factory import (
    CONNECTOR_TYPES,
    FORWARDER_TYPES,
    BuiltPipeline,
    build_checkpoint,
    build_pipeline,
    connector_summaries,
    forwarder_summaries,
    register_builtins,
)
from soc_connectors.version import __version__

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PIPELINE_FAILED = 2

DEFAULT_CONFIG = Path("config/example.yaml")

Command = Callable[[argparse.Namespace], int]

SAMPLE_RECORDS: tuple[str, ...] = (
    json.dumps(
        {
            "@timestamp": "2026-10-22T09:00:00Z",
            "event.kind": "event",
            "event.category": "authentication",
            "event.action": "console-login",
            "event.outcome": "success",
            "event.severity": 15,
            "user.name": "svc-demo",
            "source.ip": "198.51.100.10",
            "cloud.provider": "example",
        }
    ),
    json.dumps(
        {
            "@timestamp": "2026-10-22T09:00:01Z",
            "event.kind": "alert",
            "event.category": "authentication",
            "event.action": "impossible-travel",
            "event.outcome": "failure",
            "event.severity": 88,
            "user.name": "j.doe",
            "source.ip": "203.0.113.24",
            "destination.ip": "198.51.100.5",
        }
    ),
    json.dumps(
        {
            "@timestamp": "2026-10-22T09:00:02Z",
            "event.kind": "event",
            "event.category": "network",
            "event.action": "firewall-deny",
            "event.outcome": "failure",
            "network.direction": "inbound",
            "network.transport": "tcp",
            "source.ip": "203.0.113.9",
            "source.port": 51234,
            "destination.ip": "192.0.2.7",
            "destination.port": 22,
        }
    ),
    "{ this line is deliberately not JSON",
)

#: What ``self-test`` expects, derived from the sample data instead of retyped as literals:
#: every line except the deliberately malformed one must normalise and forward.
SELF_TEST_LINES: Final = len(SAMPLE_RECORDS)
SELF_TEST_MALFORMED: Final = 1
SELF_TEST_VALID: Final = SELF_TEST_LINES - SELF_TEST_MALFORMED
#: Only the second sample event crosses the alert route's ``severity_min: 85``.
SELF_TEST_ALERTS: Final = 1
SELF_TEST_CYCLES: Final = 2


def build_parser() -> argparse.ArgumentParser:
    register_builtins()
    parser = argparse.ArgumentParser(
        prog="soc-connectors",
        description="SOC connector framework: security sources to ECS documents to destinations.",
        epilog=(
            "Secrets come from the environment via ${VAR} references in the config file; "
            "they are never command-line arguments. Try: "
            "soc-connectors self-test, then soc-connectors run --config config/example.yaml --once."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"soc-connectors {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    def add_config_argument(
        sub: argparse.ArgumentParser, *, default: Path | None = DEFAULT_CONFIG
    ) -> None:
        sub.add_argument(
            "--config",
            type=Path,
            default=default,
            help="YAML configuration file.",
        )

    run = subparsers.add_parser("run", help="Run the pipeline.", description="Run the pipeline.")
    add_config_argument(run)
    run.add_argument("--once", action="store_true", help="Run a single cycle and exit.")
    run.add_argument("--max-cycles", type=int, default=None, help="Stop after this many cycles.")
    run.add_argument("--log-level", default=None, help="Override the configured log level.")
    run.add_argument(
        "--log-format", default=None, choices=("json", "console"), help="Override the log format."
    )
    run.add_argument(
        "--source", action="append", default=None, help="Run only these source ids (repeatable)."
    )

    validate = subparsers.add_parser(
        "validate-config",
        help="Interpolate, validate and summarise a config file without running it.",
    )
    add_config_argument(validate)
    validate.add_argument("--show-secrets", action="store_true", help=argparse.SUPPRESS)

    status = subparsers.add_parser("status", help="Print checkpointed positions and counters.")
    add_config_argument(status)

    subparsers.add_parser("list-types", help="List registered source and destination types.")

    self_test = subparsers.add_parser(
        "self-test",
        help="Run an end-to-end pipeline against synthetic data and no external services.",
    )
    self_test.add_argument(
        "--keep", action="store_true", help="Print the temporary working directory name."
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    handlers: dict[str, Command] = {
        "run": _command_run,
        "validate-config": _command_validate_config,
        "status": _command_status,
        "list-types": _command_list_types,
        "self-test": _command_self_test,
    }
    try:
        return handlers[str(args.command)](args)
    except ConfigError as exc:
        _error(f"configuration error: {exc}")
        return EXIT_USAGE
    except SocConnectorError as exc:
        _error(f"{type(exc).__name__}: {exc}")
        return EXIT_PIPELINE_FAILED
    except KeyboardInterrupt:
        _error("interrupted")
        return EXIT_PIPELINE_FAILED


def _error(message: str) -> None:
    print(message, file=sys.stderr)


def _emit(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _configure(args: argparse.Namespace, config: AppConfig) -> None:
    configure_logging(
        level=str(getattr(args, "log_level", None) or config.pipeline.log_level),
        log_format=str(getattr(args, "log_format", None) or config.pipeline.log_format),
    )


def _load(args: argparse.Namespace) -> AppConfig:
    config_path = Path(str(args.config))
    return load_config(config_path)


def _filtered(config: AppConfig, wanted: list[str] | None) -> AppConfig:
    if not wanted:
        return config
    known = {source.id for source in config.sources}
    unknown = sorted(set(wanted) - known)
    if unknown:
        raise ConfigError(f"--source names unknown source(s): {', '.join(unknown)}")
    payload = config.model_dump(mode="python")
    for source in payload["sources"]:
        if source["id"] not in wanted:
            source["enabled"] = False
    return parse_config(payload)


# -- commands ----------------------------------------------------------------


def _command_run(args: argparse.Namespace) -> int:
    config = _load(args)
    _configure(args, config)
    config = _filtered(config, args.source)
    built = build_pipeline(config)
    log = get_logger("cli")

    stop_event = threading.Event()

    def handle_signal(signum: int, _frame: Any) -> None:
        if stop_event.is_set():
            return
        stop_event.set()
        log.info("shutdown requested", extra={"signal": signal.Signals(signum).name})
        built.runner.request_stop()

    installed: list[tuple[int, Any]] = []
    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        # The disposition found on entry is kept so a caller that embedded this CLI — or a test
        # suite with its own handler — gets its own back, not the default. Off the main thread
        # (tests, embedding) no handler can be installed at all, which is not an error.
        with contextlib.suppress(ValueError, OSError):
            installed.append((number, signal.signal(number, handle_signal)))

    try:
        state = built.runner.run(once=bool(args.once), max_cycles=args.max_cycles)
    finally:
        built.close()
        for number, previous in installed:
            signal.signal(number, previous)

    summary = state.summary()
    _emit(summary)
    return EXIT_PIPELINE_FAILED if summary["failed_cycles"] else EXIT_OK


def _command_validate_config(args: argparse.Namespace) -> int:
    config = _load(args)
    _configure(args, config)
    register_builtins()
    unknown_sources = sorted({source.type for source in config.sources} - set(CONNECTOR_TYPES))
    unknown_destinations = sorted(
        {item.type for item in config.destinations} - set(FORWARDER_TYPES)
    )
    if unknown_sources or unknown_destinations:
        raise ConfigError(
            "config references unregistered type(s): "
            + ", ".join([*unknown_sources, *unknown_destinations])
            + ". Run `soc-connectors list-types` to see what is available."
        )
    summary = config.describe()
    summary["registry"] = {
        "sources": sorted(CONNECTOR_TYPES),
        "destinations": sorted(FORWARDER_TYPES),
    }
    _emit(summary)
    return EXIT_OK


def _command_status(args: argparse.Namespace) -> int:
    config = _load(args)
    _configure(args, config)
    report: dict[str, Any] = {"config": str(args.config), "sources": []}
    for source in config.sources:
        store = build_checkpoint(config, source)
        state = store.load()
        report["sources"].append(
            {
                "id": source.id,
                "type": source.type,
                "enabled": source.enabled,
                "state_file": str(store.path),
                "exists": store.path.exists(),
                "cursor": state.cursor,
                "last_timestamp": None
                if state.last_timestamp is None
                else state.last_timestamp.isoformat(),
                "seen_ids": len(state.seen_ids),
                "dead_letter_file": str(config.dead_letter_path(source.id)),
            }
        )
    _emit(report)
    return EXIT_OK


def _command_list_types(_args: argparse.Namespace) -> int:
    _emit({"sources": connector_summaries(), "destinations": forwarder_summaries()})
    return EXIT_OK


def _command_self_test(args: argparse.Namespace) -> int:
    """Run the whole pipeline over synthetic data and assert the framework did its job."""
    checks: list[tuple[str, bool, str]] = []

    with tempfile.TemporaryDirectory(prefix="soc-selftest-") as raw_directory:
        root = Path(raw_directory)
        sample = root / "sample.jsonl"
        sample.write_text("\n".join(SAMPLE_RECORDS) + "\n", encoding="utf-8")
        record_file = root / "sink" / "received.jsonl"

        config = parse_config(
            {
                "pipeline": {
                    "poll_interval_seconds": 1,
                    "batch_size": 2,
                    "state_dir": root / "state",
                    "dead_letter_dir": root / "dead_letter",
                    "log_level": "INFO",
                    "log_format": "json",
                },
                "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
                "sources": [
                    {"id": "demo", "type": "sample_jsonl", "options": {"path": str(sample)}}
                ],
                "destinations": [
                    {
                        "id": "recorded",
                        "type": "sink",
                        "options": {"record_file": str(record_file)},
                    },
                    {"id": "alerts", "type": "sink", "severity_min": 85, "options": {}},
                ],
            }
        )
        configure_logging(level="INFO", log_format="json")
        built = build_pipeline(config, sleeper=lambda _seconds: True)
        first = built.runner.run(once=True)
        second = built.runner.run(once=True)
        documents = _read_jsonl(record_file)
        dead = list(built.dead_letters["demo"].records())
        built.close()

        checks = [
            (
                "first cycle read every line",
                first.reports[0].fetched == SELF_TEST_LINES,
                f"fetched={first.reports[0].fetched}",
            ),
            (
                "malformed line dead-lettered",
                first.reports[0].dead_lettered == SELF_TEST_MALFORMED,
                f"dead={first.reports[0].dead_lettered}",
            ),
            (
                "valid lines normalized",
                first.reports[0].normalized == SELF_TEST_VALID,
                f"normalized={first.reports[0].normalized}",
            ),
            (
                "all valid lines forwarded",
                first.reports[0].forwarded == SELF_TEST_VALID,
                f"forwarded={first.reports[0].forwarded}",
            ),
            (
                "every forwarded event was recorded",
                len(documents) == SELF_TEST_VALID,
                f"documents={len(documents)}",
            ),
            (
                "documents carry ECS version",
                all(str(doc.get("ecs", {}).get("version")) for doc in documents),
                "",
            ),
            ("alert route filtered by severity", _alert_route_count(built) == SELF_TEST_ALERTS, ""),
            ("cursor persisted", built.checkpoints["demo"].state.cursor is not None, ""),
            (
                "second cycle re-read nothing",
                second.reports[0].fetched == 0,
                f"fetched={second.reports[0].fetched}",
            ),
            ("dead-letter record explains itself", bool(dead) and "reason" in dead[0], ""),
            (
                "metrics counted the cycles",
                built.metrics.total("cycles") == SELF_TEST_CYCLES,
                f"cycles={built.metrics.total('cycles')}",
            ),
        ]
        if args.keep:
            print(f"working directory kept at {root}", file=sys.stderr)

    failed = [name for name, passed, _detail in checks if not passed]
    for name, passed, detail in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}{'' if passed else f'  ({detail})'}")
    _emit(
        {
            "self_test": "failed" if failed else "passed",
            "checks": len(checks),
            "failed": failed,
            "note": "synthetic data, no external services; fixtures/mocks only",
        }
    )
    return EXIT_OK if not failed else EXIT_PIPELINE_FAILED


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            decoded = json.loads(line)
            if isinstance(decoded, dict):
                rows.append(decoded)
    return rows


def _alert_route_count(built: BuiltPipeline) -> int:
    for route in built.dispatcher.routes:
        if route.forwarder.id == "alerts":
            return int(getattr(route.forwarder, "received", 0))
    return 0
