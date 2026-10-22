"""The CLI: exit codes are an interface, and so is what it refuses to print.

Three things are worth pinning down here: the documented exit codes (CI depends on them), that
a resolved secret never reaches stdout, and that ``self-test`` passes without any service
running — which is the claim the README makes, so it is the claim a test keeps true.
"""

from __future__ import annotations

import json
import logging
import signal
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from soc_connectors.cli import (
    DEFAULT_CONFIG,
    EXIT_OK,
    EXIT_PIPELINE_FAILED,
    EXIT_USAGE,
    SAMPLE_RECORDS,
    SELF_TEST_LINES,
    SELF_TEST_MALFORMED,
    SELF_TEST_VALID,
    build_parser,
    main,
)
from soc_connectors.exceptions import CheckpointError

pytestmark = pytest.mark.unit

#: A value only this module's environment ever sees, used to prove it never reaches a print.
CANARY_VALUE = "synthetic-canary-never-print-this"


@pytest.fixture(autouse=True)
def _leave_logging_alone() -> Iterator[None]:
    """``_configure`` rewrites the package logger, so every test puts it back."""
    logger = logging.getLogger("soc_connectors")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.handlers = handlers
    logger.setLevel(level)
    logger.propagate = propagate


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[[Mapping[str, Any]], Path]:
    def factory(payload: Mapping[str, Any], name: str = "config.yaml") -> Path:
        path = tmp_path / name
        path.write_text(yaml.safe_dump(dict(payload), sort_keys=False), encoding="utf-8")
        return path

    return factory


def sample_line(index: int, **fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "@timestamp": f"2026-10-22T09:00:{index:02d}Z",
        "event.kind": "event",
        "event.category": "authentication",
        "event.action": f"demo-login-{index}",
        "event.severity": 42,
        "user.name": "svc-demo",
        "source.ip": "198.51.100.10",
    }
    record.update(fields)
    return record


def write_sample(
    path: Path, count: int = 3, *, malformed: bool = True, lines: list[dict[str, Any]] | None = None
) -> Path:
    rows = lines if lines is not None else [sample_line(index) for index in range(count)]
    text = "".join(json.dumps(row) + "\n" for row in rows)
    if malformed:
        text += "{ this line is deliberately not JSON\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def demo_payload(
    tmp_path: Path,
    *,
    sources: list[dict[str, Any]] | None = None,
    destinations: list[dict[str, Any]] | None = None,
    batch_size: int = 5,
    redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A config that needs nothing installed: one JSONL source, one sink destination."""
    if sources is None:
        sample = write_sample(tmp_path / "data" / "sample.jsonl")
        sources = [{"id": "demo", "type": "sample_jsonl", "options": {"path": str(sample)}}]
    if destinations is None:
        destinations = [
            {
                "id": "recorded",
                "type": "sink",
                "options": {"record_file": str(tmp_path / "out" / "received.jsonl")},
            }
        ]
    payload: dict[str, Any] = {
        "pipeline": {
            "poll_interval_seconds": 1,
            "batch_size": batch_size,
            "state_dir": str(tmp_path / "state"),
            "dead_letter_dir": str(tmp_path / "dead_letter"),
            "log_level": "INFO",
            "log_format": "json",
        },
        "retry": {"max_attempts": 2, "base_wait_seconds": 0, "max_wait_seconds": 0},
        "sources": sources,
        "destinations": destinations,
    }
    if redaction is not None:
        payload["redaction"] = redaction
    return payload


def decoded(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Parse the JSON the command printed, failing loudly when it printed something else."""
    text = capsys.readouterr().out
    assert text.strip(), "the command printed nothing to stdout"
    payload = json.loads(text)
    assert isinstance(payload, dict)
    return payload


# -- the parser ---------------------------------------------------------------


def test_no_command_prints_help_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_OK
    assert "usage: soc-connectors" in capsys.readouterr().out


def test_the_version_flag_reports_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "soc-connectors" in capsys.readouterr().out


def test_the_default_config_is_the_shipped_example() -> None:
    parser = build_parser()
    assert parser.parse_args(["validate-config"]).config == DEFAULT_CONFIG
    assert Path("config/example.yaml") == DEFAULT_CONFIG


def test_help_names_the_epilog_without_a_secret_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    text = capsys.readouterr().out
    assert "never command-line arguments" in text
    assert "--secret" not in text
    assert "--token" not in text


def test_list_types_prints_the_built_in_registry(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-types"]) == EXIT_OK
    payload = decoded(capsys)
    assert "sample_jsonl" in payload["sources"]
    assert "sink" in payload["destinations"]
    assert payload["sources"]["sample_jsonl"]


def test_self_test_documents_that_it_used_no_services(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["self-test"]) == EXIT_OK
    payload = _json_block(capsys.readouterr().out)
    assert "synthetic data" in payload["note"]
    assert "fixtures/mocks only" in payload["note"]


# -- validate-config ----------------------------------------------------------


def test_validate_config_summarises_without_running_anything(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    assert main(["validate-config", "--config", str(path)]) == EXIT_OK
    summary = decoded(capsys)
    assert sorted(summary) == [
        "destinations",
        "pipeline",
        "redaction",
        "registry",
        "retry",
        "sources",
        "version",
    ]
    assert summary["sources"][0]["id"] == "demo"
    sources = summary["registry"]["sources"]
    assert sources == sorted(sources)
    assert {"sample_jsonl", "cloudtrail"} <= set(sources)
    assert summary["registry"]["destinations"] == ["sink"]


def test_validate_config_prints_option_names_never_option_values(
    tmp_path: Path,
    write_config: Callable[[Mapping[str, Any]], Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOC_TEST_SECRET", CANARY_VALUE)
    payload = demo_payload(tmp_path)
    payload["sources"][0]["options"]["client_secret"] = "${SOC_TEST_SECRET}"
    path = write_config(payload)
    assert main(["validate-config", "--config", str(path)]) == EXIT_OK
    text = capsys.readouterr().out
    assert "client_secret" in text
    assert CANARY_VALUE not in text


def test_validate_config_refuses_an_unregistered_type(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    payload = demo_payload(tmp_path)
    payload["destinations"] = [{"id": "es", "type": "elasticsearch", "options": {}}]
    assert main(["validate-config", "--config", str(write_config(payload))]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "unregistered type" in captured.err
    assert "elasticsearch" in captured.err
    assert captured.out == ""


def test_a_missing_config_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "nothing.yaml"
    assert main(["validate-config", "--config", str(missing)]) == EXIT_USAGE
    assert "configuration file not found" in capsys.readouterr().err


def test_an_unset_secret_reference_fails_before_anything_runs(
    tmp_path: Path,
    write_config: Callable[[Mapping[str, Any]], Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOC_TEST_SECRET", raising=False)
    payload = demo_payload(tmp_path)
    payload["sources"][0]["options"]["api_key"] = "${SOC_TEST_SECRET}"
    assert main(["validate-config", "--config", str(write_config(payload))]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "SOC_TEST_SECRET" in err
    assert CANARY_VALUE not in err


def test_disabling_every_destination_is_refused_not_warned(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    # The config validator owns this rule, so the CLI has no half-broken pipeline to warn about.
    payload = demo_payload(tmp_path)
    payload["destinations"] = [{"id": "recorded", "type": "sink", "enabled": False, "options": {}}]
    assert main(["validate-config", "--config", str(write_config(payload))]) == EXIT_USAGE
    assert "no enabled destinations" in capsys.readouterr().err


# -- run ----------------------------------------------------------------------


def test_run_once_forwards_the_sample_and_dead_letters_the_bad_line(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once"]) == EXIT_OK
    summary = decoded(capsys)
    assert summary["cycles"] == 1
    assert summary["failed_cycles"] == 0
    report = summary["reports"][0]
    assert report["connector_id"] == "demo"
    assert report["fetched"] == 4
    assert report["normalized"] == 3
    assert report["forwarded"] == 3
    assert report["dead_lettered"] == 1


def test_run_records_the_documents_a_real_destination_would_have_received(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once"]) == EXIT_OK
    capsys.readouterr()
    rows = [
        json.loads(line)
        for line in (tmp_path / "out" / "received.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 3
    assert all(row["ecs"]["version"] for row in rows)
    assert rows[0]["event"]["action"] == "demo-login-0"


def test_run_persists_state_so_the_next_cycle_reads_only_new_lines(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    sample = write_sample(tmp_path / "data" / "sample.jsonl")
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once"]) == EXIT_OK
    capsys.readouterr()
    assert (tmp_path / "state" / "demo.json").exists()
    with sample.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(sample_line(9)) + "\n")
    assert main(["run", "--config", str(path), "--once"]) == EXIT_OK
    report = decoded(capsys)["reports"][0]
    assert report["fetched"] == 1
    assert report["forwarded"] == 1


def test_a_destination_that_cannot_write_exits_two(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    payload = demo_payload(
        tmp_path,
        destinations=[{"id": "recorded", "type": "sink", "options": {"record_file": str(blocked)}}],
    )
    code = main(["run", "--config", str(write_config(payload)), "--once"])
    assert code == EXIT_PIPELINE_FAILED
    summary = decoded(capsys)
    assert summary["failed_cycles"] == 1
    report = summary["reports"][0]
    assert report["forwarded"] == 0
    assert report["dead_lettered"] == 4
    assert report["error"]


def test_the_run_summary_is_json_and_the_logs_are_stderr(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    main(["run", "--config", str(path), "--once"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["cycles"] == 1
    assert "cycle complete" in captured.err


def test_log_overrides_change_what_the_cli_emits(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    main(["run", "--config", str(path), "--once", "--log-level", "WARNING"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["fetched"] == 4
    assert "cycle complete" not in captured.err


def test_the_sink_records_a_redacted_document(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    payload = demo_payload(tmp_path, redaction={"fields": ["user.name"], "mode": "mask"})
    assert main(["run", "--config", str(write_config(payload)), "--once"]) == EXIT_OK
    capsys.readouterr()
    text = (tmp_path / "out" / "received.jsonl").read_text(encoding="utf-8")
    assert "svc-demo" not in text
    assert "***" in text


def test_source_filtering_leaves_the_other_source_untouched(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    quiet = tmp_path / "data" / "quiet.jsonl"
    write_sample(quiet, 2)
    loud = tmp_path / "data" / "loud.jsonl"
    write_sample(loud, 3)
    payload = demo_payload(
        tmp_path,
        sources=[
            {"id": "quiet", "type": "sample_jsonl", "options": {"path": str(quiet)}},
            {"id": "loud", "type": "sample_jsonl", "options": {"path": str(loud)}},
        ],
    )
    path = write_config(payload)
    assert main(["run", "--config", str(path), "--once", "--source", "loud"]) == EXIT_OK
    summary = decoded(capsys)
    assert [report["connector_id"] for report in summary["reports"]] == ["loud"]
    assert summary["reports"][0]["fetched"] == 4
    assert not (tmp_path / "state" / "quiet.json").exists()


def test_an_unknown_source_filter_is_a_usage_error(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once", "--source", "typo"]) == EXIT_USAGE
    assert "unknown source" in capsys.readouterr().err


def test_a_keyboard_interrupt_exits_two(
    tmp_path: Path,
    write_config: Callable[[Mapping[str, Any]], Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt(_config: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr("soc_connectors.cli.build_pipeline", interrupt)
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once"]) == EXIT_PIPELINE_FAILED
    assert "interrupted" in capsys.readouterr().err


def test_a_typed_pipeline_failure_exits_two(
    tmp_path: Path,
    write_config: Callable[[Mapping[str, Any]], Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_config: Any) -> Any:
        raise CheckpointError("state is unreadable")

    monkeypatch.setattr("soc_connectors.cli.build_pipeline", fail)
    path = write_config(demo_payload(tmp_path))
    assert main(["run", "--config", str(path), "--once"]) == EXIT_PIPELINE_FAILED
    assert "CheckpointError" in capsys.readouterr().err


def test_run_restores_the_signal_handler_it_replaced(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    # A CLI that embeds in another program must give back the handler it found, not the default:
    # otherwise running it once silently disarms the caller's own shutdown.
    def ours(signum: int, _frame: Any) -> None:
        raise AssertionError(signum)

    original = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, ours)
    try:
        path = write_config(demo_payload(tmp_path))
        assert main(["run", "--config", str(path), "--once"]) == EXIT_OK
        assert signal.getsignal(signal.SIGINT) is ours
    finally:
        signal.signal(signal.SIGINT, original)
    capsys.readouterr()


# -- status -------------------------------------------------------------------


def test_status_shows_a_position_before_the_first_run(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    assert main(["status", "--config", str(path)]) == EXIT_OK
    entry = decoded(capsys)["sources"][0]
    assert entry["exists"] is False
    assert entry["cursor"] is None
    assert entry["id"] == "demo"


def test_status_reports_where_the_pipeline_stopped(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    path = write_config(demo_payload(tmp_path))
    main(["run", "--config", str(path), "--once"])
    capsys.readouterr()
    assert main(["status", "--config", str(path)]) == EXIT_OK
    entry = decoded(capsys)["sources"][0]
    assert entry["exists"] is True
    assert entry["cursor"]
    assert entry["seen_ids"] == 3
    assert Path(entry["dead_letter_file"]).parent == tmp_path / "dead_letter"


def test_status_needs_no_registry_and_no_writes(
    tmp_path: Path, write_config: Callable[[Mapping[str, Any]], Path], capsys: Any
) -> None:
    payload = demo_payload(tmp_path)
    payload["destinations"] = [{"id": "x", "type": "not_a_real_type", "options": {}}]
    path = write_config(payload)
    assert main(["status", "--config", str(path)]) == EXIT_OK
    assert decoded(capsys)["sources"][0]["type"] == "sample_jsonl"


# -- self-test ----------------------------------------------------------------


def _check_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(("PASS ", "FAIL "))]


def _json_block(text: str) -> dict[str, Any]:
    payload = json.loads(text[text.index("\n{") :].lstrip())
    assert isinstance(payload, dict)
    return payload


def test_self_test_passes_every_check_it_claims(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["self-test"]) == EXIT_OK
    out = capsys.readouterr().out
    lines = _check_lines(out)
    assert lines and all(line.startswith("PASS ") for line in lines)
    payload = _json_block(out)
    assert payload["self_test"] == "passed"
    assert payload["failed"] == []
    assert payload["checks"] == len(lines)


def test_self_test_keeps_its_working_directory_when_asked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["self-test", "--keep"]) == EXIT_OK
    assert "working directory kept at" in capsys.readouterr().err


def test_the_sample_the_self_test_scores_itself_against_is_known() -> None:
    # The expected counts are derived from SAMPLE_RECORDS, not retyped as literals: this is the
    # one place that can prove the derivation still matches the data.
    assert len(SAMPLE_RECORDS) == SELF_TEST_LINES == 4
    assert len([line for line in SAMPLE_RECORDS if not _parses_as_object(line)]) == 1
    assert SELF_TEST_VALID == SELF_TEST_LINES - SELF_TEST_MALFORMED == 3


def _parses_as_object(text: str) -> bool:
    try:
        decoded = json.loads(text)
    except ValueError:
        return False
    return isinstance(decoded, dict)
