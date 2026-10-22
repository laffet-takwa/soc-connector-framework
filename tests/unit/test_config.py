"""Configuration loading: env indirection is mandatory, and secrets stay masked."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from soc_connectors.config import (
    EnvResolved,
    PipelineSettings,
    interpolate_env,
    load_config,
    parse_config,
)
from soc_connectors.exceptions import ConfigError

pytestmark = pytest.mark.unit

MINIMAL: dict[str, Any] = {
    "sources": [{"id": "demo", "type": "sample_jsonl", "options": {"path": "data/sample.jsonl"}}],
    "destinations": [{"id": "sink", "type": "sink", "options": {}}],
}

# Deliberately fake: 32 characters of one letter is a shape, not a key.
SYNTHETIC_SECRET = "x" * 32


def source_options(options: dict[str, Any]) -> dict[str, Any]:
    raw = {
        "sources": [{"id": "entra", "type": "entra_id", "options": options}],
        "destinations": [{"id": "sink", "type": "sink"}],
    }
    return parse_config(raw).sources[0].options


def write_yaml(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


# -- interpolation ---------------------------------------------------------


def test_a_bare_reference_becomes_the_environment_value() -> None:
    resolved = interpolate_env({"token": "${SOC_TOKEN}"}, env={"SOC_TOKEN": SYNTHETIC_SECRET})
    assert resolved["token"] == SYNTHETIC_SECRET


def test_an_embedded_reference_is_replaced_in_place() -> None:
    resolved = interpolate_env(
        {"url": "https://soc.example/${SOC_TENANT}/v1"}, env={"SOC_TENANT": "contoso"}
    )
    assert resolved["url"] == "https://soc.example/contoso/v1"


def test_recursion_covers_nested_mappings_and_lists() -> None:
    resolved = interpolate_env(
        {"sources": [{"options": {"a": "${A}", "list": ["${B}", {"c": "${C}"}]}}]},
        env={"A": "1", "B": "2", "C": "3"},
    )
    options = resolved["sources"][0]["options"]
    assert options["a"] == "1"
    assert options["list"] == ["2", {"c": "3"}]


def test_non_strings_pass_through_untouched() -> None:
    resolved = interpolate_env({"n": 5, "flag": True, "none": None}, env={})
    assert resolved == {"n": 5, "flag": True, "none": None}


def test_a_default_is_used_when_the_variable_is_absent() -> None:
    assert interpolate_env("${SOC_MISSING:-fallback}", env={}) == "fallback"


def test_a_value_from_the_environment_is_marked_as_resolved() -> None:
    resolved = interpolate_env(
        {"a": "${A}", "b": "${MISSING:-written_in_the_file}"}, env={"A": "x"}
    )
    assert isinstance(resolved["a"], EnvResolved)
    assert not isinstance(resolved["b"], EnvResolved)
    assert not isinstance(interpolate_env("plain text", env={}), EnvResolved)


def test_a_missing_reference_names_the_variables_and_nothing_else() -> None:
    with pytest.raises(ConfigError, match="SOC_ALPHA, SOC_BETA") as excinfo:
        interpolate_env("https://soc.example/${SOC_BETA}/${SOC_ALPHA}", env={})
    assert SYNTHETIC_SECRET not in str(excinfo.value)


def test_interpolation_reads_the_process_environment_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOC_FROM_PROCESS", SYNTHETIC_SECRET)
    assert interpolate_env("${SOC_FROM_PROCESS}") == SYNTHETIC_SECRET


# -- the literal-credential guard -----------------------------------------


def test_a_secret_supplied_by_reference_loads_and_is_wrapped() -> None:
    """The documented flow: ``${VAR}`` in the file, value in the environment.

    Interpolation happens before validation, so the guard has to be able to tell a resolved
    credential from a pasted one — otherwise every correct config is refused.
    """
    resolved = interpolate_env(
        {"client_secret": "${SOC_ENTRA_CLIENT_SECRET}"},
        env={"SOC_ENTRA_CLIENT_SECRET": SYNTHETIC_SECRET},
    )
    options = source_options(resolved)
    secret = options["client_secret"]
    assert isinstance(secret, SecretStr)
    assert secret.get_secret_value() == SYNTHETIC_SECRET


def test_a_pasted_credential_is_refused() -> None:
    with pytest.raises(ConfigError, match="looks like a literal credential"):
        source_options({"client_secret": SYNTHETIC_SECRET})


def test_a_fallback_written_in_the_file_is_refused_too() -> None:
    # Assembled at runtime: the repository's own secret scanner is right to refuse a
    # credential-shaped default in a checked-in file, so the fixture builds it here.
    reference = "${SOC_KEY:-" + "fallback-text-from-the-file" + "}"
    resolved = interpolate_env({"api_key": reference}, env={})
    with pytest.raises(ConfigError, match="literal credential"):
        source_options(resolved)


@pytest.mark.parametrize("key", ["api_key", "apikey", "AWS.secret_key", "Bearer_Token", "password"])
def test_every_known_credential_key_is_guarded(key: str) -> None:
    with pytest.raises(ConfigError):
        source_options({key: SYNTHETIC_SECRET})


def test_an_ordinary_option_holding_text_is_not_guarded() -> None:
    options = source_options({"tenant_domain": "contoso.example"})
    assert options["tenant_domain"] == "contoso.example"


def test_an_empty_credential_option_is_left_alone() -> None:
    """``${VAR:-}`` on an unset variable yields "": nothing to leak, nothing to refuse."""
    options = source_options({"client_secret": ""})
    assert options["client_secret"] == ""


# -- structure validation --------------------------------------------------


def test_minimal_config_loads_with_defaults() -> None:
    config = parse_config(MINIMAL)
    assert config.pipeline.batch_size == 200
    assert config.retry.max_attempts >= 1
    assert config.version == 1


def test_an_unknown_key_is_a_refused_option_not_a_typo_nobody_notices() -> None:
    with pytest.raises(ConfigError, match="Extra inputs are not permitted"):
        parse_config({"sources": MINIMAL["sources"], "destination": []})


def test_an_unknown_key_inside_a_source_is_located_precisely() -> None:
    raw = {"sources": [{"id": "demo", "type": "sample_jsonl", "polling": 5}], "destinations": []}
    with pytest.raises(ConfigError, match=r"sources\.0\.polling"):
        parse_config(raw)


@pytest.mark.parametrize("bad_id", ["Demo", "-demo", "demo source", "", "d" * 65])
def test_identifiers_are_lowercase_scoped_and_bounded(bad_id: str) -> None:
    with pytest.raises(ConfigError, match="not a lowercase id"):
        parse_config({"sources": [{"id": bad_id, "type": "sample_jsonl"}]})


def test_duplicate_ids_are_refused_per_kind() -> None:
    raw = {
        "sources": [
            {"id": "demo", "type": "sample_jsonl"},
            {"id": "demo", "type": "sample_jsonl"},
        ]
    }
    with pytest.raises(ConfigError, match="duplicate source id"):
        parse_config(raw)


def test_routing_to_an_unknown_destination_is_refused() -> None:
    raw = {
        "sources": [{"id": "demo", "type": "sample_jsonl", "destinations": ["nope"]}],
        "destinations": [{"id": "sink", "type": "sink"}],
    }
    with pytest.raises(ConfigError, match=r"routes to unknown destination\(s\): \['nope'\]"):
        parse_config(raw)


def test_a_config_with_no_enabled_source_is_refused() -> None:
    raw = {
        "sources": [{"id": "demo", "type": "sample_jsonl", "enabled": False}],
        "destinations": [{"id": "sink", "type": "sink"}],
    }
    with pytest.raises(ConfigError, match="no enabled sources"):
        parse_config(raw)


def test_a_config_that_delivers_nothing_is_refused() -> None:
    raw = {
        "sources": [{"id": "demo", "type": "sample_jsonl"}],
        "destinations": [{"id": "sink", "type": "sink", "enabled": False}],
    }
    with pytest.raises(ConfigError, match="read events and deliver nothing"):
        parse_config(raw)


def test_an_explicit_empty_destination_list_is_refused() -> None:
    """``destinations: []`` means "route nowhere", which is never what a reader meant."""
    raw = {
        "sources": [{"id": "demo", "type": "sample_jsonl", "destinations": []}],
        "destinations": [{"id": "sink", "type": "sink"}],
    }
    with pytest.raises(ConfigError, match="empty destination list"):
        parse_config(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("poll_interval_seconds", 0),
        ("poll_interval_seconds", 100_000),
        ("batch_size", 0),
        ("max_pages_per_cycle", 0),
        ("shutdown_grace_seconds", -1),
        ("dedup_window", 0),
        ("log_level", "verbose"),
        ("log_format", "yaml"),
    ],
)
def test_pipeline_settings_are_bounded(field: str, value: Any) -> None:
    with pytest.raises(ConfigError):
        parse_config({"pipeline": {field: value}, **MINIMAL})


def test_destination_severity_floor_is_on_the_ecs_scale() -> None:
    with pytest.raises(ConfigError):
        parse_config({"destinations": [{"id": "hive", "type": "sink", "severity_min": 100}]})


@pytest.mark.parametrize("rpm", [0, -5])
def test_a_rate_limit_has_to_be_a_positive_quota(rpm: float) -> None:
    with pytest.raises(ConfigError):
        parse_config(
            {"sources": [{"id": "demo", "type": "sample_jsonl", "requests_per_minute": rpm}]}
        )


def test_a_rendered_error_lists_every_problem() -> None:
    with pytest.raises(ConfigError, match=r"\(2 problem\(s\)\)") as excinfo:
        parse_config(
            {
                "pipeline": {"batch_size": 0},
                "sources": [{"id": "Demo", "type": "sample_jsonl"}],
            }
        )
    message = str(excinfo.value)
    assert "pipeline.batch_size" in message
    assert "sources.0.id" in message


# -- lookups used by the runner -------------------------------------------


def test_helpers_fall_back_to_the_pipeline_wide_settings() -> None:
    config = parse_config(MINIMAL)
    source = config.sources[0]
    destination = config.destinations[0]
    assert config.retry_policy_for(source) is config.retry
    assert config.batch_size_for(source) == config.pipeline.batch_size
    assert config.destinations_for(source) == [destination]
    assert config.state_path("demo").name == "demo.json"
    assert config.dead_letter_path("demo").name == "demo.jsonl"


def test_per_item_overrides_win() -> None:
    raw = {
        "pipeline": {"batch_size": 50},
        "retry": {"max_attempts": 4},
        "sources": [{"id": "demo", "type": "sample_jsonl", "batch_size": 7}],
        "destinations": [{"id": "sink", "type": "sink", "retry": {"max_attempts": 9}}],
    }
    config = parse_config(raw)
    assert config.batch_size_for(config.sources[0]) == 7
    assert config.batch_size_for(config.destinations[0]) == 50
    assert config.retry_policy_for(config.destinations[0]).max_attempts == 9
    assert config.retry_policy_for(config.sources[0]).max_attempts == 4


def test_routing_selects_the_named_enabled_destinations_only() -> None:
    raw = {
        "sources": [{"id": "demo", "type": "sample_jsonl", "destinations": ["sink", "hive"]}],
        "destinations": [
            {"id": "sink", "type": "sink"},
            {"id": "hive", "type": "sink", "enabled": False},
            {"id": "other", "type": "sink"},
        ],
    }
    config = parse_config(raw)
    assert [item.id for item in config.enabled_destinations()] == ["sink", "other"]
    assert [item.id for item in config.destinations_for(config.sources[0])] == ["sink"]
    assert [item.id for item in config.enabled_sources()] == ["demo"]


# -- the secret-free summary ----------------------------------------------


def test_describe_publishes_option_names_never_option_values() -> None:
    resolved = interpolate_env(
        {
            "sources": [{"id": "entra", "type": "entra_id", "options": {"client_secret": "${S}"}}],
            "destinations": [{"id": "sink", "type": "sink"}],
        },
        env={"S": SYNTHETIC_SECRET},
    )
    summary = parse_config(resolved).describe()
    assert summary["sources"][0]["option_keys"] == ["client_secret"]
    assert SYNTHETIC_SECRET not in json.dumps(summary)
    assert str(SecretStr(SYNTHETIC_SECRET)) not in json.dumps(summary)


def test_describe_summarises_the_pipeline_and_thresholds() -> None:
    raw = {
        "pipeline": {"poll_interval_seconds": 3, "batch_size": 9},
        "sources": [{"id": "demo", "type": "sample_jsonl"}],
        "destinations": [{"id": "hive", "type": "sink", "severity_min": 80}],
    }
    summary = parse_config(raw).describe()
    assert summary["pipeline"]["poll_interval_seconds"] == 3
    assert summary["pipeline"]["batch_size"] == 9
    assert summary["destinations"][0]["severity_min"] == 80
    assert "retry" in summary and "redaction" in summary


# -- load_config -----------------------------------------------------------


def test_load_config_reads_a_file_with_references_from_the_environment(
    tmp_path: Path,
) -> None:
    path = write_yaml(
        tmp_path / "config.yaml",
        {
            "sources": [{"id": "entra", "type": "entra_id", "options": {"client_secret": "${S}"}}],
            "destinations": [{"id": "sink", "type": "sink"}],
        },
    )
    config = load_config(path, env={"S": SYNTHETIC_SECRET})
    assert isinstance(config.sources[0].options["client_secret"], SecretStr)


def test_load_config_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "absent.yaml", env={})


def test_load_config_reports_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("sources: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(path, env={})


def test_load_config_reports_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ConfigError, match="is empty"):
        load_config(path, env={})


def test_load_config_reports_a_document_that_is_not_a_mapping(tmp_path: Path) -> None:
    path = write_yaml(tmp_path / "list.yaml", ["-a", "-b"])
    with pytest.raises(ConfigError, match="mapping at the top level"):
        load_config(path, env={})


def test_load_config_reports_a_file_that_is_not_utf8_text(tmp_path: Path) -> None:
    path = tmp_path / "binary.yaml"
    path.write_bytes(b"sources: \xff\xfe\x00\x01")
    with pytest.raises(ConfigError, match="cannot read configuration file"):
        load_config(path, env={})


def test_the_shipped_configs_are_valid() -> None:
    """``config/example.yaml`` and ``config/demo.yaml`` are documentation: they must load."""
    repo_root = Path(__file__).resolve().parents[2]
    for name in ("example.yaml", "demo.yaml"):
        path = repo_root / "config" / name
        if not path.exists():  # pragma: no cover - these files ship with the repo
            pytest.skip(f"config/{name} is not present in this checkout")
        config = load_config(path, env={})
        assert config.enabled_sources(), name
        assert config.enabled_destinations(), name
        PipelineSettings()  # the defaults these files rely on are constructible
