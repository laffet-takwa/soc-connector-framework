"""Field redaction and payload size limits.

Security logs are full of other people's activity: usernames, source addresses, request
bodies that may contain a password a user typed into the wrong console field. Redaction runs
at the last moment before a document leaves the process — to a destination or to the
dead-letter file — so the framework can keep full fidelity where it is authorised and
minimum-necessary data where it is not, from one switch.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from soc_connectors.utils.network import mask_ip

MASK = "***"
TRUNCATED_KEY = "truncated_keys"

#: Keys whose value is an address, wherever they appear in a document.
IP_KEYS = frozenset({"ip", "nat_ip"})


class RedactionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    fields: list[str] = Field(
        default_factory=list,
        description="Dotted ECS paths to mask or drop, e.g. ['user.name', 'cloud.account.id'].",
    )
    mode: Literal["mask", "drop"] = "mask"
    ip_mode: Literal["keep", "mask_subnet", "drop"] = "keep"
    keep_raw: bool = Field(
        default=True,
        description="Whether the untouched source record is kept in the `raw` field.",
    )
    max_raw_bytes: int = Field(default=8192, ge=128, le=262_144)

    def normalized_fields(self) -> list[list[str]]:
        paths = []
        for dotted in self.fields:
            parts = [part for part in dotted.split(".") if part]
            if parts:
                paths.append(parts)
        return paths


def _apply_path(container: dict[str, Any], parts: list[str], mode: str) -> None:
    """Mask or drop one dotted path, then remove the ancestors a drop left empty.

    ``cloud.account.id`` dropped must not publish ``"cloud": {"account": {}}``: an empty
    object says "this event has a cloud account, contents unknown", which is worse than
    saying nothing.
    """
    ancestors: list[tuple[dict[str, Any], str]] = []
    target: Any = container
    for part in parts[:-1]:
        if not isinstance(target, dict) or part not in target:
            return
        ancestors.append((target, part))
        target = target[part]
    if not isinstance(target, dict) or parts[-1] not in target:
        return
    if mode == "drop":
        del target[parts[-1]]
        for parent, key in reversed(ancestors):
            if isinstance(parent[key], dict) and not parent[key]:
                del parent[key]
            else:
                break
    else:
        target[parts[-1]] = MASK


def _apply_ip_policy(item: Any, settings: RedactionSettings) -> Any:
    """Mask or drop an address field, including a list of addresses such as ``related.ip``."""
    if isinstance(item, list):
        return [_apply_ip_policy(entry, settings) for entry in item]
    if settings.ip_mode == "mask_subnet" and isinstance(item, str):
        return mask_ip(item)
    return item


def _walk_ip_fields(value: Any, settings: RedactionSettings) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in IP_KEYS and settings.ip_mode != "keep":
                if settings.ip_mode == "drop":
                    continue
                result[key] = _apply_ip_policy(item, settings)
                continue
            walked = _walk_ip_fields(item, settings)
            if isinstance(walked, (dict, list)) and not walked:
                continue
            result[key] = walked
        return result
    if isinstance(value, list):
        return [_walk_ip_fields(item, settings) for item in value]
    return value


def _truncate_raw(raw: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Drop the largest values until the payload fits, recording what was dropped.

    Keeping a truncated record beats dropping the whole event: the timestamp, action and
    principal usually survive, and `truncated_keys` says exactly what is missing.
    """
    trimmed = dict(raw)
    dropped: list[str] = []
    size = _size(trimmed)
    while size > max_bytes and trimmed:
        largest = max(trimmed, key=lambda key: _size({key: trimmed[key]}))
        dropped.append(largest)
        del trimmed[largest]
        size = _size(trimmed)
    if dropped:
        trimmed[TRUNCATED_KEY] = sorted(dropped)
    return trimmed


def _size(payload: Any) -> int:
    return len(json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8"))


def _redact_raw(raw: dict[str, Any], settings: RedactionSettings) -> dict[str, Any]:
    """Apply this policy to the untouched source copy as well as to the shaped fields.

    A document whose ECS ``user.name`` is masked while its ``raw`` still holds the username is
    not redacted at all — the copy sits two keys away. A source also names its fields its own
    way, so both the nested path and the literal dotted key (``user.name`` as one flat key) are
    matched here.
    """
    prepared = copy.deepcopy(raw)
    for parts in settings.normalized_fields():
        _apply_path(prepared, parts, settings.mode)
        dotted = ".".join(parts)
        if dotted in prepared:
            if settings.mode == "drop":
                del prepared[dotted]
            else:
                prepared[dotted] = MASK
    for key in list(prepared):
        if key.rsplit(".", 1)[-1] in IP_KEYS and settings.ip_mode != "keep":
            if settings.ip_mode == "drop":
                del prepared[key]
            else:
                prepared[key] = _apply_ip_policy(prepared[key], settings)
    return _truncate_raw(_walk_ip_fields(prepared, settings), settings.max_raw_bytes)


def redact_document(document: Mapping[str, Any], settings: RedactionSettings) -> dict[str, Any]:
    """Apply field paths, address policy and the raw-payload budget to one document.

    The document is copied first: the same event fans out to several destinations and may
    also be dead-lettered, so redacting one copy must not edit the others.
    """
    result: dict[str, Any] = {
        key: copy.deepcopy(value) for key, value in document.items() if key != "raw"
    }
    raw = document.get("raw")

    for parts in settings.normalized_fields():
        _apply_path(result, parts, settings.mode)

    result = _walk_ip_fields(result, settings)

    if isinstance(raw, Mapping) and settings.keep_raw:
        result["raw"] = _redact_raw(dict(raw), settings)
    return result
