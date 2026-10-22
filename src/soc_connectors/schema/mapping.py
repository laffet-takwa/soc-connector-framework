"""Flat source fields to nested ECS, in one place.

Sources hand over flat, oddly named data: Fortinet sends ``srcip``, CloudTrail sends
``sourceIPAddress``, an iptables line sends ``SRC``. A connector's normalizer should be a
table of those correspondences, not fifty keyword arguments, so this module turns a mapping of
``ecs path -> value`` into the nested structure :class:`EcsEvent` validates.

Two rules keep this honest:
* empty values are dropped instead of written as ``""``, so ``exclude_none`` serialisation
  does not publish fields that carry nothing;
* an unsettable path (``source.ip`` under an already-set ``source`` that is a scalar) is an
  error, because silently discarding a mapped field is how a connector stops reporting
  something important and nobody notices for a month.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.schema.ecs_models import EcsEvent, build_event

#: Field sets ECS represents as a list of scalars; a repeated source value accumulates here
#: instead of overwriting.
REPEATED_PATHS = frozenset(
    {"event.category", "event.type", "related.user", "related.ip", "host.ip", "user.roles"}
)

#: Keys that are legitimately bare (no dotted path) at the top of an ECS document.
TOP_LEVEL_KEYS = frozenset({"@timestamp", "message", "tags", "labels", "raw"})

_MISSING = object()


def set_dotted(document: dict[str, Any], path: str, value: Any) -> None:
    """Write ``value`` at ``path`` ("source.ip"), creating intermediate objects as needed."""
    parts = [part for part in path.split(".") if part]
    if not parts:
        raise MalformedEventError(f"cannot map to empty ECS path {path!r}", field=path)
    target: Any = document
    for part in parts[:-1]:
        if not isinstance(target, dict):
            raise MalformedEventError(
                f"cannot map {path!r}: {part} is already a {type(target).__name__}", field=path
            )
        existing = target.get(part, _MISSING)
        if existing is _MISSING:
            target[part] = {}
        elif not isinstance(existing, dict):
            raise MalformedEventError(
                f"cannot map {path!r}: {part} is already {existing!r}", field=path
            )
        target = target[part]
    if not isinstance(target, dict):
        raise MalformedEventError(f"cannot map {path!r}: parent is not an object", field=path)
    leaf = parts[-1]
    if path in REPEATED_PATHS:
        additions = list(value) if isinstance(value, (list, tuple, set, frozenset)) else [value]
        merged = list(target.get(leaf, []))
        for item in additions:
            if item not in merged:
                merged.append(item)
        target[leaf] = merged
        return
    target[leaf] = value


def prune(document: dict[str, Any]) -> dict[str, Any]:
    """Drop empty strings, containers and ``None`` so unmapped fields stay absent."""
    pruned: dict[str, Any] = {}
    for key, value in document.items():
        if isinstance(value, Mapping):
            nested = prune(dict(value))
            if nested:
                pruned[key] = nested
            continue
        if value is None or value == "" or (isinstance(value, (list, tuple)) and not value):
            continue
        pruned[key] = value
    return pruned


def from_flat(
    values: Mapping[str, Any],
    *,
    aliases: Mapping[str, str] | None = None,
    defaults: Mapping[str, Any] | None = None,
) -> EcsEvent:
    """Build an :class:`EcsEvent` from ``ecs path -> value`` pairs.

    ``aliases`` maps source field names onto ECS paths; ``defaults`` supplies constant ECS
    paths a source cannot know (``cloud.provider``, ``event.module``, ``event.dataset``).

    Priority is ``defaults`` -> ``aliases`` -> ``values``: a default is the framework's guess
    about what the source could not say, so a source that does report the field keeps its own
    value, and a field consumed by an alias is not re-read as an ECS path.
    """
    document: dict[str, Any] = {}
    for ecs_path, value in (defaults or {}).items():
        if value is None or value == "":
            continue
        set_dotted(document, ecs_path, value)
    aliased = set(aliases or {})
    for source_name, ecs_path in (aliases or {}).items():
        if source_name in values and values[source_name] not in (None, ""):
            set_dotted(document, ecs_path, values[source_name])
    for ecs_path, value in values.items():
        if ecs_path in aliased:
            continue
        if "." not in ecs_path and ecs_path not in TOP_LEVEL_KEYS:
            raise MalformedEventError(
                f"{ecs_path!r} is not an ECS path; use an aliases table for source field names",
                field=ecs_path,
            )
        if value is None or value == "":
            continue
        set_dotted(document, ecs_path, value)
    return build_event(**prune(document))
