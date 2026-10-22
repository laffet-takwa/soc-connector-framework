"""File primitives: atomic replacement and append-only JSONL.

Checkpoint files are rewritten in place and read back by the next process, so a torn
write is worse than a crash — it produces a state file that looks valid but is not.
Every overwrite here goes through a temporary file, ``fsync`` and ``os.replace``, which is
atomic on both NTFS and ext4 for a same-directory rename.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def fsync_directory(path: Path) -> None:
    """Make a rename durable where the OS allows it; silently skip where it does not.

    Windows has no directory fsync, and failing a checkpoint write for it would be worse
    than the very small window it protects against.
    """
    try:
        handle = os.open(path, getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    ensure_directory(path.parent)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary).replace(path)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)
    fsync_directory(path.parent)


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def read_text(path: Path, *, encoding: str = "utf-8") -> str | None:
    try:
        return path.read_text(encoding=encoding)
    except FileNotFoundError:
        return None


def append_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> int:
    """Append newline-delimited JSON and flush it to the device.

    The dead-letter file is the last copy of an event that never reached a destination, so
    ``flush`` plus ``fsync`` here are the point rather than paranoia: without them a power
    loss can silently drop exactly the records that matter for the post-mortem.
    """
    ensure_directory(path.parent)
    written = 0
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, default=str, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            written += 1
        handle.flush()
        os.fsync(handle.fileno())
    return written


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0
