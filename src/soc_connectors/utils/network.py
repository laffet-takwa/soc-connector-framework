"""Input validation for addresses and ports, plus the masking used by redaction.

Log data is untrusted input: a firewall record can carry an empty, bracketed, zone-suffixed
or outright malformed address. These helpers return ``None`` for the optional variants and
raise ``MalformedEventError`` for the required ones, so a bad field never reaches a
destination as a wrongly-typed value that the index then rejects.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from soc_connectors.exceptions import MalformedEventError

_PORT_MIN = 1
_PORT_MAX = 65535


def optional_ip(value: Any) -> str | None:
    """Best-effort address: returns ``None`` for missing or malformed input."""
    if value is None:
        return None
    text = str(value).strip().strip("\"'")
    if not text or text.lower() in {"none", "null", "-", "unknown", "(null)"}:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    # Strip an IPv6 zone id such as fe80::1%eth0 before parsing.
    text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def require_ip(value: Any, *, field_name: str) -> str:
    ip = optional_ip(value)
    if ip is None:
        raise MalformedEventError(f"{field_name}={value!r} is not an IP address", field=field_name)
    return ip


def optional_port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not _PORT_MIN <= port <= _PORT_MAX:
        return None
    return port


def mask_ip(ip: str) -> str:
    """Coarsen an address to its /24 (IPv4) or /64 (IPv6) network.

    Used when a deployment wants correlation by subnet but not the exact host address —
    the compromise between "no data" and "personal data" that source systems often need.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(address, ipaddress.IPv4Address):
        packed = bytearray(address.packed)
        packed[3] = 0
        return str(ipaddress.IPv4Address(bytes(packed)))
    packed = bytearray(address.packed)
    for index in range(8, 16):
        packed[index] = 0
    return str(ipaddress.IPv6Address(bytes(packed)))


def is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False
