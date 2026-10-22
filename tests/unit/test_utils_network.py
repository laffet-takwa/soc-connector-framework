"""Address and port validation — log fields are untrusted input."""

from __future__ import annotations

from typing import Any

import pytest

from soc_connectors.exceptions import MalformedEventError
from soc_connectors.utils.network import is_ipv4, mask_ip, optional_ip, optional_port, require_ip

pytestmark = pytest.mark.unit

V4 = "198.51.100.7"
V6 = "2001:db8:dead:beef:1234:5678:9abc:def0"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (V4, V4),
        (f" {V4} ", V4),
        (f'"{V4}"', V4),
        (f"'{V4}'", V4),
        (V6, V6),
        ("fe80::1%eth0", "fe80::1"),
        (f"[{V6}]", V6),
    ],
)
def test_addresses_are_normalised(value: Any, expected: str) -> None:
    assert optional_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [None, "", "  ", "none", "NULL", "-", "unknown", "(null)", "app.example.com", "10.0.0.999"],
)
def test_missing_or_malformed_addresses_become_none(value: Any) -> None:
    assert optional_ip(value) is None


def test_require_ip_names_the_field_and_the_value() -> None:
    assert require_ip(V4, field_name="source.ip") == V4
    with pytest.raises(MalformedEventError) as exc_info:
        require_ip("not-an-ip", field_name="source.ip")
    assert exc_info.value.field == "source.ip"
    assert "not-an-ip" in str(exc_info.value)


@pytest.mark.parametrize("value", ["80", 80, " 80 "])
def test_valid_ports(value: Any) -> None:
    assert optional_port(value) == 80


@pytest.mark.parametrize(("value", "expected"), [(1, 1), (65535, 65535), ("65535", 65535)])
def test_port_boundaries_are_inclusive(value: Any, expected: int) -> None:
    assert optional_port(value) == expected


@pytest.mark.parametrize("value", [None, "", "http", 0, -1, 65536, True, False, "abc", 80.0])
def test_ports_outside_the_valid_range_become_none(value: Any) -> None:
    assert optional_port(value) is None


@pytest.mark.parametrize(
    ("address", "masked"),
    [
        ("198.51.100.7", "198.51.100.0"),
        ("192.0.2.210", "192.0.2.0"),
        ("2001:db8:dead:beef:1234:5678:9abc:def0", "2001:db8:dead:beef::"),
        ("fe80::1", "fe80::"),
    ],
)
def test_masking_keeps_the_subnet_and_drops_the_host(address: str, masked: str) -> None:
    assert mask_ip(address) == masked


def test_leading_zeros_are_ambiguous_not_repaired() -> None:
    """ipaddress rejects them because ``10.0.0.01`` may be octal; so do we."""
    assert optional_ip("198.51.100.007") is None


def test_masking_leaves_a_non_address_alone() -> None:
    assert mask_ip("host-42") == "host-42"


def test_is_ipv4() -> None:
    assert is_ipv4(V4)
    assert not is_ipv4(V6)
    assert not is_ipv4("nope")
