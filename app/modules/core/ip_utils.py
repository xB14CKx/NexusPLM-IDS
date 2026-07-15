"""IP address validation and private/reserved range detection."""
from __future__ import annotations
import ipaddress


def parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP string, stripping ports if present. Returns None if invalid."""
    if not ip:
        return None
    # Strip IPv6 brackets and port, e.g. [::1]:8080 → ::1
    stripped = ip.strip()
    if stripped.startswith("["):
        stripped = stripped.split("]")[0].lstrip("[")
    # Strip IPv4 port, e.g. 1.2.3.4:8080 → 1.2.3.4
    elif ":" in stripped and stripped.count(":") == 1:
        stripped = stripped.split(":")[0]
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        return None


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    return parse_ip(ip) is not None


def is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is in a private, loopback, link-local, or other
    non-routable range that should never be auto-blocked.

    Covers:
      - Loopback:    127.0.0.0/8, ::1
      - Private:     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
      - Link-local:  169.254.0.0/16, fe80::/10
      - CGNAT:       100.64.0.0/10  (shared address space, ISP carrier-grade NAT)
      - Localhost aliases / unspecified: 0.0.0.0, ::
    """
    addr = parse_ip(ip)
    if addr is None:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def normalize_ip(ip: str) -> str:
    """
    Normalize an IP string to its canonical form (strips ports, expands IPv6).
    Returns the original string unchanged if it cannot be parsed.
    """
    addr = parse_ip(ip)
    return str(addr) if addr is not None else ip
