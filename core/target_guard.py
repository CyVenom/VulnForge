"""
VulnForge Target Guard
Decides whether a scan target falls inside a blocked/reserved range.

The old check only looked at targets that were literal IPv4/IPv6 addresses, so
a hostname (or a URL) whose DNS record points into a blocked range slipped
straight through. This module extracts the host from whatever the user typed,
resolves it, and checks every address it resolves to.

Limits worth knowing:
  * DNS is resolved at check time. A hostile DNS server could answer
    differently later (DNS rebinding), so this is a safety net against
    mistakes, not a defence against a determined attacker.
  * A name that does not resolve is not blocked here; the scan will fail on
    its own because there is nothing to connect to.
"""
import ipaddress
import socket
from typing import Callable
from urllib.parse import urlsplit

Resolver = Callable[[str], list[str]]


def extract_host(target: str) -> str:
    """Return the bare host from a hostname, IP, host:port or URL."""
    t = (target or "").strip()
    if not t:
        return ""
    bare = t[1:-1] if t.startswith("[") and t.endswith("]") else t
    try:  # plain IPv4/IPv6 literal (urlsplit would mangle an unbracketed IPv6)
        ipaddress.ip_address(bare)
        return bare
    except ValueError:
        pass
    try:
        parts = urlsplit(t if "://" in t else "//" + t)
        return (parts.hostname or "").rstrip(".")
    except ValueError:
        return ""


def resolve_all(host: str) -> list[str]:
    """Every IPv4/IPv6 address the OS resolver returns for host (empty on failure)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0].split("%")[0] for info in infos})


def blocked_reason(target: str, blocked_ranges: list[str], resolver: Resolver = resolve_all) -> str | None:
    """
    Return a short explanation if target (or anything it resolves to) lies in a
    blocked range, otherwise None. An invalid range in the config raises
    ValueError rather than being skipped, so a typo cannot silently turn a
    block off.
    """
    try:
        networks = [ipaddress.ip_network(r, strict=False) for r in blocked_ranges]
    except ValueError as exc:
        raise ValueError(f"Invalid entry in authorization.blocked_ranges: {exc}") from exc
    if not networks:
        return None

    host = extract_host(target)
    if not host:
        return None

    try:
        addresses = [ipaddress.ip_address(host)]
        via = ""
    except ValueError:
        addresses = []
        for text in resolver(host):
            try:
                addresses.append(ipaddress.ip_address(text))
            except ValueError:
                continue
        via = f"{host} resolves to "

    for addr in addresses:
        candidates = [addr]
        mapped = getattr(addr, "ipv4_mapped", None)  # ::ffff:a.b.c.d is really IPv4
        if mapped is not None:
            candidates.append(mapped)
        for candidate in candidates:
            for net in networks:
                if candidate in net:
                    return f"{via}{addr}, inside blocked range {net}"
    return None
