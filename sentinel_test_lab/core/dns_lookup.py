"""DNS record lookups through one injectable resolver."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception

# (nameservers, port). None = the system resolver. Tests point this at a local DNS server.
_override: tuple[list[str], int] | None = None


def use_nameservers(nameservers: list[str] | None, port: int = 53) -> None:
    """Route all lookups to specific DNS servers; ``None`` restores the system resolver."""
    global _override
    _override = (list(nameservers), port) if nameservers else None


def _resolver(timeout_s: float) -> dns.asyncresolver.Resolver:
    if _override is None:
        resolver = dns.asyncresolver.Resolver()
    else:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers, resolver.port = _override
    resolver.lifetime = timeout_s
    resolver.timeout = min(timeout_s, 3.0)
    return resolver


async def lookup(name: str, record_type: str, timeout_s: float = 5.0) -> list[str]:
    """Record values as text (TXT values unquoted and joined). Empty list when there is no answer."""
    try:
        answer = await _resolver(timeout_s).resolve(name, record_type)
    except (dns.exception.DNSException, OSError):
        return []
    if record_type.upper() == "TXT":
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]
    return [record.to_text().rstrip(".") for record in answer]
