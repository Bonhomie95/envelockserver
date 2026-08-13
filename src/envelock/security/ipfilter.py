"""Source-IP allowlisting for the forwarding ingest (PRD §5.4 / security).

A per-tenant token in the RCPT address proves *which* tenant a forwarded copy is
for, but not that the sender is that tenant's real mail gateway — anyone who
learns a token could inject mail to poison detection or fabricate alerts. Pinning
the source IP/CIDR closes that: only the customer's known forwarders (or our
inbound-parse provider) are accepted.

An empty allowlist means "allow any" — correct for local development, unsafe for
production. The ingest logs a warning at startup when it runs open.
"""

from __future__ import annotations

import ipaddress
import logging

from envelock.config import get_settings

logger = logging.getLogger("envelock.ipfilter")


def _networks(entries: list[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("ignoring invalid ingest allowlist entry: %s", entry)
    return nets


def ingest_ip_allowed(ip: str | None) -> bool:
    """Is `ip` permitted to submit forwarded mail? Open when no allowlist is set."""
    allow = get_settings().ingest_allowed_ip_list
    if not allow:
        return True  # dev / not yet pinned — the token still gates the tenant
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _networks(allow))


__all__ = ["ingest_ip_allowed"]
