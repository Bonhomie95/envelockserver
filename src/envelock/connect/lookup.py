"""MX lookup and the connection plan an IT team actually follows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from envelock.connect.advisor import (
    Method,
    Provider,
    identify,
    imap_host_guess,
)
from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import ProtectionLevel
from envelock.util.domains import registrable_domain

try:
    import dns.asyncresolver
    import dns.exception

    _DNS = True
except ImportError:  # pragma: no cover
    _DNS = False


@dataclass(frozen=True, slots=True)
class ConnectionPlan:
    domain: str
    mx_hosts: tuple[str, ...]
    detected: bool
    provider: Provider
    imap_host: str | None
    imap_port: int
    recommended: Method
    alternatives: tuple[Method, ...]
    dmarc: str | None
    spf: bool


async def _resolve(domain: str, rdtype: str) -> list[str]:
    if not _DNS:
        return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        answer = await resolver.resolve(domain, rdtype)
    except Exception:
        # Any DNS failure means "unknown", never an error page — the advisor
        # still returns the universal methods.
        return []
    return [r.to_text() for r in answer]


async def build_plan(domain: str) -> ConnectionPlan:
    reg = registrable_domain(domain) or domain.strip().lower()

    mx_raw, txt_root, txt_dmarc = await asyncio.gather(
        _resolve(reg, "MX"),
        _resolve(reg, "TXT"),
        _resolve(f"_dmarc.{reg}", "TXT"),
    )

    # MX answers arrive as "10 mail.example.com." — keep the host, drop priority.
    mx_hosts = tuple(
        part.split()[-1].rstrip(".")
        for part in mx_raw
        if part.split()
    )

    provider = identify(list(mx_hosts))
    detected = provider.id != "generic" and bool(mx_hosts)

    dmarc_policy: str | None = None
    for record in txt_dmarc:
        lowered = record.lower()
        if "v=dmarc1" in lowered:
            for token in lowered.replace('"', "").split(";"):
                if token.strip().startswith("p="):
                    dmarc_policy = token.strip()[2:].strip()

    spf = any("v=spf1" in r.lower() for r in txt_root)

    methods = provider.methods
    return ConnectionPlan(
        domain=reg,
        mx_hosts=mx_hosts,
        detected=detected,
        provider=provider,
        imap_host=imap_host_guess(provider, reg, list(mx_hosts)),
        imap_port=provider.imap_port,
        recommended=methods[0],
        alternatives=methods[1:],
        dmarc=dmarc_policy,
        spf=spf,
    )


def method_payload(method: Method, *, with_sensor: bool = True) -> dict:
    """Serialise a method, including the protection level it yields.

    The level is computed from the capability model rather than written down, so
    it cannot drift from what the mailbox will actually get (PRD P4).
    """
    sources = {method.source}
    if with_sensor:
        from envelock.core.enums import SourceMechanism

        sources.add(SourceMechanism.CLIENT_SENSOR)

    caps = capabilities_for(frozenset(sources))
    level: ProtectionLevel = protection_level(caps)

    return {
        "id": method.id,
        "name": method.name,
        "tier": int(method.tier),
        "effort": method.effort,
        "who": method.who,
        "steps": list(method.steps),
        "remediation": method.remediation,
        "identity_from": method.identity_from,
        "protection_level": level.value,
    }


def plan_payload(plan: ConnectionPlan) -> dict:
    return {
        "domain": plan.domain,
        "detected": plan.detected,
        "mx_hosts": list(plan.mx_hosts),
        "provider": {
            "id": plan.provider.id,
            "name": plan.provider.name,
            "aliases": list(plan.provider.aliases),
            "notes": plan.provider.notes,
        },
        "imap": {"host": plan.imap_host, "port": plan.imap_port},
        "dns": {"dmarc_policy": plan.dmarc, "spf_present": plan.spf},
        "recommended": method_payload(plan.recommended),
        "alternatives": [method_payload(m) for m in plan.alternatives],
    }
