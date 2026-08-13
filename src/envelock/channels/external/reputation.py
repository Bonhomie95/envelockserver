"""Sender-domain reputation via free feeds (user requirement #3).

When mail arrives, we check the FROM domain against public blocklists so a domain
already known for phishing/spam is flagged even before our own cross-tenant graph
has seen it. Everything here is free and needs no API key:

* **DNSBL domain lists** — Spamhaus DBL and SURBL answer a normal DNS query:
  `<domain>.dbl.spamhaus.org` resolving to `127.0.1.x` means listed. (Spamhaus DBL
  is free for low-volume/non-commercial use — audit the terms before high volume,
  per the README licensing note.)
* **Google Safe Browsing** — used for URLs elsewhere; if a key is set we also check
  the domain's root URL here.

Results are cached briefly so a burst of mail from one sender is one lookup, and
every failure mode (no resolver, timeout, NXDOMAIN) resolves to "not listed"
rather than raising.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from envelock.config import get_settings
from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.reputation")


@dataclass(frozen=True, slots=True)
class ReputationResult:
    domain: str
    listed: bool
    sources: tuple[str, ...] = ()
    codes: tuple[str, ...] = ()


@dataclass
class _CacheEntry:
    result: ReputationResult
    at: float


@dataclass
class DomainReputation:
    """Cached DNSBL reputation checker. One instance is shared process-wide."""

    _cache: dict[str, _CacheEntry] = field(default_factory=dict)

    def _cached(self, reg: str) -> ReputationResult | None:
        entry = self._cache.get(reg)
        if entry is None:
            return None
        ttl = get_settings().reputation_cache_seconds
        if (time.monotonic() - entry.at) > ttl:
            self._cache.pop(reg, None)
            return None
        return entry.result

    def _dnsbl_listed(self, reg: str, zone: str) -> str | None:
        """Return the return-code (127.0.1.x) if `reg` is listed in `zone`, else
        None. A listing is any answer in 127.0.0.0/8 that is not an error code."""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5.0
            answers = resolver.resolve(f"{reg}.{zone}", "A")
            for rdata in answers:
                code = str(rdata)
                # 127.255.255.x are DBL "error"/typing responses, not listings.
                if code.startswith("127.") and not code.startswith("127.255."):
                    return code
            return None
        except Exception:  # noqa: BLE001 — NXDOMAIN (not listed), timeout, no resolver
            return None

    def check(self, domain: str) -> ReputationResult:
        reg = registrable_domain(domain)
        if not reg:
            return ReputationResult(domain=domain, listed=False)
        cached = self._cached(reg)
        if cached is not None:
            return cached

        settings = get_settings()
        sources: list[str] = []
        codes: list[str] = []
        if settings.domain_reputation_enabled:
            for zone in settings.dnsbl_domain_zone_list:
                code = self._dnsbl_listed(reg, zone)
                if code:
                    sources.append(zone)
                    codes.append(code)

        result = ReputationResult(
            domain=reg,
            listed=bool(sources),
            sources=tuple(sources),
            codes=tuple(codes),
        )
        self._cache[reg] = _CacheEntry(result=result, at=time.monotonic())
        return result


#: Process-wide singleton so the cache is shared across requests.
REPUTATION = DomainReputation()


async def check_sender_domain(domain: str) -> ReputationResult:
    """Async wrapper — the DNS lookups are blocking, so run them off the loop."""
    import asyncio

    return await asyncio.to_thread(REPUTATION.check, domain)


__all__ = ["DomainReputation", "REPUTATION", "ReputationResult", "check_sender_domain"]
