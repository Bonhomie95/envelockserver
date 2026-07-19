"""Channel 3 workers — Certificate Transparency, zone files, RDAP, DMARC RUA.

All free, all public infrastructure, and none of it needs mailbox access. That
is why Guard is free forever and why this runs before a prospect signs up.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from envelock.channels.external.lookalike import match_stream_entry
from envelock.config import get_settings
from envelock.util.domains import registrable_domain


@dataclass(frozen=True, slots=True)
class DomainObservation:
    domain: str
    source: str
    observed_at: datetime
    protected_domain: str | None = None
    technique: str | None = None
    similarity: float | None = None

    @property
    def is_match(self) -> bool:
        return self.protected_domain is not None


@dataclass
class WatcherStats:
    observed: int = 0
    matched: int = 0
    errors: int = 0
    reconnects: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def payload(self) -> dict:
        return {
            "observed": self.observed,
            "matched": self.matched,
            "match_rate": round(self.matched / self.observed, 6) if self.observed else 0.0,
            "errors": self.errors,
            "reconnects": self.reconnects,
            "started_at": self.started_at.isoformat(),
        }


class CertTransparencyWatcher:
    """D2 — the primary sensor.

    Catches a domain the moment it gets a certificate, which is the moment
    before it is used. The match path is the hot loop: it runs on every
    certificate issued worldwide, so it does no I/O and allocates little.
    """

    def __init__(
        self,
        *,
        protected_domains: frozenset[str] = frozenset(),
        on_match: Callable[[DomainObservation], None] | None = None,
        url: str | None = None,
    ) -> None:
        self.protected = set(protected_domains)
        self.on_match = on_match
        self.url = url or get_settings().certstream_url
        self.stats = WatcherStats()
        self._running = False

    def watch_domain(self, domain: str) -> None:
        reg = registrable_domain(domain)
        if reg:
            self.protected.add(reg)

    def unwatch_domain(self, domain: str) -> None:
        self.protected.discard(registrable_domain(domain))

    def handle_certificate(self, all_domains: list[str]) -> list[DomainObservation]:
        """One CT entry. Returns only matches, never the firehose."""
        now = datetime.now(UTC)
        out: list[DomainObservation] = []
        protected = frozenset(self.protected)

        for raw in all_domains:
            self.stats.observed += 1
            candidate = raw.lstrip("*.").lower()
            match = match_stream_entry(candidate, protected)
            if match is None:
                continue
            protected_domain, technique, similarity = match
            self.stats.matched += 1
            observation = DomainObservation(
                domain=registrable_domain(candidate),
                source="cert_transparency",
                observed_at=now,
                protected_domain=protected_domain,
                technique=technique,
                similarity=similarity,
            )
            out.append(observation)
            if self.on_match:
                self.on_match(observation)
        return out

    async def run(self, stream: AsyncIterator[dict] | None = None) -> None:
        """`stream` is injectable so the watcher is testable without a network."""
        self._running = True
        source = stream if stream is not None else self._connect()
        try:
            async for message in source:
                if not self._running:
                    break
                try:
                    leaf = (message.get("data") or {}).get("leaf_cert") or {}
                    domains = leaf.get("all_domains") or []
                    if domains:
                        self.handle_certificate(domains)
                except Exception:
                    self.stats.errors += 1
        except asyncio.CancelledError:
            raise

    async def _connect(self) -> AsyncIterator[dict]:
        """Live certstream. The public feed has no SLA, so reconnection is
        expected rather than exceptional."""
        try:
            import websockets
        except ImportError:
            return
        while self._running:
            try:
                async with websockets.connect(self.url) as socket:
                    async for raw in socket:
                        with contextlib.suppress(json.JSONDecodeError):
                            yield json.loads(raw)
            except Exception:
                self.stats.reconnects += 1
                await asyncio.sleep(min(2**self.stats.reconnects, 60))

    def stop(self) -> None:
        self._running = False


class ZoneFileWatcher:
    """D3 — ICANN CZDS gTLD zone files.

    Free with an application, and precisely what commercial NRD feeds resell.
    ccTLDs are not in CZDS, which is a gap in our target markets — CT logs fill
    it, since any domain issued a certificate appears regardless of TLD.
    """

    CZDS_API = "https://czds-api.icann.org"

    def __init__(self, *, protected_domains: frozenset[str] = frozenset()) -> None:
        settings = get_settings()
        self.username = settings.czds_username
        self.password = (
            settings.czds_password.get_secret_value() if settings.czds_password else None
        )
        self.protected = set(protected_domains)
        self.stats = WatcherStats()

    @property
    def configured(self) -> bool:
        return bool(self.username and self.password)

    def scan_zone(self, lines: list[str]) -> list[DomainObservation]:
        """Zone lines are `domain. TTL IN NS host.` — we only need the name."""
        now = datetime.now(UTC)
        protected = frozenset(self.protected)
        seen: set[str] = set()
        out: list[DomainObservation] = []

        for line in lines:
            parts = line.split()
            if not parts:
                continue
            candidate = parts[0].rstrip(".").lower()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            self.stats.observed += 1
            match = match_stream_entry(candidate, protected)
            if match is None:
                continue
            protected_domain, technique, similarity = match
            self.stats.matched += 1
            out.append(
                DomainObservation(
                    domain=registrable_domain(candidate),
                    source="zone_file",
                    observed_at=now,
                    protected_domain=protected_domain,
                    technique=technique,
                    similarity=similarity,
                )
            )
        return out

    def status(self) -> dict:
        return {
            "source": "czds",
            "configured": self.configured,
            "reason": None
            if self.configured
            else "CZDS credentials not set — CT logs still cover this ground",
            "covers": "gTLDs only; ccTLDs come from Certificate Transparency",
        }


class DmarcReportWatcher:
    """D6 — one TXT record reveals who is spoofing you, worldwide."""

    def __init__(self) -> None:
        self.reports_processed = 0
        self.spoof_sources: dict[str, int] = {}

    def ingest(self, xml_text: str, *, domain: str) -> dict:
        from envelock.channels.external.brand import parse_dmarc_report, summarise_spoofing

        sources = parse_dmarc_report(xml_text)
        self.reports_processed += 1
        for s in sources:
            if s.is_spoof:
                self.spoof_sources[s.source_ip] = self.spoof_sources.get(s.source_ip, 0) + s.count
        summary = summarise_spoofing(sources)
        summary["domain"] = domain
        return summary


class RdapClient:
    """Free, standardised, and the correct primary — raw WHOIS is the legacy
    fallback, not the reverse. Registrant identity is usually redacted
    post-GDPR, but creation date is the field we actually need.
    """

    def __init__(self) -> None:
        self.bootstrap = get_settings().rdap_bootstrap_url
        self._cache: dict[str, dict] = {}

    async def lookup(self, domain: str) -> dict | None:
        reg = registrable_domain(domain)
        if reg in self._cache:
            return self._cache[reg]
        try:
            import httpx
        except ImportError:
            return None
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                response = await client.get(f"{self.bootstrap.rstrip('/')}/domain/{reg}")
            if response.status_code != 200:
                return None
            data = response.json()
        except Exception:
            return None

        registered_at = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                registered_at = event.get("eventDate")
                break

        result = {
            "domain": reg,
            "registered_at": registered_at,
            "registrar": next(
                (
                    e.get("vcardArray", [None, []])[1][1][3]
                    for e in data.get("entities", [])
                    if "registrar" in (e.get("roles") or [])
                    and len(e.get("vcardArray", [None, []])[1]) > 1
                ),
                None,
            ),
            "status": data.get("status", []),
        }
        self._cache[reg] = result
        return result

    def age_days(self, registered_at: str | None) -> int | None:
        if not registered_at:
            return None
        try:
            when = datetime.fromisoformat(registered_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (datetime.now(UTC) - when).days
