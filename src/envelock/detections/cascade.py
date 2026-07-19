"""Attachment and URL cascades — free layers first, metered last (PRD §12.12).

The fall-through rate is the single number that predicts COGS, so it is metered
at every layer rather than inferred.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum

from envelock.config import get_settings


class Layer(IntEnum):
    CACHE = 0
    STATIC = 1
    REPUTATION = 2
    DETONATION = 3


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CascadeResult:
    sha256: str
    verdict: Verdict
    layer: Layer
    reasons: tuple[str, ...] = ()
    cost_micros: int = 0

    @property
    def reached_paid_layer(self) -> bool:
        return self.layer >= Layer.REPUTATION


@dataclass
class CascadeMetrics:
    seen: int = 0
    cache_hits: int = 0
    static_resolved: int = 0
    reputation_calls: int = 0
    detonations: int = 0
    cost_micros: int = 0

    @property
    def fallthrough_rate(self) -> float:
        """Target < 5% (PRD §15.4)."""
        return self.detonations / self.seen if self.seen else 0.0

    def payload(self) -> dict:
        return {
            "attachments_seen": self.seen,
            "cache_hits": self.cache_hits,
            "static_resolved": self.static_resolved,
            "reputation_calls": self.reputation_calls,
            "detonations": self.detonations,
            "fallthrough_rate": round(self.fallthrough_rate, 4),
            "target": 0.05,
            "within_target": self.fallthrough_rate <= 0.05,
            "external_cost_micros": self.cost_micros,
        }


class VerdictCache:
    """Layer 0. Shared across tenants and keyed only by hash, so it holds no
    customer data. Clean verdicts expire because clean-today can be
    flagged-tomorrow; malicious verdicts never do."""

    def __init__(self, *, clean_ttl_days: int | None = None) -> None:
        self._ttl = timedelta(
            days=clean_ttl_days or get_settings().attachment_cache_ttl_clean_days
        )
        self._entries: dict[str, tuple[Verdict, datetime]] = {}

    def get(self, sha256: str, *, now: datetime | None = None) -> Verdict | None:
        entry = self._entries.get(sha256)
        if entry is None:
            return None
        verdict, stored_at = entry
        if verdict is Verdict.MALICIOUS:
            return verdict
        if (now or datetime.now(UTC)) - stored_at > self._ttl:
            del self._entries[sha256]
            return None
        return verdict

    def put(self, sha256: str, verdict: Verdict, *, now: datetime | None = None) -> None:
        self._entries[sha256] = (verdict, now or datetime.now(UTC))

    def __len__(self) -> int:
        return len(self._entries)


# ── Layer 1: static triage, free and self-hosted ─────────────────────────────
_EXECUTABLE_MAGIC = {
    b"MZ": "Windows executable",
    b"\x7fELF": "Linux executable",
    b"\xca\xfe\xba\xbe": "Mach-O executable",
}
_RISKY_EXT = (
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".wsf", ".hta", ".lnk", ".iso", ".img", ".vhd", ".ps1", ".msi", ".one",
)
_MACRO_MAGIC = b"\xd0\xcf\x11\xe0"
_PDF_ACTIONS = (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile")


@dataclass(frozen=True, slots=True)
class StaticVerdict:
    verdict: Verdict
    reasons: tuple[str, ...]


def static_triage(
    *, filename: str, payload: bytes, declared_mime: str | None = None
) -> StaticVerdict:
    """YARA and ClamAV plug in here; these checks need no dependency at all and
    already resolve the common cases."""
    name = filename.lower()
    reasons: list[str] = []
    verdict = Verdict.UNKNOWN

    for magic, label in _EXECUTABLE_MAGIC.items():
        if payload.startswith(magic):
            reasons.append(f"{label} content")
            verdict = Verdict.MALICIOUS
            break

    if name.endswith(_RISKY_EXT):
        reasons.append("executable or script extension")
        verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if declared_mime and declared_mime.startswith("image/") and payload[:2] in (b"MZ", b"PK"):
        reasons.append("claims to be an image but is not")
        verdict = Verdict.MALICIOUS

    if payload.startswith(_MACRO_MAGIC) or name.endswith((".docm", ".xlsm", ".pptm")):
        reasons.append("macro-capable Office document")
        verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if payload.startswith(b"%PDF"):
        hits = [a.decode() for a in _PDF_ACTIONS if a in payload[:200_000]]
        if hits:
            reasons.append(f"PDF with active content ({', '.join(hits)})")
            verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if not reasons and payload:
        verdict = Verdict.CLEAN
        reasons.append("no static indicators")

    return StaticVerdict(verdict, tuple(reasons))


_SEVERITY = {Verdict.CLEAN: 0, Verdict.UNKNOWN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


def _severity(v: Verdict) -> int:
    return _SEVERITY[v]


class AttachmentCascade:
    """Layer 0 → 1 → 2 → 3, stopping as soon as a verdict is reached."""

    def __init__(
        self,
        *,
        cache: VerdictCache | None = None,
        detonation_enabled: bool | None = None,
    ) -> None:
        settings = get_settings()
        self.cache = cache or VerdictCache()
        self.detonation_enabled = (
            settings.detonation_enabled if detonation_enabled is None else detonation_enabled
        )
        self.reputation_available = settings.virustotal_api_key is not None
        self.metrics = CascadeMetrics()

    async def analyse(
        self,
        *,
        sha256: str,
        filename: str,
        payload: bytes,
        declared_mime: str | None = None,
        protected_mailbox: bool = True,
    ) -> CascadeResult:
        self.metrics.seen += 1

        cached = self.cache.get(sha256)
        if cached is not None:
            self.metrics.cache_hits += 1
            return CascadeResult(sha256, cached, Layer.CACHE, ("shared verdict cache",))

        static = static_triage(filename=filename, payload=payload, declared_mime=declared_mime)
        if static.verdict in (Verdict.MALICIOUS, Verdict.CLEAN):
            self.metrics.static_resolved += 1
            self.cache.put(sha256, static.verdict)
            return CascadeResult(sha256, static.verdict, Layer.STATIC, static.reasons)

        if self.reputation_available:
            self.metrics.reputation_calls += 1
            # A hash lookup is not a detonation — far cheaper.
            self.metrics.cost_micros += 100
            reputation = await self._reputation(sha256)
            if reputation is not None:
                self.cache.put(sha256, reputation)
                return CascadeResult(
                    sha256, reputation, Layer.REPUTATION, ("hash reputation",), 100
                )

        # Only unknown, risky, Protected-bound files reach the metered layer.
        if self.detonation_enabled and protected_mailbox:
            self.metrics.detonations += 1
            self.metrics.cost_micros += 5000
            verdict = await self._detonate(payload)
            self.cache.put(sha256, verdict)
            return CascadeResult(sha256, verdict, Layer.DETONATION, ("dynamic analysis",), 5000)

        return CascadeResult(
            sha256,
            static.verdict,
            Layer.STATIC,
            static.reasons + ("detonation not enabled",),
        )

    async def _reputation(self, sha256: str) -> Verdict | None:
        """VirusTotal hash lookup. Returns None when the sample is unknown."""
        return None

    async def _detonate(self, payload: bytes) -> Verdict:
        return Verdict.UNKNOWN


# ── URL cascade ──────────────────────────────────────────────────────────────
_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
     "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
)
_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class UrlMetrics:
    checked: int = 0
    free_hits: int = 0
    paid_calls: int = 0

    def payload(self) -> dict:
        return {
            "urls_checked": self.checked,
            "free_resolved": self.free_hits,
            "paid_calls": self.paid_calls,
            "paid_rate": round(self.paid_calls / self.checked, 4) if self.checked else 0.0,
        }


@dataclass(frozen=True, slots=True)
class UrlVerdict:
    url: str
    verdict: Verdict
    source: str
    reasons: tuple[str, ...] = ()


class UrlCascade:
    """Google Safe Browsing is free and is the primary. Redirect unwrapping and
    brand-similarity are entirely self-built."""

    def __init__(self, *, feed_domains: frozenset[str] = frozenset()) -> None:
        settings = get_settings()
        self.safebrowsing = settings.safebrowsing_api_key is not None
        self.urlhaus = settings.urlhaus_enabled
        self.feed_domains = feed_domains
        self.metrics = UrlMetrics()
        self._cache: dict[str, UrlVerdict] = {}

    async def check(self, url: str) -> UrlVerdict:
        if url in self._cache:
            return self._cache[url]

        self.metrics.checked += 1
        from envelock.util.domains import registrable_domain

        host = url.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
        reg = registrable_domain(host)
        reasons: list[str] = []

        if reg in self.feed_domains:
            self.metrics.free_hits += 1
            verdict = UrlVerdict(url, Verdict.MALICIOUS, "threat feed", ("on a threat feed",))
            self._cache[url] = verdict
            return verdict

        if _IP_HOST.match(host):
            reasons.append("bare IP address instead of a hostname")
        if reg in _SHORTENERS:
            reasons.append("link shortener hides the destination")
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            reasons.append("credentials embedded in the URL")

        if reasons:
            self.metrics.free_hits += 1
            verdict = UrlVerdict(url, Verdict.SUSPICIOUS, "static", tuple(reasons))
        elif self.safebrowsing:
            self.metrics.paid_calls += 1
            verdict = UrlVerdict(url, Verdict.UNKNOWN, "safebrowsing", ())
        else:
            verdict = UrlVerdict(url, Verdict.UNKNOWN, "static", ("no reputation source",))

        self._cache[url] = verdict
        return verdict


def rewrite_for_click(url: str, *, token: str, base: str = "https://click.envelock.io") -> str:
    """B2 — links weaponised after delivery are the standard evasion, so the
    destination is re-checked at click time."""
    from urllib.parse import quote

    return f"{base}/{token}?u={quote(url, safe='')}"
