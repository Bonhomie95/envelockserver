"""Group D — brand and domain protection (D1–D7).

Requires no mailbox access at all, which is why Guard is free forever and why
this runs before a prospect signs up (PRD S12).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from envelock.core.enums import AlertTier
from envelock.util.domains import registrable_domain

try:
    import dns.asyncresolver

    _DNS = True
except ImportError:  # pragma: no cover
    _DNS = False


# ── D5 / D6 — own-domain authentication posture ──────────────────────────────
@dataclass(frozen=True, slots=True)
class DmarcPosture:
    domain: str
    spf_present: bool
    spf_record: str | None
    dkim_selectors_found: tuple[str, ...]
    dmarc_present: bool
    dmarc_policy: str | None
    dmarc_pct: int
    rua_configured: bool
    rua_points_to_us: bool

    @property
    def protected(self) -> bool:
        """Only `quarantine` or `reject` actually stops a spoof."""
        return self.dmarc_policy in ("quarantine", "reject") and self.dmarc_pct == 100

    @property
    def tier(self) -> AlertTier:
        if not self.dmarc_present or not self.spf_present:
            return AlertTier.HIGH
        if not self.protected:
            return AlertTier.MEDIUM
        return AlertTier.LOW

    @property
    def summary(self) -> str:
        if not self.dmarc_present:
            return (
                f"{self.domain} has no DMARC record. Anyone can send mail that "
                f"appears to come from you."
            )
        if self.dmarc_policy == "none":
            return (
                f"{self.domain} publishes DMARC but with p=none, which reports "
                f"spoofing without stopping it."
            )
        if self.dmarc_pct < 100:
            return f"{self.domain} enforces DMARC on only {self.dmarc_pct}% of mail."
        return f"{self.domain} is protected by DMARC p={self.dmarc_policy}."

    @property
    def recommendations(self) -> list[str]:
        out: list[str] = []
        if not self.spf_present:
            out.append("Publish an SPF record listing every service that sends as you.")
        if not self.dmarc_present:
            out.append("Publish a DMARC record at _dmarc, starting with p=none to observe.")
        elif self.dmarc_policy == "none":
            out.append("Move DMARC to p=quarantine, then p=reject once reports are clean.")
        elif self.dmarc_pct < 100:
            out.append(f"Raise DMARC pct from {self.dmarc_pct} to 100.")
        if not self.dkim_selectors_found:
            out.append("Enable DKIM signing with your mail provider.")
        if not self.rua_points_to_us:
            out.append("Add our RUA address so we can show you who is spoofing you.")
        return out


_COMMON_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail")


async def _txt(name: str) -> list[str]:
    if not _DNS:
        return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        answer = await resolver.resolve(name, "TXT")
    except Exception:
        return []
    return [r.to_text().strip('"').replace('" "', "") for r in answer]


async def _has_record(name: str, rdtype: str) -> bool:
    if not _DNS:
        return False
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        await resolver.resolve(name, rdtype)
    except Exception:
        return False
    return True


async def check_posture(domain: str, *, our_rua: str = "rua@envelock.io") -> DmarcPosture:
    """D5 — costs one DNS round trip and needs no customer integration."""
    reg = registrable_domain(domain) or domain

    root_txt, dmarc_txt = await asyncio.gather(_txt(reg), _txt(f"_dmarc.{reg}"))
    selectors = await asyncio.gather(
        *[_has_record(f"{s}._domainkey.{reg}", "TXT") for s in _COMMON_SELECTORS]
    )

    spf = next((r for r in root_txt if r.lower().startswith("v=spf1")), None)
    dmarc = next((r for r in dmarc_txt if r.lower().startswith("v=dmarc1")), None)

    policy, pct, rua = None, 100, None
    if dmarc:
        for token in dmarc.split(";"):
            key, _, value = token.strip().partition("=")
            key, value = key.strip().lower(), value.strip()
            if key == "p":
                policy = value.lower()
            elif key == "pct" and value.isdigit():
                pct = int(value)
            elif key == "rua":
                rua = value

    return DmarcPosture(
        domain=reg,
        spf_present=spf is not None,
        spf_record=spf,
        dkim_selectors_found=tuple(
            s for s, found in zip(_COMMON_SELECTORS, selectors, strict=True) if found
        ),
        dmarc_present=dmarc is not None,
        dmarc_policy=policy,
        dmarc_pct=pct,
        rua_configured=rua is not None,
        rua_points_to_us=bool(rua and our_rua.split("@")[-1] in rua),
    )


# ── D6 — DMARC aggregate report parsing ──────────────────────────────────────
@dataclass(frozen=True, slots=True)
class SpoofSource:
    source_ip: str
    count: int
    spf_pass: bool
    dkim_pass: bool
    header_from: str

    @property
    def is_spoof(self) -> bool:
        return not (self.spf_pass or self.dkim_pass)


def parse_dmarc_report(xml_text: str) -> list[SpoofSource]:
    """One TXT record reveals who is spoofing you, worldwide. Cheapest
    high-signal feature we have (PRD D6)."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)  # noqa: S314 — trusted RUA feed, not user input
    except ET.ParseError:
        return []

    out: list[SpoofSource] = []
    for record in root.findall(".//record"):
        row = record.find("row")
        policy = record.find("row/policy_evaluated")
        identifiers = record.find("identifiers")
        if row is None or policy is None:
            continue
        out.append(
            SpoofSource(
                source_ip=(row.findtext("source_ip") or "").strip(),
                count=int(row.findtext("count") or 0),
                spf_pass=(policy.findtext("spf") or "").lower() == "pass",
                dkim_pass=(policy.findtext("dkim") or "").lower() == "pass",
                header_from=(
                    identifiers.findtext("header_from") if identifiers is not None else ""
                )
                or "",
            )
        )
    return out


def summarise_spoofing(sources: list[SpoofSource]) -> dict:
    spoofs = [s for s in sources if s.is_spoof]
    total = sum(s.count for s in sources)
    spoofed = sum(s.count for s in spoofs)
    return {
        "total_messages": total,
        "spoofed_messages": spoofed,
        "spoof_rate": round(spoofed / total, 4) if total else 0.0,
        "distinct_spoof_sources": len(spoofs),
        "top_sources": [
            {"ip": s.source_ip, "count": s.count, "header_from": s.header_from}
            for s in sorted(spoofs, key=lambda s: -s.count)[:10]
        ],
        "tier": AlertTier.HIGH if spoofed > 0 else AlertTier.LOW,
    }


# ── D4 — live weaponisation probing ──────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class DomainProbe:
    domain: str
    has_mx: bool
    has_a: bool
    mx_hosts: tuple[str, ...]

    @property
    def armed(self) -> bool:
        """MX configured means it can send mail as the brand — that is the alert."""
        return self.has_mx


async def probe_domain(domain: str) -> DomainProbe:
    reg = registrable_domain(domain) or domain
    if not _DNS:
        return DomainProbe(reg, False, False, ())

    async def _mx() -> list[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 4.0
            answer = await resolver.resolve(reg, "MX")
        except Exception:
            return []
        return [str(r).split()[-1].rstrip(".") for r in answer]

    mx, has_a = await asyncio.gather(_mx(), _has_record(reg, "A"))
    return DomainProbe(reg, bool(mx), has_a, tuple(mx))


# ── D7 — takedown workflow ───────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class TakedownPacket:
    """Turns an alert into a resolution."""

    candidate: str
    protected: str
    technique: str
    registrar_abuse: str | None
    host_abuse: str | None
    evidence: dict
    subject: str
    body: str


def build_takedown(
    *,
    candidate: str,
    protected: str,
    technique: str,
    registrar: str | None = None,
    registrar_abuse: str | None = None,
    host_abuse: str | None = None,
    registered_at: datetime | None = None,
    has_mx: bool = False,
) -> TakedownPacket:
    observed = (registered_at or datetime.now(UTC)).date().isoformat()
    body = (
        f"To whom it may concern,\n\n"
        f"The domain {candidate} was registered on {observed} and closely "
        f"imitates {protected}, a domain we protect on behalf of its owner.\n\n"
        f"Technique observed: {technique.replace('_', ' ')}.\n"
        f"Mail exchange records: "
        f"{'configured — the domain can send mail' if has_mx else 'none observed'}.\n\n"
        f"We believe this registration exists to impersonate {protected} in "
        f"business email compromise attacks, and we request suspension under "
        f"your abuse policy.\n\n"
        f"Evidence is attached. We are available for any further information.\n\n"
        f"Envelock Brand Protection"
    )
    return TakedownPacket(
        candidate=candidate,
        protected=protected,
        technique=technique,
        registrar_abuse=registrar_abuse,
        host_abuse=host_abuse,
        evidence={
            "candidate": candidate,
            "protected": protected,
            "technique": technique,
            "registrar": registrar,
            "registered_at": registered_at.isoformat() if registered_at else None,
            "has_mx": has_mx,
            "observed_at": datetime.now(UTC).isoformat(),
        },
        subject=f"Abuse report: {candidate} impersonating {protected}",
        body=body,
    )


def newly_registered(registered_at: datetime | None, *, days: int = 30) -> bool:
    if registered_at is None:
        return False
    return datetime.now(UTC) - registered_at < timedelta(days=days)
