"""Group C — the remaining identity and mailbox-integrity detections.

Travel analysis runs on *our own users'* sessions, where the identity provider or
the client sensor gives us a real client IP. Inbound sender IPs are stripped by
most providers, so A10 (infrastructure change) covers counterparties instead
(PRD §7.2, §7.3).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier, IdentityEventKind
from envelock.detections.base import DetectionContext, FindingResult, register
from envelock.util.domains import registrable_domain

_RULES = frozenset({Capability.READ_SERVER_RULES})
_SESSIONS = frozenset({Capability.READ_SESSIONS})
_MFA = frozenset({Capability.READ_MFA_STATE})

#: Fastest plausible commercial travel, including airport time.
MAX_TRAVEL_KMH = 900.0
#: Below this, geolocation error dominates and the result is noise.
MIN_TRAVEL_KM = 500.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))


@dataclass(frozen=True)
class _C3DelegateChange:
    service: str = "C3"
    requires: frozenset[Capability] = _RULES

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.DELEGATE_CHANGED:
            return []
        target = (ev.after or "").lower()
        external = "@" in target and registrable_domain(target) not in ctx.owned_domains
        return [
            FindingResult(
                service="C3",
                tier=AlertTier.CRITICAL if external else AlertTier.HIGH,
                score=95 if external else 65,
                summary=(
                    f"Mailbox access was granted to {ev.after}"
                    + (" — an address outside your organisation." if external else ".")
                ),
                evidence={"delegate": ev.after, "external": external, "before": ev.before},
            )
        ]


@dataclass(frozen=True)
class _C5SignatureTampering:
    """An altered signature block is a quiet way to redirect payments."""

    service: str = "C5"
    requires: frozenset[Capability] = frozenset({Capability.READ_OUTBOUND})

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.SIGNATURE_CHANGED:
            return []

        from envelock.util.payments import extract_bank_identifiers

        before_ids = {b.identifier for b in extract_bank_identifiers(ev.before or "")}
        after_ids = {b.identifier for b in extract_bank_identifiers(ev.after or "")}
        added = after_ids - before_ids

        if added:
            return [
                FindingResult(
                    service="C5",
                    tier=AlertTier.CRITICAL,
                    score=95,
                    summary=(
                        "Bank details in the mail signature were changed. Every "
                        "message this mailbox sends now carries the new account."
                    ),
                    evidence={"added_identifiers": sorted(added)},
                )
            ]
        return [
            FindingResult(
                service="C5",
                tier=AlertTier.LOW,
                score=15,
                summary="Mail signature was changed.",
                evidence={"before": (ev.before or "")[:200], "after": (ev.after or "")[:200]},
            )
        ]


@dataclass(frozen=True)
class _C7ImpossibleTravel:
    service: str = "C7"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        prev = ctx.previous_session
        if ev is None or prev is None:
            return []
        if ev.kind not in (IdentityEventKind.SIGN_IN, IdentityEventKind.SESSION_START):
            return []

        net = ev.network
        if net.latitude is None or net.longitude is None:
            return []
        if prev.latitude is None or prev.longitude is None:
            return []
        # A VPN exit is a location claim, not a location — C9 handles it.
        if net.is_vpn or net.is_proxy or net.is_tor:
            return []

        distance = haversine_km(prev.latitude, prev.longitude, net.latitude, net.longitude)
        if distance < MIN_TRAVEL_KM:
            return []

        hours = max((ev.occurred_at - prev.at).total_seconds() / 3600, 1 / 60)
        speed = distance / hours
        if speed <= MAX_TRAVEL_KMH:
            return []

        return [
            FindingResult(
                service="C7",
                tier=AlertTier.HIGH,
                score=85,
                summary=(
                    f"Sign-in from {net.country or 'an unknown country'} "
                    f"{int(distance):,}km away, {hours:.1f}h after the previous "
                    f"sign-in from {prev.country or 'elsewhere'} — not physically possible."
                ),
                evidence={
                    "distance_km": round(distance),
                    "hours": round(hours, 2),
                    "implied_kmh": round(speed),
                    "from_country": prev.country,
                    "to_country": net.country,
                    "ip": net.ip,
                },
            )
        ]


@dataclass(frozen=True)
class _C8LocationChange:
    """Possible but unusual relocation. Deliberately lower tier than C7, or it
    becomes noise and the channel gets muted."""

    service: str = "C8"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        prev = ctx.previous_session
        if ev is None or prev is None:
            return []
        if ev.kind not in (IdentityEventKind.SIGN_IN, IdentityEventKind.SESSION_START):
            return []

        net = ev.network
        if not net.country or not prev.country or net.country == prev.country:
            return []
        # C7 already covers the impossible case at a higher tier.
        if net.latitude is not None and prev.latitude is not None:
            distance = haversine_km(
                prev.latitude, prev.longitude or 0, net.latitude, net.longitude or 0
            )
            hours = max((ev.occurred_at - prev.at).total_seconds() / 3600, 1 / 60)
            if distance / hours > MAX_TRAVEL_KMH:
                return []

        asn_changed = net.asn is not None and prev.asn is not None and net.asn != prev.asn
        return [
            FindingResult(
                service="C8",
                tier=AlertTier.MEDIUM,
                score=40,
                summary=(
                    f"Sign-in from {net.country}, previously {prev.country}."
                ),
                evidence={
                    "from_country": prev.country,
                    "to_country": net.country,
                    "asn_changed": asn_changed,
                    "asn_name": net.asn_name,
                },
            )
        ]


@dataclass(frozen=True)
class _C9NetworkClassification:
    """VPN-ness is itself the signal — we never claim to see through it."""

    service: str = "C9"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None:
            return []
        if ev.kind not in (IdentityEventKind.SIGN_IN, IdentityEventKind.SESSION_START):
            return []

        net = ev.network
        kinds = [
            name
            for name, flag in (
                ("Tor", net.is_tor),
                ("hosting/datacenter", net.is_hosting),
                ("proxy", net.is_proxy),
                ("VPN", net.is_vpn),
            )
            if flag
        ]
        if not kinds:
            return []

        prev = ctx.previous_session
        first_time = prev is not None and prev.asn != net.asn
        tier = AlertTier.HIGH if (net.is_tor or net.is_hosting) else AlertTier.MEDIUM

        return [
            FindingResult(
                service="C9",
                tier=tier,
                score=70 if tier is AlertTier.HIGH else 40,
                summary=(
                    f"Sign-in through {kinds[0]}. The real location cannot be "
                    f"established — treat the network itself as the signal."
                ),
                evidence={
                    "classification": kinds,
                    "asn": net.asn,
                    "asn_name": net.asn_name,
                    "claimed_country": net.country,
                    "new_network": first_time,
                },
            )
        ]


@dataclass(frozen=True)
class _C10NewDevice:
    service: str = "C10"
    requires: frozenset[Capability] = frozenset({Capability.READ_DEVICE_FINGERPRINT})

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or not ev.device.fingerprint:
            return []
        if ev.kind not in (IdentityEventKind.SIGN_IN, IdentityEventKind.SESSION_START):
            return []
        if ev.device.fingerprint in ctx.known_devices:
            return []
        # First device ever seen is enrolment, not an anomaly.
        if not ctx.known_devices:
            return []

        net = ev.network
        risky = bool(net.is_vpn or net.is_hosting or net.is_tor)
        return [
            FindingResult(
                service="C10",
                tier=AlertTier.MEDIUM if risky else AlertTier.LOW,
                score=45 if risky else 20,
                summary=(
                    "First sign-in from a new device"
                    + (
                        f" ({ev.device.browser or ev.device.mail_client})"
                        if ev.device.browser or ev.device.mail_client
                        else ""
                    )
                    + (" on an anonymising network." if risky else ".")
                ),
                evidence={
                    "fingerprint": ev.device.fingerprint,
                    "browser": ev.device.browser,
                    "os": ev.device.os,
                    "mail_client": ev.device.mail_client,
                    "known_devices": len(ctx.known_devices),
                },
            )
        ]


@dataclass(frozen=True)
class _C13MfaPosture:
    """Preventive rather than detective — cheap, and high value."""

    service: str = "C13"
    requires: frozenset[Capability] = _MFA

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ctx.mfa_enabled is not False:
            return []
        if ev.kind not in (IdentityEventKind.SIGN_IN, IdentityEventKind.MFA_CHANGED):
            return []
        return [
            FindingResult(
                service="C13",
                tier=AlertTier.MEDIUM,
                score=50,
                summary=(
                    "This mailbox has no multi-factor authentication. A stolen "
                    "password is all an attacker needs."
                ),
                evidence={"mfa_enabled": False},
            )
        ]


@dataclass(frozen=True)
class _C14CounterpartyTravel:
    """Only possible where the counterparty is also an Envelock tenant — which
    is exactly why the cross-tenant graph (E8) matters (PRD §7.3)."""

    service: str = "C14"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.SIGN_IN:
            return []
        if not ev.counterparty_shared:
            return []
        prev = ctx.previous_session
        net = ev.network
        if prev is None or net.latitude is None or prev.latitude is None:
            return []

        distance = haversine_km(
            prev.latitude, prev.longitude or 0, net.latitude, net.longitude or 0
        )
        hours = max((ev.occurred_at - prev.at).total_seconds() / 3600, 1 / 60)
        if distance < MIN_TRAVEL_KM or distance / hours <= MAX_TRAVEL_KMH:
            return []

        return [
            FindingResult(
                service="C14",
                tier=AlertTier.HIGH,
                score=80,
                summary=(
                    "A counterparty who also uses Envelock shows impossible "
                    "travel — their account may be compromised."
                ),
                evidence={
                    "distance_km": round(distance),
                    "hours": round(hours, 2),
                    "shared_graph": True,
                },
            )
        ]


C3 = register(_C3DelegateChange())
C5 = register(_C5SignatureTampering())
C7 = register(_C7ImpossibleTravel())
C8 = register(_C8LocationChange())
C9 = register(_C9NetworkClassification())
C10 = register(_C10NewDevice())
C13 = register(_C13MfaPosture())
C14 = register(_C14CounterpartyTravel())
