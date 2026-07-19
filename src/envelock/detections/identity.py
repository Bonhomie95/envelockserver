"""Group C — mailbox and identity integrity.

Most of this group runs on capabilities the client sensor supplies, which is what
lets ISP-mail customers have it at all (PRD §7.7).
"""

from __future__ import annotations

from dataclasses import dataclass

from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier, IdentityEventKind
from envelock.detections.base import DetectionContext, FindingResult, register
from envelock.util.domains import registrable_domain

_RULES = frozenset({Capability.READ_SERVER_RULES})
_SESSIONS = frozenset({Capability.READ_SESSIONS})
_FLAGS = frozenset({Capability.READ_FLAGS})
_OAUTH = frozenset({Capability.READ_OAUTH_GRANTS})


@dataclass(frozen=True)
class _C1ExternalForward:
    """The single most reliable indicator of an active takeover."""

    service: str = "C1"
    requires: frozenset[Capability] = _RULES

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.RULE_CHANGED:
            return []
        target = (ev.after or "").lower()
        if "@" not in target:
            return []
        destination = registrable_domain(target)
        if not destination or destination in ctx.owned_domains:
            return []

        return [
            FindingResult(
                service="C1",
                tier=AlertTier.CRITICAL,
                score=100,
                summary=(
                    f"A rule was created forwarding mail to {destination}, "
                    f"outside your organisation."
                ),
                evidence={
                    "rule": ev.target,
                    "destination": destination,
                    "raw": ev.after,
                },
            )
        ]


@dataclass(frozen=True)
class _C2RuleTampering:
    service: str = "C2"
    requires: frozenset[Capability] = _RULES

    _SUSPICIOUS = ("delete", "trash", "junk", "archive", "mark as read")
    _FINANCE = ("invoice", "payment", "bank", "wire", "remit", "swift", "iban")

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.RULE_CHANGED:
            return []
        blob = f"{ev.target or ''} {ev.after or ''}".lower()
        hides = any(word in blob for word in self._SUSPICIOUS)
        finance = any(word in blob for word in self._FINANCE)
        if not (hides and finance):
            return []
        return [
            FindingResult(
                service="C2",
                tier=AlertTier.CRITICAL,
                score=95,
                summary=(
                    "A rule was created that hides finance-related mail — the "
                    "standard way an attacker conceals invoice fraud."
                ),
                evidence={"rule": ev.target, "definition": ev.after},
            )
        ]


@dataclass(frozen=True)
class _C4OAuthGrant:
    """Survives password resets and MFA. Critical by construction."""

    service: str = "C4"
    requires: frozenset[Capability] = _OAUTH

    _MAIL_SCOPES = ("mail.read", "mail.readwrite", "imap.accessasuser", "https://mail.google.com")

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.OAUTH_GRANT:
            return []
        scopes = (ev.after or "").lower()
        if not any(scope in scopes for scope in self._MAIL_SCOPES):
            return []
        return [
            FindingResult(
                service="C4",
                tier=AlertTier.CRITICAL,
                score=100,
                summary=(
                    f'An application ("{ev.target}") was granted permission to read '
                    f"this mailbox. This survives password changes and MFA."
                ),
                evidence={"application": ev.target, "scopes": ev.after},
            )
        ]


@dataclass(frozen=True)
class _C6Concurrency:
    """Note: >1 session is normal (phone + laptop + webmail), and on shared
    mailboxes it is expected (PRD S9). Alert only on *anomalous* concurrency."""

    service: str = "C6"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.SESSION_START:
            return []
        # Concurrency below the mailbox's known-user count is unremarkable.
        if ctx.active_sessions <= 1:
            return []

        net = ev.network
        anomalous = bool(net.is_vpn or net.is_hosting or net.is_tor)
        if not anomalous:
            return []

        return [
            FindingResult(
                service="C6",
                tier=AlertTier.HIGH,
                score=80,
                summary=(
                    f"A concurrent session opened from {net.country or 'an unknown country'} "
                    f"on an anonymising or hosting network while other sessions were active."
                ),
                evidence={
                    "ip": net.ip,
                    "country": net.country,
                    "asn": net.asn,
                    "asn_name": net.asn_name,
                    "is_vpn": net.is_vpn,
                    "is_hosting": net.is_hosting,
                    "concurrent_sessions": ctx.active_sessions,
                    "browser": ev.device.browser,
                    "mail_client": ev.device.mail_client,
                },
            )
        ]


@dataclass(frozen=True)
class _C11SilentAccess:
    """PRD C11 — solved better than originally specified.

    A `\\Seen` flag flipping with **no sensor-attested session at that moment**
    means someone else is in the mailbox. Cleaner than the M365 audit log, and it
    needs no E5 licence.
    """

    service: str = "C11"
    requires: frozenset[Capability] = _FLAGS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind is not IdentityEventKind.FLAG_CHANGED:
            return []
        if ev.sensor_attested or ctx.active_sessions > 0:
            return []
        if ev.after != "seen":
            return []

        return [
            FindingResult(
                service="C11",
                tier=AlertTier.CRITICAL,
                score=95,
                summary=(
                    "A message was marked as read while none of your devices were "
                    "signed in. Someone else may be in this mailbox — change the "
                    "password now."
                ),
                evidence={
                    "message": ev.target,
                    "occurred_at": ev.occurred_at.isoformat(),
                    "active_sessions": ctx.active_sessions,
                },
            )
        ]


@dataclass(frozen=True)
class _C12CredentialChange:
    service: str = "C12"
    requires: frozenset[Capability] = _SESSIONS

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        ev = ctx.identity
        if ev is None or ev.kind not in (
            IdentityEventKind.CREDENTIAL_CHANGED,
            IdentityEventKind.MFA_CHANGED,
        ):
            return []
        removed = ev.kind is IdentityEventKind.MFA_CHANGED and "remov" in (ev.after or "").lower()
        return [
            FindingResult(
                service="C12",
                tier=AlertTier.CRITICAL if removed else AlertTier.HIGH,
                score=95 if removed else 70,
                summary=(
                    "Multi-factor authentication was removed from this account."
                    if removed
                    else "Account credentials or recovery details were changed."
                ),
                evidence={"kind": ev.kind.value, "before": ev.before, "after": ev.after},
            )
        ]


C1 = register(_C1ExternalForward())
C2 = register(_C2RuleTampering())
C4 = register(_C4OAuthGrant())
C6 = register(_C6Concurrency())
C11 = register(_C11SilentAccess())
C12 = register(_C12CredentialChange())
