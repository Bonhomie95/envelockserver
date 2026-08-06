"""What each source mechanism can actually do.

This module exists to enforce PRD P4 — *never silently degrade*.

Detections declare the capabilities they require. A mailbox's protection level and
its list of inactive detections are then **derived** from the capabilities its
configured sources provide, rather than maintained by hand in a spreadsheet that
drifts. If a mailbox cannot support a detection, the product says so by
construction.

The mapping below is the executable form of the PRD §4 coverage matrix.
"""

from __future__ import annotations

from enum import StrEnum

from envelock.core.enums import ProtectionLevel, SourceMechanism


class Capability(StrEnum):
    # ── Channel 1 ────────────────────────────────────────────────────────────
    READ_INBOUND = "read_inbound"
    READ_OUTBOUND = "read_outbound"
    """Sent-items visibility. Forwarding lacks it — weakens A9 and A12."""

    READ_HISTORY = "read_history"
    """Backfill for A9 stylometry and A12 baselines (E11)."""

    MODIFY_MESSAGE = "modify_message"
    """Quarantine, claw-back, link rewriting. E2 and B2.

    Forwarding arrives *post-delivery*, so it can never have this. PRD §4 fn.3 —
    the single strongest argument for upgrading a customer from Tier 4 to Tier 3.
    """

    READ_FLAGS = "read_flags"
    """IMAP \\Seen state. Half of C11."""

    # ── Channel 2 ────────────────────────────────────────────────────────────
    READ_SIGNIN_LOGS = "read_signin_logs"
    READ_SESSIONS = "read_sessions"
    READ_DEVICE_FINGERPRINT = "read_device_fingerprint"
    READ_SERVER_RULES = "read_server_rules"
    """C1–C3 at full fidelity.

    IMAP has no concept of server-side rules (PRD §7.4). Tier 3/4 get best-effort
    inference only, and must not claim parity.
    """

    READ_OAUTH_GRANTS = "read_oauth_grants"  # C4
    READ_MFA_STATE = "read_mfa_state"  # C13

    # ── Channel 3 ────────────────────────────────────────────────────────────
    OBSERVE_DOMAIN = "observe_domain"
    OBSERVE_DMARC = "observe_dmarc"


#: Capabilities granted by each mechanism. A mailbox unions the sets of all its
#: configured sources.
MECHANISM_CAPABILITIES: dict[SourceMechanism, frozenset[Capability]] = {
    # ── Channel 1 ────────────────────────────────────────────────────────────
    SourceMechanism.GRAPH_API: frozenset(
        {
            Capability.READ_INBOUND,
            Capability.READ_OUTBOUND,
            Capability.READ_HISTORY,
            Capability.MODIFY_MESSAGE,
            Capability.READ_FLAGS,
            Capability.READ_SERVER_RULES,
            Capability.READ_OAUTH_GRANTS,
        }
    ),
    SourceMechanism.GMAIL_API: frozenset(
        {
            Capability.READ_INBOUND,
            Capability.READ_OUTBOUND,
            Capability.READ_HISTORY,
            Capability.MODIFY_MESSAGE,
            Capability.READ_FLAGS,
            Capability.READ_SERVER_RULES,
            Capability.READ_OAUTH_GRANTS,
        }
    ),
    SourceMechanism.ADMIN_API: frozenset(
        {
            Capability.READ_INBOUND,
            Capability.READ_OUTBOUND,
            Capability.READ_HISTORY,
            Capability.MODIFY_MESSAGE,
            Capability.READ_FLAGS,
        }
    ),
    # Tier 3 keeps full content access *and* remediation — IMAP MOVE works on a
    # 1998 server. What it cannot do is read server-side rules.
    SourceMechanism.IMAP_IDLE: frozenset(
        {
            Capability.READ_INBOUND,
            Capability.READ_OUTBOUND,
            Capability.READ_HISTORY,
            Capability.MODIFY_MESSAGE,
            Capability.READ_FLAGS,
        }
    ),
    SourceMechanism.IMAP_POLL: frozenset(
        {
            Capability.READ_INBOUND,
            Capability.READ_OUTBOUND,
            Capability.READ_HISTORY,
            Capability.READ_FLAGS,
        }
    ),
    # Tier 4: post-delivery, inbound only, no remediation of any kind.
    SourceMechanism.FORWARD_INGEST: frozenset({Capability.READ_INBOUND}),
    SourceMechanism.JOURNAL: frozenset(
        {Capability.READ_INBOUND, Capability.READ_OUTBOUND}
    ),
    # ── Channel 2 ────────────────────────────────────────────────────────────
    SourceMechanism.ENTRA_LOGS: frozenset(
        {
            Capability.READ_SIGNIN_LOGS,
            Capability.READ_SESSIONS,
            Capability.READ_MFA_STATE,
            Capability.READ_OAUTH_GRANTS,
        }
    ),
    SourceMechanism.GOOGLE_REPORTS: frozenset(
        {
            Capability.READ_SIGNIN_LOGS,
            Capability.READ_SESSIONS,
            Capability.READ_MFA_STATE,
            Capability.READ_OAUTH_GRANTS,
        }
    ),
    # The equaliser. Lives on the device, so it works on any provider — this is
    # what makes ISP-mail customers viable (PRD §7.7). It sees the real device
    # and the exact moment a message is opened, which sign-in logs do not.
    SourceMechanism.CLIENT_SENSOR: frozenset(
        {
            Capability.READ_SESSIONS,
            Capability.READ_DEVICE_FINGERPRINT,
        }
    ),
    SourceMechanism.IMAP_FLAGS: frozenset({Capability.READ_FLAGS}),
    # ── Channel 3 ────────────────────────────────────────────────────────────
    SourceMechanism.CERT_TRANSPARENCY: frozenset({Capability.OBSERVE_DOMAIN}),
    SourceMechanism.ZONE_FILE: frozenset({Capability.OBSERVE_DOMAIN}),
    SourceMechanism.RDAP: frozenset({Capability.OBSERVE_DOMAIN}),
    SourceMechanism.DMARC_RUA: frozenset({Capability.OBSERVE_DMARC}),
    SourceMechanism.THREAT_FEED: frozenset({Capability.OBSERVE_DOMAIN}),
}


def capabilities_for(sources: frozenset[SourceMechanism]) -> frozenset[Capability]:
    """Union of everything the configured sources can do."""
    result: set[Capability] = set()
    for source in sources:
        result |= MECHANISM_CAPABILITIES.get(source, frozenset())
    return frozenset(result)


#: Capabilities that must be present for a mailbox to count as fully protected.
_FULL_REQUIREMENTS: frozenset[Capability] = frozenset(
    {
        Capability.READ_INBOUND,
        Capability.READ_OUTBOUND,
        Capability.READ_HISTORY,
        Capability.MODIFY_MESSAGE,
        Capability.READ_SESSIONS,
        Capability.READ_SERVER_RULES,
    }
)

#: Below this, the mailbox is Limited.
_STANDARD_REQUIREMENTS: frozenset[Capability] = frozenset(
    {
        Capability.READ_INBOUND,
        Capability.MODIFY_MESSAGE,
    }
)


def protection_level(capabilities: frozenset[Capability]) -> ProtectionLevel:
    """Derive the level shown to the customer (PRD E7).

    Deliberately computed rather than configured. A mailbox that loses a source
    downgrades automatically and visibly, which is the entire point of P4.
    """
    if capabilities >= _FULL_REQUIREMENTS:
        return ProtectionLevel.FULL
    if capabilities >= _STANDARD_REQUIREMENTS:
        return ProtectionLevel.STANDARD
    return ProtectionLevel.LIMITED


#: Human-readable, per-capability "what this unlocks" + which source grants it.
#: Drives the connect UI's "to reach Full protection, do X" explainer so the level
#: is never a bare word the customer has to guess about (P4, E7).
_CAPABILITY_GUIDANCE: dict[Capability, tuple[str, str]] = {
    Capability.READ_INBOUND: ("scan incoming mail", "connect the mailbox"),
    Capability.MODIFY_MESSAGE: (
        "quarantine or rewrite a dangerous message",
        "connect over IMAP/OAuth (not forwarding, which is post-delivery)",
    ),
    Capability.READ_OUTBOUND: (
        "watch sent mail for signature and stylometry drift",
        "connect over IMAP or OAuth",
    ),
    Capability.READ_HISTORY: (
        "backfill history so baselines are accurate from day one",
        "connect over IMAP or OAuth",
    ),
    Capability.READ_SESSIONS: (
        "alert on unknown-IP, new-country and new-device logins",
        "install the browser/Outlook sensor, or connect via Microsoft 365 / Google Workspace",
    ),
    Capability.READ_SERVER_RULES: (
        "detect malicious mailbox rules and hidden forwarding",
        "connect via Microsoft 365 / Google Workspace (IMAP cannot see server rules)",
    ),
}


def _sources_granting(capability: Capability) -> list[str]:
    return sorted(
        s.value for s, caps in MECHANISM_CAPABILITIES.items() if capability in caps
    )


def protection_advice(sources: frozenset[SourceMechanism]) -> dict:
    """Explain the current protection level and exactly what would raise it.

    Returns the level, whether it is already the maximum, and — if not — the
    capabilities still missing for the next level, each with a plain-language
    reason and the way to obtain it. This is what the UI shows next to the level
    so "Standard" is never a bare, unexplained word (P4/E7).
    """
    caps = capabilities_for(sources)
    level = protection_level(caps)

    if level is ProtectionLevel.FULL:
        return {"level": level.value, "is_max": True, "next_level": None, "missing": []}

    next_level = (
        ProtectionLevel.STANDARD
        if level is ProtectionLevel.LIMITED
        else ProtectionLevel.FULL
    )
    required = (
        _STANDARD_REQUIREMENTS if next_level is ProtectionLevel.STANDARD else _FULL_REQUIREMENTS
    )
    missing = []
    for cap in sorted(required - caps, key=lambda c: c.value):
        unlocks, how = _CAPABILITY_GUIDANCE.get(cap, (cap.value.replace("_", " "), ""))
        missing.append(
            {
                "capability": cap.value,
                "unlocks": unlocks,
                "how": how,
                "provided_by": _sources_granting(cap),
            }
        )
    return {
        "level": level.value,
        "is_max": False,
        "next_level": next_level.value,
        "missing": missing,
    }
