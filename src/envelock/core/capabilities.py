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
