"""Shared vocabulary.

These names come straight from PRD.md. Keep them in sync with it — the PRD is the
source of truth for what each value means.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Channel(StrEnum):
    """PRD §2. Every service draws from exactly one of these."""

    MAIL = "mail"  # Channel 1 — content
    IDENTITY = "identity"  # Channel 2 — who / where / when
    EXTERNAL = "external"  # Channel 3 — the world outside the mailbox


class SourceMechanism(StrEnum):
    """How an event physically reached us.

    Detection logic must never branch on this — that is the whole point of the
    normaliser (PRD §10). Branch on `Capability` instead (see capabilities.py).
    """

    # Channel 1
    GRAPH_API = "graph_api"  # Tier 1, Microsoft 365
    GMAIL_API = "gmail_api"  # Tier 1, Google Workspace
    ADMIN_API = "admin_api"  # Tier 2, Zimbra / Zoho / Alibaba / Fastmail
    IMAP_IDLE = "imap_idle"  # Tier 3, Protected mailboxes
    IMAP_POLL = "imap_poll"  # Tier 3, Monitored mailboxes (PRD §12.11D)
    FORWARD_INGEST = "forward_ingest"  # Tier 4
    JOURNAL = "journal"  # Tier 4, on-prem dual-delivery

    # Channel 2
    ENTRA_LOGS = "entra_logs"
    GOOGLE_REPORTS = "google_reports"
    CLIENT_SENSOR = "client_sensor"  # browser ext / Outlook add-in / Thunderbird
    IMAP_FLAGS = "imap_flags"  # \Seen divergence — C11 without a sensor

    # Channel 3
    CERT_TRANSPARENCY = "cert_transparency"
    ZONE_FILE = "zone_file"  # CZDS
    RDAP = "rdap"
    DMARC_RUA = "dmarc_rua"
    THREAT_FEED = "threat_feed"


class IntegrationTier(IntEnum):
    """PRD §5. Determined automatically by MX lookup at signup."""

    FULL_API = 1
    ADMIN_API = 2
    IMAP = 3
    FORWARDING = 4


class MailboxClass(StrEnum):
    """PRD §12.2. Drives both pricing and IMAP connection strategy.

    PROTECTED holds an IDLE connection because quarantine latency is the product.
    MONITORED polls, which is why it stays cheap enough to mandate whole-domain
    coverage.
    """

    PROTECTED = "protected"
    MONITORED = "monitored"


class ProtectionLevel(StrEnum):
    """PRD E7. Derived from capabilities, never hand-set — see capabilities.py."""

    FULL = "full"
    STANDARD = "standard"
    LIMITED = "limited"


class AlertTier(StrEnum):
    """PRD §8. Defined by required action, not by how alarming the finding sounds."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MailDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class AuthResult(StrEnum):
    """SPF / DKIM / DMARC outcome. Feeds B8."""

    PASS = "pass"  # noqa: S105 — an SPF/DKIM outcome, not a credential
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class IdentityEventKind(StrEnum):
    """Channel 2 event types. Maps to the C-group services."""

    SIGN_IN = "sign_in"  # C6, C7, C8
    SESSION_START = "session_start"  # C6
    SESSION_HEARTBEAT = "session_heartbeat"  # C6 — sensor liveness
    MESSAGE_OPENED = "message_opened"  # C11 — sensor-reported
    FLAG_CHANGED = "flag_changed"  # C11 — IMAP \Seen divergence
    RULE_CHANGED = "rule_changed"  # C1, C2
    DELEGATE_CHANGED = "delegate_changed"  # C3
    OAUTH_GRANT = "oauth_grant"  # C4
    SIGNATURE_CHANGED = "signature_changed"  # C5
    CREDENTIAL_CHANGED = "credential_changed"  # C12
    MFA_CHANGED = "mfa_changed"  # C12, C13


class ExternalEventKind(StrEnum):
    """Channel 3 event types. Maps to the D-group services."""

    CERT_ISSUED = "cert_issued"  # D2
    DOMAIN_REGISTERED = "domain_registered"  # D1, D3
    DOMAIN_PROBED = "domain_probed"  # D4 — MX/web weaponisation scoring
    DMARC_REPORT = "dmarc_report"  # D6
    FEED_INDICATOR = "feed_indicator"  # B7
