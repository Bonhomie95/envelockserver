"""The unified event schema — *the* critical abstraction (PRD §10).

Every ingest mechanism emits these types and nothing else. Graph, Gmail, IMAP IDLE,
IMAP polling, forwarding and journaling all normalise into `MailEvent`; sign-in
logs, the client sensor and `\\Seen` divergence all normalise into `IdentityEvent`.

**Detection logic is written once against these models and must never branch on
`source`.** Where a detection needs something a mechanism cannot provide, it
declares a `Capability` requirement (see capabilities.py) and is reported as
inactive for that mailbox. Without this discipline we end up with four
implementations of A1 and they drift.

Build this before anything that consumes it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from envelock.core.enums import (
    AuthResult,
    Channel,
    ExternalEventKind,
    IdentityEventKind,
    MailDirection,
    SourceMechanism,
)


class _Base(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ─────────────────────────────────────────────────────────────────────────────
# Shared value objects
# ─────────────────────────────────────────────────────────────────────────────


class EmailAddress(_Base):
    """A parsed address. `display` is kept separate because display-name spoofing
    (A5) is the cheapest and most common attack we detect."""

    address: str
    display: str | None = None

    @property
    def domain(self) -> str:
        _, _, domain = self.address.rpartition("@")
        return domain.lower()


class AttachmentRef(_Base):
    """A reference, never the bytes.

    Content lives in object storage keyed by `sha256`, which makes the shared
    cross-tenant verdict cache (PRD §12.12A layer 0) a natural consequence of the
    schema rather than a bolt-on. In metadata-only mode (E13) `storage_key` is
    None and only the hash and shape survive.
    """

    filename: str
    sha256: str
    size_bytes: int
    declared_mime: str | None = None
    detected_mime: str | None = None
    """Magic-byte sniff. A mismatch with `declared_mime` is itself a signal (B6)."""

    storage_key: str | None = None
    is_archive: bool = False
    archive_depth: int = 0
    is_encrypted: bool = False
    """Password-protected archive — often with the password in the body (B5)."""


class AuthenticationResults(_Base):
    """Header-derived, free, and feeds B8."""

    spf: AuthResult = AuthResult.NONE
    dkim: AuthResult = AuthResult.NONE
    dmarc: AuthResult = AuthResult.NONE
    dkim_domain: str | None = None
    """A counterparty whose DKIM signing domain suddenly changes is a signal (A10)."""


class NetworkContext(_Base):
    """Where something came from.

    Only trustworthy for *our own users'* sessions (Channel 2). Inbound sender IPs
    are usually stripped or rewritten by the provider — see PRD §7.3, and prefer
    A10 infrastructure-change detection over sender geolocation.
    """

    ip: str | None = None
    asn: int | None = None
    asn_name: str | None = None
    country: str | None = None
    city: str | None = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_tor: bool = False
    """VPN-ness is itself the signal — we never claim to see through it (PRD §7.2)."""

    latitude: float | None = None
    longitude: float | None = None


class DeviceContext(_Base):
    """Sensor-reported. This is what Tier 3 gets *instead of* sign-in logs, and in
    some respects it is better — it identifies the device at the moment a message
    is opened, not merely at authentication."""

    fingerprint: str | None = None
    user_agent: str | None = None
    browser: str | None = None
    os: str | None = None
    mail_client: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Event envelope
# ─────────────────────────────────────────────────────────────────────────────


class EventEnvelope(_Base):
    event_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    occurred_at: datetime
    """When it happened at the source. Never our clock."""

    ingested_at: datetime
    """When we saw it. The gap matters: polling sources lag by design, and alert
    latency claims must be computed from this pair rather than assumed."""

    source: SourceMechanism
    source_ref: str | None = None
    """Provider-native id, for idempotency and reconciliation."""


# ─────────────────────────────────────────────────────────────────────────────
# Channel 1 — mail
# ─────────────────────────────────────────────────────────────────────────────


class MailEvent(EventEnvelope):
    """One message, however it reached us.

    Emitted identically by Graph, Gmail, IMAP and forwarding ingest.
    """

    channel: Literal[Channel.MAIL] = Channel.MAIL
    mailbox_id: UUID

    direction: MailDirection
    rfc_message_id: str | None = None
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()
    """Thread chain. A reply quoting history but breaking this is A8."""

    sender: EmailAddress
    reply_to: EmailAddress | None = None
    return_path: EmailAddress | None = None
    """`sender` vs `reply_to` divergence is A6 — trivial to compute, catches real BEC."""

    recipients_to: tuple[EmailAddress, ...] = ()
    recipients_cc: tuple[EmailAddress, ...] = ()

    subject: str | None = None
    sent_at: datetime | None = None

    body_text: str | None = None
    body_html: str | None = None
    body_storage_key: str | None = None
    """Set instead of inline bodies under metadata-only mode (E13)."""

    attachments: tuple[AttachmentRef, ...] = ()
    urls: tuple[str, ...] = ()
    authentication: AuthenticationResults = AuthenticationResults()

    received_headers: tuple[str, ...] = ()
    """Retained for A10 infrastructure-change analysis, not for geolocation."""

    remediable: bool = False
    """Whether this message can still be quarantined or rewritten.

    False for forwarding and journaling — the copy reaches us *after* delivery, so
    E2 and B2 are impossible no matter what we detect (PRD §4 fn.3). Detections
    must consult this before promising remediation in an alert.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Channel 2 — identity
# ─────────────────────────────────────────────────────────────────────────────


class IdentityEvent(EventEnvelope):
    """Access, session and configuration activity on a mailbox we protect."""

    channel: Literal[Channel.IDENTITY] = Channel.IDENTITY
    mailbox_id: UUID
    kind: IdentityEventKind

    network: NetworkContext = NetworkContext()
    device: DeviceContext = DeviceContext()
    session_id: str | None = None

    target: str | None = None
    """What changed — rule name, delegate address, OAuth app id, message id."""

    before: str | None = None
    after: str | None = None
    """Old and new values for change events. `after` containing an external domain
    on a forwarding rule is the C1 Critical case."""

    counterparty_shared: bool = False
    """True when this session belongs to a counterparty who is also an Envelock
    tenant and has consented to graph participation (C14, E8)."""

    sensor_attested: bool = False
    """True when a client sensor reported this.

    C11 turns on exactly this field: a `\\Seen` flag flipping with no
    sensor-attested session at that moment means someone else is in the mailbox.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Channel 3 — external
# ─────────────────────────────────────────────────────────────────────────────


class ExternalEvent(EventEnvelope):
    """Observations about the world. Requires no mailbox access at all, which is
    why Guard can be free forever and why this is the pre-sales demo (PRD S12)."""

    channel: Literal[Channel.EXTERNAL] = Channel.EXTERNAL
    kind: ExternalEventKind

    domain: str
    registrable_domain: str
    """eTLD+1 via the Public Suffix List. Never naive string splitting — that
    would break every .co.uk, .com.tw and .com.ng customer, i.e. our markets."""

    protected_domain: str | None = None
    """The customer domain this observation resembles, if any."""

    similarity_score: float | None = None
    registered_at: datetime | None = None
    """Still public post-GDPR, and the field we actually need (PRD §12.12B)."""

    has_mx: bool = False
    """A lookalike with MX configured is armed — High, not Low (D4)."""

    has_web_content: bool = False
    certificate_sans: tuple[str, ...] = ()


Event = Annotated[
    MailEvent | IdentityEvent | ExternalEvent,
    Field(discriminator="channel"),
]

__all__ = [
    "AttachmentRef",
    "AuthenticationResults",
    "DeviceContext",
    "EmailAddress",
    "Event",
    "EventEnvelope",
    "ExternalEvent",
    "IdentityEvent",
    "MailEvent",
    "NetworkContext",
]
