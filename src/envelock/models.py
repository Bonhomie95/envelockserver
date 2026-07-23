"""Persistent models. See PRD.md §12 (billing), §3 (services), E5 (audit trail).

Every tenant-scoped table carries `tenant_id` — multi-tenancy from commit one
(PRD §10). Row-level security policies live in the initial migration.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from envelock.core.enums import (
    AlertTier,
    IntegrationTier,
    MailboxClass,
    ProtectionLevel,
)
from envelock.db import Base, TimestampMixin, UUIDMixin
from envelock.types import JsonDict, StringList


# ─────────────────────────────────────────────────────────────────────────────
# Tenancy
# ─────────────────────────────────────────────────────────────────────────────
class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255))
    plan: Mapped[str] = mapped_column(String(32), default="guard")  # guard|essential|complete|solo
    billing_term: Mapped[str] = mapped_column(String(16), default="monthly")
    trial_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_method_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    domains: Mapped[list[Domain]] = relationship(back_populates="tenant")


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    #: PRD §15.1 three-role model: owner|admin|member. `is_admin` is kept in
    #: sync (admin or owner) for the notification recipient model (E4/E6).
    role: Mapped[str] = mapped_column(String(16), default="member")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    #: MFA is mandatory before a session can be held (PRD §15.1). The secret is
    #: provisioned at enrolment and confirmed at first verify.
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: SHA-256 hashes of single-use recovery codes; the codes themselves are
    #: shown exactly once at enrolment and never stored.
    recovery_hashes: Mapped[list[str]] = mapped_column(StringList, default=list)
    #: PRD §8.2 — alerts must reach somewhere the attacker does not control.
    out_of_band_email: Mapped[str | None] = mapped_column(String(320))
    phone: Mapped[str | None] = mapped_column(String(32))


# ─────────────────────────────────────────────────────────────────────────────
# Domains
# ─────────────────────────────────────────────────────────────────────────────
class Domain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "domains"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(253))
    #: eTLD+1 via Public Suffix List. Never naive splitting — PRD §12.7.
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_token: Mapped[str | None] = mapped_column(String(64))
    #: Defensive/parked domains are monitored free and unlimited (PRD §12.5).
    is_defensive: Mapped[bool] = mapped_column(Boolean, default=False)
    integration_tier: Mapped[int | None] = mapped_column(Integer)
    mx_hosts: Mapped[list[str] | None] = mapped_column(StringList)
    dmarc_policy: Mapped[str | None] = mapped_column(String(16))  # none|quarantine|reject
    spf_record: Mapped[str | None] = mapped_column(Text)

    tenant: Mapped[Tenant] = relationship(back_populates="domains")

    __table_args__ = (UniqueConstraint("tenant_id", "name"),)


class DomainTrialLedger(Base, TimestampMixin):
    """PRD §12.7 — append-only, permanent, survives tenant deletion.

    A registrable domain is not personal data, so retaining it through erasure
    requests is defensible. That permanence *is* the anti-abuse mechanism.
    """

    __tablename__ = "domain_trial_ledger"

    registrable_domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    first_trial_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_tenant_id: Mapped[UUID] = mapped_column(Uuid)
    outcome: Mapped[str] = mapped_column(String(16), default="active")
    payment_fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    override_by: Mapped[UUID | None] = mapped_column(Uuid)
    override_reason: Mapped[str | None] = mapped_column(Text)


class GraphVerdict(Base, TimestampMixin):
    """E8 — the cross-tenant counterparty graph, made durable.

    The moat is that one tenant's confirmation protects every other tenant. If it
    lives only in process memory it evaporates on every deploy, so verdicts are
    persisted here and hydrated at startup. Only a domain, a verdict and a
    confirmation count are stored — never a message, an address, or content. The
    reporting tenant ids are kept solely to stop one tenant inflating a count;
    they never cross the tenant boundary in any response.
    """

    __tablename__ = "graph_verdicts"

    registrable_domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16))  # fraudulent|suspicious|legitimate
    confirmations: Mapped[int] = mapped_column(Integer, default=1)
    first_reported: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_reported: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    techniques: Mapped[list[str]] = mapped_column(StringList, default=list)
    reporter_tenant_ids: Mapped[list[str]] = mapped_column(StringList, default=list)


class LookalikeDomain(Base, UUIDMixin, TimestampMixin):
    """D1–D4 findings."""

    __tablename__ = "lookalike_domains"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    protected_domain: Mapped[str] = mapped_column(String(253), index=True)
    candidate_domain: Mapped[str] = mapped_column(String(253), index=True)
    technique: Mapped[str] = mapped_column(String(32))  # typosquat|homoglyph|cousin|tld_swap
    similarity: Mapped[float] = mapped_column(Numeric(4, 3))
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Weaponisation scoring — MX present means armed (PRD D4).
    has_mx: Mapped[bool] = mapped_column(Boolean, default=False)
    has_web: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="open")

    __table_args__ = (UniqueConstraint("tenant_id", "candidate_domain"),)


# ─────────────────────────────────────────────────────────────────────────────
# Mailboxes
# ─────────────────────────────────────────────────────────────────────────────
class Mailbox(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mailboxes"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    domain_id: Mapped[UUID | None] = mapped_column(ForeignKey("domains.id"))
    address: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    #: Drives both pricing and IMAP strategy — PROTECTED holds IDLE, MONITORED
    #: polls (PRD §12.2, §12.11D).
    mailbox_class: Mapped[str] = mapped_column(String(16), default=MailboxClass.MONITORED)
    integration_tier: Mapped[int] = mapped_column(Integer, default=IntegrationTier.FORWARDING)
    #: Configured SourceMechanism values; capabilities are derived from these.
    sources: Mapped[list[str]] = mapped_column(StringList, default=list)
    protection_level: Mapped[str] = mapped_column(String(16), default=ProtectionLevel.LIMITED)
    inactive_detections: Mapped[list[str]] = mapped_column(StringList, default=list)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Shared mailboxes make concurrency normal — PRD S9.
    known_user_count: Mapped[int] = mapped_column(Integer, default=1)
    backfilled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (UniqueConstraint("tenant_id", "address"),)


class MailboxCredential(Base, UUIDMixin, TimestampMixin):
    """Envelope-encrypted. Decrypted only inside the connection broker (PRD §5.2)."""

    __tablename__ = "mailbox_credentials"

    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), unique=True)
    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # imap_password|oauth_token
    imap_host: Mapped[str | None] = mapped_column(String(253))
    imap_port: Mapped[int | None] = mapped_column(Integer)
    #: Ciphertext only. Never logged, never returned by the API.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str | None] = mapped_column(String(255))


# ─────────────────────────────────────────────────────────────────────────────
# Counterparties — the A-group state
# ─────────────────────────────────────────────────────────────────────────────
class Counterparty(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "counterparties"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    #: A2 — the number we prompt the user to call. Never the one in the email.
    verified_phone: Mapped[str | None] = mapped_column(String(32))
    #: A12 — historical reply latency baseline, seconds.
    median_reply_seconds: Mapped[int | None] = mapped_column(Integer)
    #: A10 — sending infrastructure fingerprint.
    known_dkim_domains: Mapped[list[str]] = mapped_column(StringList, default=list)
    known_mail_clients: Mapped[list[str]] = mapped_column(StringList, default=list)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (UniqueConstraint("tenant_id", "registrable_domain"),)


class BankRecord(Base, UUIDMixin, TimestampMixin):
    """A1/A2 — known-good payment details per counterparty.

    Any change to a previously-seen vendor's details is Critical, always.
    """

    __tablename__ = "bank_records"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    counterparty_id: Mapped[UUID] = mapped_column(ForeignKey("counterparties.id"), index=True)
    scheme: Mapped[str] = mapped_column(String(16))  # iban|swift|ach|sortcode|crypto
    #: Normalised account identifier (IBAN, account no, wallet address).
    identifier: Mapped[str] = mapped_column(String(128))
    bank_name: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[UUID | None] = mapped_column(Uuid)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (
        UniqueConstraint("counterparty_id", "scheme", "identifier"),
        Index("ix_bank_records_lookup", "tenant_id", "counterparty_id", "is_active"),
    )


class SenderProfile(Base, UUIDMixin, TimestampMixin):
    """A9 stylometry baseline, per sending address."""

    __tablename__ = "sender_profiles"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    address: Mapped[str] = mapped_column(String(320), index=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Lightweight stylometric features; embeddings live in pgvector separately.
    features: Mapped[dict] = mapped_column(JsonDict, default=dict)

    __table_args__ = (UniqueConstraint("tenant_id", "address"),)


# ─────────────────────────────────────────────────────────────────────────────
# Messages, findings, alerts
# ─────────────────────────────────────────────────────────────────────────────
class Message(Base, UUIDMixin, TimestampMixin):
    """Metadata always; bodies only when metadata-only mode is off (E13)."""

    __tablename__ = "messages"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    rfc_message_id: Mapped[str | None] = mapped_column(String(998), index=True)
    thread_key: Mapped[str | None] = mapped_column(String(255), index=True)
    direction: Mapped[str] = mapped_column(String(16))
    sender_address: Mapped[str] = mapped_column(String(320), index=True)
    sender_display: Mapped[str | None] = mapped_column(String(255))
    reply_to_address: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32))
    remediable: Mapped[bool] = mapped_column(Boolean, default=False)
    spf: Mapped[str | None] = mapped_column(String(16))
    dkim: Mapped[str | None] = mapped_column(String(16))
    dmarc: Mapped[str | None] = mapped_column(String(16))
    attachment_hashes: Mapped[list[str]] = mapped_column(StringList, default=list)
    body_storage_key: Mapped[str | None] = mapped_column(String(512))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base, UUIDMixin, TimestampMixin):
    """One detection firing. Alerts aggregate findings (PRD §8 combination logic)."""

    __tablename__ = "findings"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(ForeignKey("mailboxes.id"))
    message_id: Mapped[UUID | None] = mapped_column(ForeignKey("messages.id"))
    alert_id: Mapped[UUID | None] = mapped_column(ForeignKey("alerts.id"), index=True)
    #: Service id from the PRD catalogue — "A1", "C4", "D4".
    service: Mapped[str] = mapped_column(String(8), index=True)
    tier: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JsonDict, default=dict)


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    mailbox_id: Mapped[UUID | None] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    tier: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    #: Guided out-of-band verification (E3) — the step that stops the loss.
    requires_callback: Mapped[bool] = mapped_column(Boolean, default=False)
    callback_phone: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default="open")  # open|acked|resolved|dismissed
    #: Acknowledgement — not delivery — drives escalation (PRD §8.1).
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[UUID | None] = mapped_column(Uuid)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_alerts_open", "tenant_id", "state", "tier"),)


class NotificationDelivery(Base, UUIDMixin, TimestampMixin):
    """One attempt on one rung of the ladder (PRD §8.1). L3 is metered."""

    __tablename__ = "notification_deliveries"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), index=True)
    user_id: Mapped[UUID | None] = mapped_column(Uuid)
    rung: Mapped[str] = mapped_column(String(4))  # L0|L1|L2|L3
    channel: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    cost_micros: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class AuditEvent(Base, UUIDMixin, TimestampMixin):
    """E5 — IT sees who read, who acted, who ignored."""

    __tablename__ = "audit_events"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    actor_id: Mapped[UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[UUID | None] = mapped_column(Uuid)
    detail: Mapped[dict] = mapped_column(JsonDict, default=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Channel 2 — sensor sessions
# ─────────────────────────────────────────────────────────────────────────────
class SensorSession(Base, UUIDMixin, TimestampMixin):
    """C6/C10/C11. A \\Seen flag flipping with no live session here means
    someone else is in the mailbox."""

    __tablename__ = "sensor_sessions"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    mailbox_id: Mapped[UUID] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    user_id: Mapped[UUID | None] = mapped_column(Uuid)
    device_fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str | None] = mapped_column(String(45))
    asn: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(String(2))
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    browser: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(64))
    mail_client: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PushSubscription(Base, UUIDMixin, TimestampMixin):
    """L1 — free, self-hosted Web Push."""

    __tablename__ = "push_subscriptions"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[UUID] = mapped_column(index=True)
    endpoint: Mapped[str] = mapped_column(Text, unique=True)
    p256dh: Mapped[str] = mapped_column(String(255))
    auth: Mapped[str] = mapped_column(String(255))


# ─────────────────────────────────────────────────────────────────────────────
# Billing / metering
# ─────────────────────────────────────────────────────────────────────────────
class UsageMeter(Base, UUIDMixin, TimestampMixin):
    """Daily rollup. Fall-through rate is the number that predicts COGS
    (PRD §12.12D) — meter it from day one."""

    __tablename__ = "usage_meters"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    day: Mapped[date] = mapped_column(Date, index=True)
    messages_analysed: Mapped[int] = mapped_column(Integer, default=0)
    attachments_seen: Mapped[int] = mapped_column(Integer, default=0)
    attachments_cache_hit: Mapped[int] = mapped_column(Integer, default=0)
    attachments_static_resolved: Mapped[int] = mapped_column(Integer, default=0)
    #: The expensive fall-through. Target under 5% of attachments_seen.
    attachments_detonated: Mapped[int] = mapped_column(Integer, default=0)
    url_lookups_free: Mapped[int] = mapped_column(Integer, default=0)
    url_lookups_paid: Mapped[int] = mapped_column(Integer, default=0)
    sms_sent: Mapped[int] = mapped_column(Integer, default=0)
    external_cost_micros: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("tenant_id", "day"),)


class Invoice(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "invoices"

    tenant_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    platform_cents: Mapped[int] = mapped_column(Integer, default=0)
    protected_cents: Mapped[int] = mapped_column(Integer, default=0)
    monitored_cents: Mapped[int] = mapped_column(Integer, default=0)
    discount_cents: Mapped[int] = mapped_column(Integer, default=0)
    total_cents: Mapped[int] = mapped_column(Integer, default=0)
    breakdown: Mapped[dict] = mapped_column(JsonDict, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="draft")


__all__ = [
    "Alert",
    "AlertTier",
    "AuditEvent",
    "BankRecord",
    "Counterparty",
    "Decimal",
    "Domain",
    "DomainTrialLedger",
    "Finding",
    "GraphVerdict",
    "Invoice",
    "LookalikeDomain",
    "Mailbox",
    "MailboxCredential",
    "Message",
    "NotificationDelivery",
    "PushSubscription",
    "SenderProfile",
    "SensorSession",
    "Tenant",
    "UsageMeter",
    "User",
]
