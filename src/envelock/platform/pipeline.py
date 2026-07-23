"""The analysis pipeline: event → context → detections → risk → alert → notify.

This is where the parts meet. Detections stay pure; everything that touches the
database or an external service happens here, which keeps the detection suite
unit-testable and the pipeline the only place that needs integration tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import MailDirection, SourceMechanism
from envelock.core.events import Event, MailEvent
from envelock.detections import cascade as casc
from envelock.detections.base import (
    CounterpartyState,
    DetectionContext,
    FindingResult,
    PreviousSession,
    inactive_for,
    run_all,
)
from envelock.models import (
    BankRecord,
    Counterparty,
    Mailbox,
    Message,
    SenderProfile,
    SensorSession,
)
from envelock.platform.alerts import raise_alert
from envelock.platform.graph import GRAPH
from envelock.risk.engine import RiskAssessment, assess
from envelock.util.domains import registrable_domain
from envelock.util.payments import extract_bank_identifiers


@dataclass(frozen=True, slots=True)
class PipelineResult:
    findings: list[FindingResult]
    assessment: RiskAssessment | None
    alert_id: UUID | None
    protection_level: str
    inactive_detections: list[str]
    latency_seconds: float

    @property
    def alerted(self) -> bool:
        return self.alert_id is not None


async def _counterparty_state(
    session: AsyncSession, *, tenant_id: UUID, domain: str
) -> CounterpartyState | None:
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == tenant_id,
                Counterparty.registrable_domain == domain,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None

    banks = (
        (
            await session.execute(
                select(BankRecord).where(
                    BankRecord.counterparty_id == row.id, BankRecord.is_active.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    return CounterpartyState(
        registrable_domain=row.registrable_domain,
        first_seen_at=_aware(row.first_seen_at),
        last_seen_at=_aware(row.last_seen_at),
        message_count=row.message_count,
        known_bank_ids=frozenset(b.identifier for b in banks),
        known_dkim_domains=frozenset(row.known_dkim_domains or []),
        known_mail_clients=frozenset(row.known_mail_clients or []),
        median_reply_seconds=row.median_reply_seconds,
        verified_phone=row.verified_phone,
        is_trusted=row.is_trusted,
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def build_context(
    session: AsyncSession,
    event: Event,
    *,
    tenant_id: UUID,
    owned_domains: frozenset[str],
    attachment_verdicts: dict[str, str] | None = None,
    sender_domain_age_days: int | None = None,
) -> DetectionContext:
    """Load everything the detections need. They never query anything themselves."""
    mailbox_id = getattr(event, "mailbox_id", None)
    sources: set[SourceMechanism] = {event.source}
    active_sessions = 0
    known_devices: set[str] = set()
    previous: PreviousSession | None = None
    mfa_enabled: bool | None = None

    if mailbox_id is not None:
        mailbox = await session.get(Mailbox, mailbox_id)
        if mailbox is not None:
            sources |= {SourceMechanism(s) for s in (mailbox.sources or []) if s}

        sessions = (
            (
                await session.execute(
                    select(SensorSession)
                    .where(SensorSession.mailbox_id == mailbox_id)
                    .order_by(SensorSession.last_seen_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
        active_sessions = sum(1 for s in sessions if s.ended_at is None)
        known_devices = {s.device_fingerprint for s in sessions if s.device_fingerprint}
        if sessions:
            latest = sessions[0]
            previous = PreviousSession(
                at=_aware(latest.last_seen_at) or datetime.now(UTC),
                country=latest.country,
                latitude=None,
                longitude=None,
                ip=latest.ip,
                asn=latest.asn,
            )

    counterparty = None
    baseline: dict[str, float] = {}
    if isinstance(event, MailEvent) and event.direction is MailDirection.INBOUND:
        sender_domain = registrable_domain(event.sender.domain)
        counterparty = await _counterparty_state(
            session, tenant_id=tenant_id, domain=sender_domain
        )
        profile = (
            await session.execute(
                select(SenderProfile).where(
                    SenderProfile.tenant_id == tenant_id,
                    SenderProfile.address == event.sender.address,
                )
            )
        ).scalar_one_or_none()
        if profile is not None:
            baseline = profile.features or {}

    known = {
        row
        for (row,) in (
            await session.execute(
                select(Counterparty.registrable_domain).where(
                    Counterparty.tenant_id == tenant_id
                )
            )
        ).all()
    }

    caps = capabilities_for(frozenset(sources))
    return DetectionContext(
        event=event,
        tenant_id=str(tenant_id),
        capabilities=caps,
        owned_domains=owned_domains,
        known_counterparties=frozenset(known),
        counterparty=counterparty,
        active_sessions=active_sessions,
        known_devices=frozenset(known_devices),
        previous_session=previous,
        sender_baseline=baseline,
        malicious_domains=GRAPH.known_bad(),
        attachment_verdicts=attachment_verdicts or {},
        sender_domain_age_days=sender_domain_age_days,
        mfa_enabled=mfa_enabled,
        now=datetime.now(UTC),
    )


async def learn(session: AsyncSession, event: MailEvent, *, tenant_id: UUID) -> None:
    """Update counterparty state and the stylometric baseline.

    Learning happens *after* detection so a fraudulent message cannot poison the
    baseline it was judged against.
    """
    if event.direction is not MailDirection.INBOUND:
        return
    domain = registrable_domain(event.sender.domain)
    if not domain or domain in {""}:
        return

    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == tenant_id,
                Counterparty.registrable_domain == domain,
            )
        )
    ).scalar_one_or_none()

    now = event.occurred_at
    if row is None:
        row = Counterparty(
            tenant_id=tenant_id,
            registrable_domain=domain,
            display_name=event.sender.display,
            first_seen_at=now,
            last_seen_at=now,
            message_count=1,
            known_dkim_domains=[],
            known_mail_clients=[],
        )
        session.add(row)
        await session.flush()
    else:
        row.message_count += 1
        row.last_seen_at = now

    dkim = event.authentication.dkim_domain
    if dkim and dkim not in (row.known_dkim_domains or []):
        row.known_dkim_domains = [*(row.known_dkim_domains or []), dkim]

    # Bank details are only learned from messages we did not flag, and only when
    # the vendor has no record yet — otherwise A1 could never fire.
    existing = (
        (
            await session.execute(
                select(BankRecord).where(BankRecord.counterparty_id == row.id)
            )
        )
        .scalars()
        .all()
    )
    if not existing:
        for bank in extract_bank_identifiers(
            " ".join(filter(None, [event.subject, event.body_text]))
        ):
            session.add(
                BankRecord(
                    tenant_id=tenant_id,
                    counterparty_id=row.id,
                    scheme=bank.scheme,
                    identifier=bank.identifier,
                    country=bank.country,
                    first_seen_at=now,
                )
            )

    from envelock.detections.content import style_features

    features = style_features(event.body_text or "")
    if features:
        profile = (
            await session.execute(
                select(SenderProfile).where(
                    SenderProfile.tenant_id == tenant_id,
                    SenderProfile.address == event.sender.address,
                )
            )
        ).scalar_one_or_none()
        if profile is None:
            session.add(
                SenderProfile(
                    tenant_id=tenant_id,
                    address=event.sender.address,
                    sample_count=1,
                    features=features,
                )
            )
        else:
            # Running mean keeps the baseline stable and cheap to update.
            n = profile.sample_count + 1
            merged = dict(profile.features or {})
            for key, value in features.items():
                merged[key] = ((merged.get(key, value) * (n - 1)) + value) / n
            profile.features = merged
            profile.sample_count = n


async def analyse_event(
    session: AsyncSession,
    event: Event,
    *,
    tenant_id: UUID,
    owned_domains: frozenset[str],
    recipients: list | None = None,
    persist: bool = True,
    attachment_verdicts: dict[str, str] | None = None,
    sender_domain_age_days: int | None = None,
) -> PipelineResult:
    ctx = await build_context(
        session,
        event,
        tenant_id=tenant_id,
        owned_domains=owned_domains,
        attachment_verdicts=attachment_verdicts,
        sender_domain_age_days=sender_domain_age_days,
    )

    findings = run_all(ctx)
    assessment = assess(findings)

    message_id: UUID | None = None
    if persist and isinstance(event, MailEvent):
        message = Message(
            tenant_id=tenant_id,
            mailbox_id=event.mailbox_id,
            rfc_message_id=event.rfc_message_id,
            thread_key=event.references[0] if event.references else event.rfc_message_id,
            direction=event.direction.value,
            sender_address=event.sender.address,
            sender_display=event.sender.display,
            reply_to_address=event.reply_to.address if event.reply_to else None,
            subject=event.subject,
            sent_at=event.sent_at,
            received_at=event.occurred_at,
            source=event.source.value,
            remediable=event.remediable,
            spf=event.authentication.spf.value,
            dkim=event.authentication.dkim.value,
            dmarc=event.authentication.dmarc.value,
            attachment_hashes=[a.sha256 for a in event.attachments],
            risk_score=assessment.score if assessment else 0,
        )
        session.add(message)
        await session.flush()
        message_id = message.id

    alert_id: UUID | None = None
    if persist and assessment is not None and assessment.is_alertable:
        # The counterparty is the inbound sender's registrable domain — captured
        # so that confirming the alert can feed the E8 graph (see alerts.resolve).
        counterparty_domain = None
        if isinstance(event, MailEvent):
            counterparty_domain = registrable_domain(event.sender.domain) or None
        alert = await raise_alert(
            session,
            tenant_id=tenant_id,
            mailbox_id=getattr(event, "mailbox_id", None),
            assessment=assessment,
            findings=findings,
            message_id=message_id,
            recipients=recipients or [],
            counterparty_domain=counterparty_domain,
        )
        alert_id = alert.id

    if persist and isinstance(event, MailEvent):
        await learn(session, event, tenant_id=tenant_id)

    latency = (datetime.now(UTC) - event.ingested_at).total_seconds()
    return PipelineResult(
        findings=findings,
        assessment=assessment,
        alert_id=alert_id,
        protection_level=protection_level(ctx.capabilities).value,
        inactive_detections=inactive_for(ctx.capabilities),
        latency_seconds=round(max(latency, 0.0), 3),
    )


async def analyse_attachments(
    cascade: casc.AttachmentCascade,
    event: MailEvent,
    *,
    payloads: dict[str, bytes] | None = None,
    protected_mailbox: bool = True,
) -> dict[str, str]:
    """Run the cascade and return sha256 → verdict for the detection context."""
    verdicts: dict[str, str] = {}
    for att in event.attachments:
        result = await cascade.analyse(
            sha256=att.sha256,
            filename=att.filename,
            payload=(payloads or {}).get(att.sha256, b""),
            declared_mime=att.declared_mime,
            protected_mailbox=protected_mailbox,
        )
        verdicts[att.sha256] = result.verdict.value
    return verdicts
