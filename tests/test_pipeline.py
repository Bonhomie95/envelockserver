"""End-to-end pipeline: mail arrives → detections run → alert persisted → learned."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail.parser import parse_message
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.models import (
    Alert,
    AuditEvent,
    BankRecord,
    Counterparty,
    Mailbox,
    Message,
    SenderProfile,
    Tenant,
)
from envelock.platform import alerts as alert_svc
from envelock.platform.pipeline import analyse_event

OWNED = frozenset({"acme.com"})

pytestmark = pytest.mark.asyncio


async def _mailbox(session, tenant_id, *, sources=None, cls=MailboxClass.PROTECTED):
    session.add(Tenant(id=tenant_id, name="Acme"))
    await session.flush()
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=cls.value,
        sources=[s.value for s in (sources or [SourceMechanism.IMAP_IDLE])],
    )
    session.add(mailbox)
    await session.flush()
    return mailbox


def _msg(body: str, *, sender="billing@gemini.com", subject="Invoice 4471", extra=""):
    return (
        f'From: "Gemini Accounts" <{sender}>\n'
        f"To: pay@acme.com\n"
        f"Subject: {subject}\n"
        f"{extra}"
        f"Content-Type: text/plain\n\n{body}"
    ).encode()


async def test_ordinary_first_message_learns_without_alerting(session, tenant_id):
    """A7 deliberately fires on first contact *discussing payment*, so an
    ordinary introduction must stay quiet."""
    mailbox = await _mailbox(session, tenant_id)
    event = parse_message(
        _msg("Hello, good to meet you last week. Regards.", subject="Nice to meet you"),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=OWNED,
        remediable=True,
    )
    result = await analyse_event(
        session, event, tenant_id=tenant_id, owned_domains=OWNED
    )
    await session.commit()

    assert not result.alerted
    cp = (
        await session.execute(
            select(Counterparty).where(Counterparty.registrable_domain == "gemini.com")
        )
    ).scalar_one()
    assert cp.message_count == 1


async def test_bank_change_after_learning_raises_critical_alert(session, tenant_id):
    mailbox = await _mailbox(session, tenant_id)

    # Establish the vendor and their account over several legitimate messages.
    for i in range(3):
        event = parse_message(
            _msg(
                "Invoice attached. Our bank account IBAN GB94BARC10201530093459 "
                "is unchanged. Payment terms 30 days.",
                subject=f"Invoice 400{i}",
            ),
            tenant_id=tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE,
            owned_domains=OWNED,
            remediable=True,
        )
        await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    banks = (await session.execute(select(BankRecord))).scalars().all()
    assert banks, "the known-good account should have been learned"

    # Now the fraud: a different account.
    fraud = parse_message(
        _msg(
            "Our bank account has changed. Please remit to IBAN "
            "GB33BUKB20201555555555. This is urgent, we need it today.",
            extra="In-Reply-To: <old@gemini.com>\n",
        ),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=OWNED,
        remediable=True,
    )
    result = await analyse_event(session, fraud, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert result.alerted
    assert result.assessment.tier is AlertTier.CRITICAL
    assert "A1" in result.assessment.services

    stored = (await session.execute(select(Alert))).scalars().all()
    critical = [a for a in stored if a.tier == "critical"]
    assert len(critical) == 1, "exactly one Critical — the bank change"
    assert critical[0].requires_callback


async def test_alert_and_findings_and_audit_all_persist(session, tenant_id):
    mailbox = await _mailbox(session, tenant_id)
    session.add(
        Counterparty(
            tenant_id=tenant_id,
            registrable_domain="gemini.com",
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
            message_count=40,
        )
    )
    await session.flush()
    cp = (await session.execute(select(Counterparty))).scalar_one()
    session.add(
        BankRecord(
            tenant_id=tenant_id,
            counterparty_id=cp.id,
            scheme="iban",
            identifier="GB94BARC10201530093459",
            first_seen_at=datetime.now(UTC),
        )
    )
    await session.commit()

    event = parse_message(
        _msg("New bank account: IBAN GB33BUKB20201555555555. Urgent payment please."),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=OWNED,
        remediable=True,
    )
    await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert (await session.execute(select(Message))).scalars().all()
    audit = (await session.execute(select(AuditEvent))).scalars().all()
    assert any(a.action == alert_svc.AuditAction.ALERT_RAISED for a in audit)


async def test_stylometry_baseline_accumulates(session, tenant_id):
    mailbox = await _mailbox(session, tenant_id)
    for i in range(4):
        event = parse_message(
            _msg(
                "Dear team, kindly find the monthly statement attached for your "
                "review. We appreciate your continued partnership and remain "
                f"available for questions. Regards, Accounts. Reference {i}.",
                subject=f"Statement {i}",
            ),
            tenant_id=tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE,
            owned_domains=OWNED,
        )
        await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    profile = (await session.execute(select(SenderProfile))).scalar_one()
    assert profile.sample_count == 4
    assert profile.features


async def test_forwarding_mailbox_cannot_quarantine(session, tenant_id):
    mailbox = await _mailbox(
        session, tenant_id, sources=[SourceMechanism.FORWARD_INGEST]
    )
    await session.commit()

    event = parse_message(
        _msg("Please update our bank details to IBAN GB33BUKB20201555555555."),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.FORWARD_INGEST,
        owned_domains=OWNED,
    )
    result = await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert event.remediable is False
    assert result.protection_level == "limited"
    # Detections that need write access or identity data are named, not hidden.
    assert "B2" in result.inactive_detections


async def test_acknowledge_stops_escalation(session, tenant_id):
    mailbox = await _mailbox(session, tenant_id)
    await session.commit()

    old = datetime.now(UTC) - timedelta(minutes=30)
    alert = Alert(
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        tier=AlertTier.CRITICAL.value,
        title="Bank details changed",
        body="",
        state="open",
        created_at=old,
    )
    session.add(alert)
    await session.commit()

    due = await alert_svc.due_escalations(session)
    assert any(d.alert_id == alert.id for d in due)

    await alert_svc.acknowledge(
        session, alert_id=alert.id, tenant_id=tenant_id, actor_id=uuid4()
    )
    await session.commit()

    due_after = await alert_svc.due_escalations(session)
    assert not any(d.alert_id == alert.id for d in due_after)


async def test_tenant_isolation_on_acknowledge(session, tenant_id):
    mailbox = await _mailbox(session, tenant_id)
    alert = Alert(
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        tier=AlertTier.HIGH.value,
        title="x",
        body="",
        state="open",
    )
    session.add(alert)
    await session.commit()

    other_tenant = uuid4()
    result = await alert_svc.acknowledge(
        session, alert_id=alert.id, tenant_id=other_tenant, actor_id=uuid4()
    )
    assert result is None


async def test_learning_happens_after_detection(session, tenant_id):
    """A fraudulent message must not poison the baseline it was judged against."""
    mailbox = await _mailbox(session, tenant_id)
    session.add(
        Counterparty(
            tenant_id=tenant_id,
            registrable_domain="gemini.com",
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
            message_count=20,
        )
    )
    await session.flush()
    cp = (await session.execute(select(Counterparty))).scalar_one()
    session.add(
        BankRecord(
            tenant_id=tenant_id,
            counterparty_id=cp.id,
            scheme="iban",
            identifier="GB94BARC10201530093459",
            first_seen_at=datetime.now(UTC),
        )
    )
    await session.commit()

    fraud = parse_message(
        _msg("Bank account changed, remit to IBAN GB33BUKB20201555555555 urgently."),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=OWNED,
    )
    await analyse_event(session, fraud, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    records = (await session.execute(select(BankRecord))).scalars().all()
    # The fraudulent account is not silently adopted as known-good.
    assert {r.identifier for r in records} == {"GB94BARC10201530093459"}
