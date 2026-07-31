"""Wire the transport-agnostic `ForwardingIngest` (SMTP core) to the real
detection pipeline.

`ForwardingIngest` deliberately knows nothing about the database or the
detection engine — it takes a `resolve_tenant` and an `on_message` callback so it
stays unit-testable without a socket. This module provides the production
implementations of those two callbacks: identify the tenant from the private
ingest address, then run the forwarded copy through the same pipeline the HTTP
`/ingest` endpoint uses.

Deploying live forwarding is then two steps, both outside the app:
  1. Publish MX for the ingest domain (`ENVELOCK_INGEST_DOMAIN`) to an SMTP
     front end (an aiosmtpd process, or a provider inbound-parse webhook).
  2. Have that front end call `ingest.handle_rcpt` / `ingest.handle_data`.

The tenant-identification and pipeline halves — everything that was missing —
live here and are covered by tests.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from envelock.channels.mail.ingest import ForwardingIngest
from envelock.channels.mail.parser import parse_message
from envelock.core.enums import SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox, PushSubscription, User
from envelock.notify.dispatch import deliver_pending
from envelock.notify.ladder import Recipient
from envelock.platform.pipeline import analyse_event


async def resolve_tenant_by_token(token: str) -> UUID | None:
    """Map an ingest-address token back to its tenant.

    The token is the domain's `verification_token`, minted at bootstrap and
    embedded in `t-<token>@<ingest_domain>`. No token, no tenant — a forwarded
    copy carries no other credential, which is the whole point of the scheme.
    """
    async with get_sessionmaker()() as session:
        domain = (
            await session.execute(
                select(Domain).where(Domain.verification_token == token).limit(1)
            )
        ).scalar_one_or_none()
        return domain.tenant_id if domain else None


async def _recipients(session, tenant_id: UUID) -> list[Recipient]:
    users = (
        await session.execute(select(User).where(User.tenant_id == tenant_id))
    ).scalars().all()
    push_user_ids = {
        uid
        for (uid,) in (
            await session.execute(
                select(PushSubscription.user_id).where(
                    PushSubscription.tenant_id == tenant_id
                )
            )
        ).all()
    }
    return [
        Recipient(
            user_id=str(u.id),
            is_admin=u.is_admin,
            has_push_subscription=u.id in push_user_ids,
            out_of_band_email=u.out_of_band_email,
            phone=u.phone if u.phone_verified else None,
            has_sensor=u.id in push_user_ids,
        )
        for u in users
    ]


async def _mailbox_for(session, tenant_id: UUID, raw: bytes) -> Mailbox | None:
    """Attribute the forwarded copy to one of the tenant's mailboxes.

    A forwarded message still carries its original To/Cc, so we match those
    against the tenant's connected mailboxes. If none matches (the recipient
    isn't a tracked mailbox), we fall back to the tenant's first mailbox so the
    copy is still analysed rather than dropped.
    """
    mailboxes = (
        (await session.execute(select(Mailbox).where(Mailbox.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    if not mailboxes:
        return None
    by_address = {m.address.lower(): m for m in mailboxes}

    # Peek at the recipients without committing to a mailbox_id yet.
    peek = parse_message(
        raw,
        tenant_id=tenant_id,
        mailbox_id=mailboxes[0].id,
        source=SourceMechanism.FORWARD_INGEST,
    )
    for addr in (*peek.recipients_to, *peek.recipients_cc):
        hit = by_address.get(addr.address.lower())
        if hit is not None:
            return hit
    return mailboxes[0]


async def run_forwarded_message(tenant_id: UUID, raw: bytes) -> dict:
    """Run one forwarded copy through the real pipeline for a resolved tenant."""
    async with get_sessionmaker()() as session:
        mailbox = await _mailbox_for(session, tenant_id, raw)
        if mailbox is None:
            # No mailbox to attribute it to — nothing to protect yet.
            return {"alerted": False, "reason": "no mailbox connected"}

        owned = {
            d
            for (d,) in (
                await session.execute(
                    select(Domain.registrable_domain).where(
                        Domain.tenant_id == tenant_id
                    )
                )
            ).all()
        }
        # A forwarded copy arrives post-delivery, so it is never remediable — the
        # message is already in the user's inbox (PRD §4 fn.3).
        event = parse_message(
            raw,
            tenant_id=tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.FORWARD_INGEST,
            owned_domains=frozenset(owned),
            remediable=False,
        )
        recipients = await _recipients(session, tenant_id)
        result = await analyse_event(
            session,
            event,
            tenant_id=tenant_id,
            owned_domains=frozenset(owned),
            recipients=recipients,
        )
        delivered = 0
        if result.alert_id is not None:
            touched = await deliver_pending(session, alert_id=result.alert_id)
            delivered = sum(1 for d in touched if d.status == "sent")
        await session.commit()
        return {
            "alerted": result.alerted,
            "alert_id": str(result.alert_id) if result.alert_id else None,
            "tier": result.assessment.tier.value if result.assessment else None,
            "notifications_sent": delivered,
        }


def build_forwarding_ingest() -> ForwardingIngest:
    """Production-wired SMTP ingest core. An SMTP front end drives its
    `handle_rcpt` / `handle_data`; everything downstream is real."""
    return ForwardingIngest(
        resolve_tenant=resolve_tenant_by_token,
        on_message=lambda *, tenant_id, raw: run_forwarded_message(tenant_id, raw),
    )
