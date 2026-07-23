"""Actually deliver the notifications the alert pipeline queues (PRD §8.1).

`alerts.raise_alert` records one `NotificationDelivery` row per ladder rung in the
`pending` state; without this module those rows are never sent. `deliver_pending`
resolves each rung's destination, calls the matching sender, and records the
outcome so the delivery ledger reflects what actually happened — `sent`,
`skipped` (rung not configured / no destination), or `failed`.

`run_escalation_cycle` is the free E6 safety net made to run: it escalates
unacknowledged Criticals to IT and, only when the ladder says so, to the paid SMS
rung. Acknowledgement — not delivery — is the signal, exactly as §8.1 requires.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import Alert, NotificationDelivery, PushSubscription, User
from envelock.notify.ladder import Rung
from envelock.notify.senders import Dispatcher, notification_from_alert
from envelock.platform import alerts as alert_svc


async def _destination(
    session: AsyncSession, delivery: NotificationDelivery, alert: Alert
) -> str | None:
    """Where this rung goes. In-app always has one; the rest need a registered
    out-of-band address, phone, or push subscription (PRD §8.2)."""
    rung = Rung(delivery.rung)
    if rung is Rung.L0_IN_APP:
        return str(delivery.user_id) if delivery.user_id else "dashboard"

    user = await session.get(User, delivery.user_id) if delivery.user_id else None
    if rung is Rung.L2_EMAIL:
        return user.out_of_band_email if user else None
    if rung is Rung.L3_SMS:
        return user.phone if user else None
    if rung is Rung.L1_PUSH:
        sub = (
            await session.execute(
                select(PushSubscription).where(PushSubscription.user_id == delivery.user_id)
            )
        ).scalars().first()
        return sub.endpoint if sub else None
    return None


async def deliver_pending(
    session: AsyncSession,
    *,
    alert_id: UUID | None = None,
    tenant_id: UUID | None = None,
    dispatcher: Dispatcher | None = None,
) -> list[NotificationDelivery]:
    """Send every pending delivery for an alert (or a whole tenant). Idempotent:
    a row leaves `pending` once attempted, so re-running never double-sends."""
    dispatcher = dispatcher or Dispatcher()
    query = select(NotificationDelivery).where(NotificationDelivery.status == "pending")
    if alert_id is not None:
        query = query.where(NotificationDelivery.alert_id == alert_id)
    if tenant_id is not None:
        query = query.where(NotificationDelivery.tenant_id == tenant_id)

    rows = (await session.execute(query)).scalars().all()
    touched: list[NotificationDelivery] = []
    for row in rows:
        alert = await session.get(Alert, row.alert_id)
        if alert is None:
            row.status = "skipped"
            row.error = "alert gone"
            touched.append(row)
            continue
        rung = Rung(row.rung)
        dest = await _destination(session, row, alert)
        if not dest:
            row.status = "skipped"
            row.error = "no destination"
            touched.append(row)
            continue
        result = await dispatcher.sender(rung).send(
            notification_from_alert(alert, row.tenant_id), to=dest
        )
        if result.delivered:
            row.status = "sent"
            row.cost_micros = result.cost_micros
            row.error = None
        else:
            # An unconfigured rung is skipped (infra not set up), not failed.
            row.status = "skipped" if "not configured" in result.reason else "failed"
            row.error = result.reason
        touched.append(row)
    return touched


async def run_escalation_cycle(
    session: AsyncSession,
    *,
    tenant_id: UUID | None = None,
    dispatcher: Dispatcher | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Escalate unacknowledged Criticals (E6). Meant to run on a short interval
    from an ops scheduler; returns what it did for observability."""
    dispatcher = dispatcher or Dispatcher()
    steps = await alert_svc.due_escalations(session, tenant_id=tenant_id, now=now)
    done: list[dict] = []
    for step in steps:
        alert = await session.get(Alert, step.alert_id)
        if alert is None:
            continue
        await alert_svc.mark_escalated(
            session, alert_id=step.alert_id, tenant_id=alert.tenant_id, to=step.to
        )
        # Escalation is the one place the paid SMS rung is allowed to fire.
        sms_dest = None
        admins = (
            await session.execute(
                select(User).where(User.tenant_id == alert.tenant_id, User.is_admin.is_(True))
            )
        ).scalars().all()
        for admin in admins:
            # Only a proven phone receives the paid rung — an unverified number
            # is as likely to be an attacker's as the owner's.
            if admin.phone and admin.phone_verified:
                sms_dest = admin.phone
                break
        sent_sms = False
        if sms_dest:
            result = await dispatcher.sms.send(
                notification_from_alert(alert, alert.tenant_id), to=sms_dest
            )
            sent_sms = result.delivered
        done.append(
            {
                "alert_id": str(step.alert_id),
                "to": step.to,
                "minutes_open": step.minutes_open,
                "sms_sent": sent_sms,
            }
        )
    return done
