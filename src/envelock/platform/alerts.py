"""Group E — alert lifecycle, oversight and escalation (E1–E6).

Persistence-backed: alerts, findings and the audit trail all live in Postgres so
E5 ("IT sees who read it, who acted, who ignored it") is answerable after a
restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import AlertTier
from envelock.detections.base import FindingResult
from envelock.models import Alert, AuditEvent, Finding, NotificationDelivery
from envelock.notify.ladder import Recipient, initial_rungs
from envelock.risk.engine import RiskAssessment


class AuditAction:
    ALERT_RAISED = "alert.raised"
    ALERT_VIEWED = "alert.viewed"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_DISMISSED = "alert.dismissed"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_UNREAD = "alert.marked_unread"
    MESSAGE_QUARANTINED = "message.quarantined"
    MAILBOX_CONNECTED = "mailbox.connected"
    SETTINGS_CHANGED = "settings.changed"


async def record_audit(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    action: str,
    actor_id: UUID | None = None,
    target_type: str | None = None,
    target_id: UUID | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        id=uuid4(),
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail or {},
    )
    session.add(event)
    return event


async def raise_alert(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    mailbox_id: UUID | None,
    assessment: RiskAssessment,
    findings: list[FindingResult],
    message_id: UUID | None = None,
    recipients: list[Recipient] | None = None,
) -> Alert:
    """Persist an alert plus its evidence, and fan out the free ladder rungs."""
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        mailbox_id=mailbox_id,
        tier=assessment.tier.value,
        title=assessment.title[:255],
        body=assessment.body,
        requires_callback=assessment.requires_callback,
        callback_phone=assessment.callback_phone,
        state="open",
    )
    session.add(alert)
    await session.flush()

    for f in findings:
        session.add(
            Finding(
                id=uuid4(),
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                message_id=message_id,
                alert_id=alert.id,
                service=f.service,
                tier=f.tier.value,
                score=f.score,
                summary=f.summary,
                evidence=f.evidence,
            )
        )

    for recipient in recipients or []:
        decision = initial_rungs(assessment.tier, recipient)
        for rung in decision.rungs:
            session.add(
                NotificationDelivery(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    alert_id=alert.id,
                    user_id=UUID(recipient.user_id) if recipient.user_id else None,
                    rung=rung.value,
                    channel=rung.name.lower(),
                    status="pending",
                )
            )

    await record_audit(
        session,
        tenant_id=tenant_id,
        action=AuditAction.ALERT_RAISED,
        target_type="alert",
        target_id=alert.id,
        detail={"tier": assessment.tier.value, "services": list(assessment.services)},
    )
    return alert


async def acknowledge(
    session: AsyncSession, *, alert_id: UUID, tenant_id: UUID, actor_id: UUID
) -> Alert | None:
    """Acknowledgement — not delivery — stops the escalation clock (PRD §8.1)."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != tenant_id:
        return None
    alert.state = "acked"
    alert.acknowledged_at = datetime.now(UTC)
    alert.acknowledged_by = actor_id
    await record_audit(
        session,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=AuditAction.ALERT_ACKNOWLEDGED,
        target_type="alert",
        target_id=alert.id,
    )
    return alert


async def resolve(
    session: AsyncSession,
    *,
    alert_id: UUID,
    tenant_id: UUID,
    actor_id: UUID,
    dismissed: bool = False,
) -> Alert | None:
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != tenant_id:
        return None
    alert.state = "dismissed" if dismissed else "resolved"
    alert.resolved_at = datetime.now(UTC)
    await record_audit(
        session,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=AuditAction.ALERT_DISMISSED if dismissed else AuditAction.ALERT_RESOLVED,
        target_type="alert",
        target_id=alert.id,
    )
    return alert


@dataclass(frozen=True, slots=True)
class EscalationStep:
    alert_id: UUID
    tier: AlertTier
    to: str
    minutes_open: int


async def due_escalations(
    session: AsyncSession, *, now: datetime | None = None
) -> list[EscalationStep]:
    """E6 — IT learns when a user ignores a Critical.

    This free safety net is what makes it defensible to delay the paid SMS rung.
    """
    now = now or datetime.now(UTC)
    rows = (
        await session.execute(
            select(Alert).where(
                Alert.state == "open", Alert.tier == AlertTier.CRITICAL.value
            )
        )
    ).scalars()

    steps: list[EscalationStep] = []
    for alert in rows:
        created = alert.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        minutes = int((now - created).total_seconds() // 60)
        already = alert.escalated_at is not None
        if minutes >= 60:
            target = "all_admins"
        elif minutes >= 15 and not already:
            target = "it_admin"
        else:
            continue
        steps.append(
            EscalationStep(
                alert_id=alert.id, tier=AlertTier.CRITICAL, to=target, minutes_open=minutes
            )
        )
    return steps


async def mark_escalated(
    session: AsyncSession, *, alert_id: UUID, tenant_id: UUID, to: str
) -> None:
    alert = await session.get(Alert, alert_id)
    if alert is None:
        return
    alert.escalated_at = datetime.now(UTC)
    await record_audit(
        session,
        tenant_id=tenant_id,
        action=AuditAction.ALERT_ESCALATED,
        target_type="alert",
        target_id=alert_id,
        detail={"to": to},
    )


async def oversight_summary(session: AsyncSession, *, tenant_id: UUID) -> dict:
    """E4/E5 — what the IT dashboard shows, including who ignored what."""
    alerts = (
        (await session.execute(select(Alert).where(Alert.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)

    def _age_minutes(a: Alert) -> int:
        created = a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=UTC)
        return int((now - created).total_seconds() // 60)

    open_alerts = [a for a in alerts if a.state == "open"]
    return {
        "total": len(alerts),
        "open": len(open_alerts),
        "critical_open": sum(1 for a in open_alerts if a.tier == AlertTier.CRITICAL.value),
        "acknowledged": sum(1 for a in alerts if a.acknowledged_at is not None),
        "unacknowledged_over_15m": sum(
            1
            for a in open_alerts
            if a.tier == AlertTier.CRITICAL.value and _age_minutes(a) >= 15
        ),
        "by_tier": {
            tier.value: sum(1 for a in alerts if a.tier == tier.value)
            for tier in AlertTier
        },
    }


def sla_breached(alert_tier: AlertTier, opened_at: datetime, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    limits = {
        AlertTier.CRITICAL: timedelta(minutes=15),
        AlertTier.HIGH: timedelta(hours=1),
        AlertTier.MEDIUM: timedelta(days=1),
        AlertTier.LOW: timedelta(days=7),
    }
    return now - opened_at > limits[alert_tier]
