"""The notification ladder (PRD §8.1).

Free rungs first; the paid one fires only on escalation. Acknowledgement — not
delivery — is the escalation signal, because Web Push cannot confirm a human saw
anything.

Email can never be the primary channel: we would be alerting about mailbox
compromise, by email, to the compromised mailbox (PRD §8.2). L0 and L1 do not
touch the mailbox at all, and L2 targets a registered out-of-band address.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from envelock.core.enums import AlertTier


class Rung(StrEnum):
    L0_IN_APP = "L0"  # in-app + IT dashboard — free, always
    L1_PUSH = "L1"  # Web Push via the client sensor — free, self-hosted
    L2_EMAIL = "L2"  # our own SMTP, to the out-of-band address
    L3_SMS = "L3"  # paid — escalation only


@dataclass(frozen=True, slots=True)
class Recipient:
    user_id: str
    is_admin: bool
    has_push_subscription: bool
    out_of_band_email: str | None
    phone: str | None
    #: Whether this user runs the client sensor. Without it there is no L1
    #: channel, which is itself an SMS escalation trigger.
    has_sensor: bool


@dataclass(frozen=True, slots=True)
class LadderDecision:
    rungs: tuple[Rung, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class EscalationPolicy:
    critical_after_seconds: int = 900
    unacked_count: int = 5


def initial_rungs(tier: AlertTier, recipient: Recipient) -> LadderDecision:
    """Which rungs fire the moment an alert is raised."""
    rungs: list[Rung] = [Rung.L0_IN_APP]
    reason = "in-app and dashboard always receive every alert"

    if (
        tier in (AlertTier.MEDIUM, AlertTier.HIGH, AlertTier.CRITICAL)
        and recipient.has_push_subscription
    ):
        rungs.append(Rung.L1_PUSH)

    if tier in (AlertTier.HIGH, AlertTier.CRITICAL) and recipient.out_of_band_email:
        rungs.append(Rung.L2_EMAIL)
        reason = "high or critical also emails the out-of-band address"

    # A Critical for a user with no sensor has no L1 channel at all, so the paid
    # rung fires immediately rather than waiting for an ack that cannot arrive.
    if (
        tier is AlertTier.CRITICAL
        and not recipient.has_sensor
        and recipient.phone
    ):
        rungs.append(Rung.L3_SMS)
        reason = "critical alert for a user with no sensor — no push channel exists"

    return LadderDecision(tuple(rungs), reason)


def should_escalate_to_sms(
    *,
    tier: AlertTier,
    raised_at: datetime,
    now: datetime,
    acknowledged: bool,
    unacked_total: int,
    recipient: Recipient,
    policy: EscalationPolicy | None = None,
) -> LadderDecision | None:
    """The only path to a metered channel."""
    policy = policy or EscalationPolicy()

    if acknowledged or not recipient.phone:
        return None

    if tier is AlertTier.CRITICAL and now - raised_at >= timedelta(
        seconds=policy.critical_after_seconds
    ):
        return LadderDecision(
            (Rung.L3_SMS,),
            f"critical alert unacknowledged for {policy.critical_after_seconds // 60} minutes",
        )

    if unacked_total >= policy.unacked_count:
        return LadderDecision(
            (Rung.L3_SMS,),
            f"{unacked_total} notifications unacknowledged",
        )

    return None


def admin_escalation_due(
    *, tier: AlertTier, raised_at: datetime, now: datetime, acknowledged: bool
) -> str | None:
    """E6 — IT learns when a user ignores a notification.

    This free safety net is what makes it defensible to delay the paid rung.
    """
    if acknowledged or tier is not AlertTier.CRITICAL:
        return None
    elapsed = now - raised_at
    if elapsed >= timedelta(minutes=60):
        return "all_admins"
    if elapsed >= timedelta(minutes=15):
        return "it_admin"
    return None
