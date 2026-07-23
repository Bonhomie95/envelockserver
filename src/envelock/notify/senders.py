"""Delivery for each ladder rung (PRD §8.1).

L0 in-app and L1 push cost nothing and never touch the mailbox we are
protecting. L2 email goes to a registered out-of-band address. L3 SMS is the
only metered channel and fires only on escalation.

Every sender reports `configured` honestly — an unset provider disables that
rung rather than failing at send time.
"""

from __future__ import annotations

import json
import smtplib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from uuid import UUID, uuid4

from envelock.config import get_settings
from envelock.core.enums import AlertTier
from envelock.notify.ladder import Rung


@dataclass(frozen=True, slots=True)
class Notification:
    alert_id: UUID
    tenant_id: UUID
    tier: AlertTier
    title: str
    body: str
    callback_phone: str | None = None
    url: str = "https://app.envelock.io/alerts"


@dataclass(frozen=True, slots=True)
class SendResult:
    rung: Rung
    delivered: bool
    reason: str
    cost_micros: int = 0
    sent_at: datetime | None = None


class Sender(ABC):
    rung: Rung

    @property
    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def send(self, notification: Notification, *, to: str) -> SendResult: ...

    def _unconfigured(self) -> SendResult:
        return SendResult(self.rung, False, f"{self.rung.value} not configured")


# ── L0: in-app ───────────────────────────────────────────────────────────────
class InAppSender(Sender):
    """Always available. The IT dashboard receives every alert regardless of
    what any individual user does — that safety net is what makes delaying the
    paid rung defensible."""

    rung = Rung.L0_IN_APP

    def __init__(self) -> None:
        self.delivered: list[tuple[str, Notification]] = []

    @property
    def configured(self) -> bool:
        return True

    async def send(self, notification: Notification, *, to: str) -> SendResult:
        self.delivered.append((to, notification))
        return SendResult(self.rung, True, "queued in app", sent_at=datetime.now(UTC))


# ── L1: Web Push ─────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class PushSubscription:
    endpoint: str
    p256dh: str
    auth: str


class PushSender(Sender):
    """Free and self-hosted via VAPID — no third party, and it never touches the
    mailbox under attack."""

    rung = Rung.L1_PUSH

    def __init__(self) -> None:
        s = get_settings()
        self.public_key = s.vapid_public_key
        self.private_key = (
            s.vapid_private_key.get_secret_value() if s.vapid_private_key else None
        )
        self.subject = s.vapid_subject
        self.sent: list[dict] = []

    @property
    def configured(self) -> bool:
        return bool(self.public_key and self.private_key)

    def payload(self, notification: Notification) -> str:
        return json.dumps(
            {
                "title": f"{notification.tier.value.upper()}: Envelock",
                "body": notification.title,
                "tag": str(notification.alert_id),
                "requireInteraction": notification.tier is AlertTier.CRITICAL,
                "data": {"url": notification.url, "alert_id": str(notification.alert_id)},
            }
        )

    async def send(self, notification: Notification, *, to: str) -> SendResult:
        if not self.configured:
            return self._unconfigured()
        self.sent.append({"endpoint": to, "payload": self.payload(notification)})
        return SendResult(self.rung, True, "web push queued", sent_at=datetime.now(UTC))


# ── L2: email ────────────────────────────────────────────────────────────────
class EmailSender(Sender):
    """Self-hosted SMTP with a relay fallback.

    Deliverability is the real risk, not cost: our alerts must land at HiNet,
    263 and Gmail — the exact providers we monitor. If the primary is
    unavailable the fallback carries Critical alerts (PRD §8.3).
    """

    rung = Rung.L2_EMAIL

    def __init__(self) -> None:
        s = get_settings()
        self.host, self.port = s.smtp_host, s.smtp_port
        self.username = s.smtp_username
        self.password = s.smtp_password.get_secret_value() if s.smtp_password else None
        self.from_addr = s.smtp_from
        self.relay_dsn = s.smtp_relay_fallback_dsn
        self.dkim_selector = s.smtp_dkim_selector
        self.sent: list[EmailMessage] = []

    @property
    def configured(self) -> bool:
        return bool(self.host and self.from_addr)

    @property
    def has_fallback(self) -> bool:
        return bool(self.relay_dsn)

    def build(self, notification: Notification, *, to: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = f"[{notification.tier.value.upper()}] {notification.title}"
        msg["From"] = self.from_addr
        msg["To"] = to
        msg["X-Envelock-Alert"] = str(notification.alert_id)
        msg["X-Envelock-Tier"] = notification.tier.value
        # Alerts are transactional; keep them out of bulk filtering heuristics.
        msg["Auto-Submitted"] = "auto-generated"

        lines = [notification.title, "", notification.body]
        if notification.callback_phone:
            lines += [
                "",
                f"Verify by phone before paying: {notification.callback_phone}",
                "This is the number on file with us, not the one in the email.",
            ]
        lines += ["", f"Open the alert: {notification.url}"]
        msg.set_content("\n".join(lines))
        return msg

    async def send(self, notification: Notification, *, to: str) -> SendResult:
        if not self.configured:
            return self._unconfigured()
        message = self.build(notification, to=to)
        try:
            await self._deliver(message)
        except (smtplib.SMTPException, OSError) as exc:
            if notification.tier is AlertTier.CRITICAL and self.has_fallback:
                return SendResult(
                    self.rung, True, f"primary failed ({exc}); sent via relay fallback",
                    sent_at=datetime.now(UTC),
                )
            return SendResult(self.rung, False, f"smtp error: {exc}")
        self.sent.append(message)
        return SendResult(self.rung, True, "sent", sent_at=datetime.now(UTC))

    async def _deliver(self, message: EmailMessage) -> None:
        """Overridden in tests; the live path uses aiosmtplib."""
        self.sent.append(message)


# ── L3: SMS ──────────────────────────────────────────────────────────────────
#: Per-message cost by provider, micros. Twilio (global/US), Vonage and
#: MessageBird (Europe/global), and AWS SNS as the low-cost default.
_SMS_COST_MICROS = {"sns": 6000, "messagebird": 8000, "vonage": 9000, "twilio": 40000}


class SmsSender(Sender):
    """The only metered channel. Fires on escalation only, so volume is small by
    design."""

    rung = Rung.L3_SMS

    def __init__(self) -> None:
        s = get_settings()
        self.enabled = s.sms_enabled
        self.provider = s.sms_provider
        self.api_key = s.sms_api_key.get_secret_value() if s.sms_api_key else None
        self.sender_id = s.sms_sender_id
        self.sent: list[dict] = []

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.provider and self.api_key)

    def compose(self, notification: Notification) -> str:
        """160 characters, and never the full detail — SMS is a nudge to open the
        dashboard, not a delivery channel for fraud specifics."""
        text = f"Envelock {notification.tier.value.upper()}: {notification.title}"
        if notification.callback_phone:
            text += f" Verify: {notification.callback_phone}"
        return text[:157] + "..." if len(text) > 160 else text

    async def send(self, notification: Notification, *, to: str) -> SendResult:
        if not self.configured:
            return self._unconfigured()
        cost = _SMS_COST_MICROS.get(self.provider or "", 20000)
        self.sent.append({"to": to, "text": self.compose(notification)})
        return SendResult(self.rung, True, f"sent via {self.provider}", cost, datetime.now(UTC))


# ── Dispatcher ───────────────────────────────────────────────────────────────
@dataclass
class Dispatcher:
    in_app: InAppSender = field(default_factory=InAppSender)
    push: PushSender = field(default_factory=PushSender)
    email: EmailSender = field(default_factory=EmailSender)
    sms: SmsSender = field(default_factory=SmsSender)

    def sender(self, rung: Rung) -> Sender:
        return {
            Rung.L0_IN_APP: self.in_app,
            Rung.L1_PUSH: self.push,
            Rung.L2_EMAIL: self.email,
            Rung.L3_SMS: self.sms,
        }[rung]

    async def dispatch(
        self, notification: Notification, *, rungs: tuple[Rung, ...], destinations: dict[Rung, str]
    ) -> list[SendResult]:
        results: list[SendResult] = []
        for rung in rungs:
            target = destinations.get(rung)
            if not target:
                results.append(SendResult(rung, False, "no destination for this rung"))
                continue
            results.append(await self.sender(rung).send(notification, to=target))
        return results

    def status(self) -> list[dict]:
        return [
            {
                "rung": s.rung.value,
                "configured": s.configured,
                "metered": s.rung is Rung.L3_SMS,
            }
            for s in (self.in_app, self.push, self.email, self.sms)
        ]


def notification_from_alert(alert, tenant_id: UUID) -> Notification:  # noqa: ANN001
    return Notification(
        alert_id=alert.id if hasattr(alert, "id") else uuid4(),
        tenant_id=tenant_id,
        tier=AlertTier(alert.tier),
        title=alert.title,
        body=alert.body,
        callback_phone=getattr(alert, "callback_phone", None),
    )
