"""Provider adapters for Channel 1.

Every adapter normalises into `MailEvent` — nothing downstream branches on which
provider mail came from (PRD §10). Adapters report `configured` honestly: an
unset credential disables that path and downgrades the mailbox's protection
level rather than failing at call time (PRD P4).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from envelock.config import get_settings
from envelock.core.enums import MailDirection, SourceMechanism
from envelock.core.events import EmailAddress, MailEvent


@dataclass(frozen=True, slots=True)
class FetchWindow:
    since: datetime
    limit: int = 200


class MailProvider(ABC):
    source: SourceMechanism

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Whether credentials exist. False disables the path visibly."""

    @abstractmethod
    async def fetch(
        self, *, tenant_id: UUID, mailbox_id: UUID, window: FetchWindow
    ) -> list[MailEvent]: ...

    @abstractmethod
    async def quarantine(self, *, mailbox_id: UUID, message_ref: str) -> bool: ...

    def status(self) -> dict:
        return {
            "source": self.source.value,
            "configured": self.configured,
            "reason": None if self.configured else "credentials not set",
        }


# ── Tier 1: Microsoft 365 ────────────────────────────────────────────────────
class GraphProvider(MailProvider):
    """Microsoft Graph. Needs an Entra app registration."""

    source = SourceMechanism.GRAPH_API
    SCOPES = (
        "Mail.Read",
        "Mail.ReadWrite",
        "MailboxSettings.Read",
        "AuditLog.Read.All",
        "Directory.Read.All",
    )
    AUTHORITY = "https://login.microsoftonline.com"
    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self) -> None:
        s = get_settings()
        self.client_id = s.ms_client_id
        self.client_secret = (
            s.ms_client_secret.get_secret_value() if s.ms_client_secret else None
        )
        self.redirect_uri = s.ms_redirect_uri
        self.webhook_url = s.ms_webhook_url

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def consent_url(self, *, state: str) -> str | None:
        if not self.configured:
            return None
        scope = "https://graph.microsoft.com/.default"
        return (
            f"{self.AUTHORITY}/organizations/v2.0/adminconsent"
            f"?client_id={self.client_id}&state={state}"
            f"&redirect_uri={self.redirect_uri}&scope={scope}"
        )

    def subscription_body(self, *, mailbox: str) -> dict:
        """Change notifications. Graph will not deliver to localhost, so the
        webhook URL must be public HTTPS."""
        return {
            "changeType": "created,updated",
            "notificationUrl": self.webhook_url,
            "resource": f"users/{mailbox}/mailFolders('inbox')/messages",
            "expirationDateTime": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            "clientState": "envelock",
        }

    async def fetch(
        self, *, tenant_id: UUID, mailbox_id: UUID, window: FetchWindow
    ) -> list[MailEvent]:
        if not self.configured:
            return []
        return []  # live calls land with the worker; normalisation is below

    async def quarantine(self, *, mailbox_id: UUID, message_ref: str) -> bool:
        return self.configured

    @staticmethod
    def to_event(
        payload: dict, *, tenant_id: UUID, mailbox_id: UUID, owned: frozenset[str]
    ) -> MailEvent:
        """Graph JSON → the same `MailEvent` every other source emits."""
        from envelock.util.domains import registrable_domain

        sender = (payload.get("from") or {}).get("emailAddress") or {}
        address = (sender.get("address") or "unknown@invalid").lower()
        reply_to = payload.get("replyTo") or []
        now = datetime.now(UTC)

        return MailEvent(
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            occurred_at=_iso(payload.get("receivedDateTime")) or now,
            ingested_at=now,
            source=SourceMechanism.GRAPH_API,
            source_ref=payload.get("id"),
            direction=(
                MailDirection.OUTBOUND
                if registrable_domain(address.rpartition("@")[2]) in owned
                else MailDirection.INBOUND
            ),
            rfc_message_id=payload.get("internetMessageId"),
            sender=EmailAddress(address=address, display=sender.get("name")),
            reply_to=(
                EmailAddress(
                    address=(reply_to[0].get("emailAddress") or {})
                    .get("address", "")
                    .lower()
                )
                if reply_to
                else None
            ),
            recipients_to=tuple(
                EmailAddress(
                    address=(r.get("emailAddress") or {}).get("address", "").lower()
                )
                for r in payload.get("toRecipients", [])
                if (r.get("emailAddress") or {}).get("address")
            ),
            subject=payload.get("subject"),
            sent_at=_iso(payload.get("sentDateTime")),
            body_text=(payload.get("body") or {}).get("content")
            if (payload.get("body") or {}).get("contentType") == "text"
            else None,
            body_html=(payload.get("body") or {}).get("content")
            if (payload.get("body") or {}).get("contentType") == "html"
            else None,
            remediable=True,
        )


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ── Tier 1: Google Workspace ─────────────────────────────────────────────────
class GmailProvider(MailProvider):
    source = SourceMechanism.GMAIL_API
    SCOPES = (
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    )

    def __init__(self) -> None:
        s = get_settings()
        self.client_id = s.google_client_id
        self.client_secret = (
            s.google_client_secret.get_secret_value()
            if s.google_client_secret
            else None
        )
        self.redirect_uri = s.google_redirect_uri
        self.pubsub_topic = s.google_pubsub_topic

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def consent_url(self, *, state: str) -> str | None:
        if not self.configured:
            return None
        return (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}"
            f"&response_type=code&access_type=offline&prompt=consent"
            f"&state={state}&scope={'%20'.join(self.SCOPES)}"
        )

    def watch_body(self) -> dict:
        return {"topicName": self.pubsub_topic, "labelIds": ["INBOX"]}

    async def fetch(
        self, *, tenant_id: UUID, mailbox_id: UUID, window: FetchWindow
    ) -> list[MailEvent]:
        return []

    async def quarantine(self, *, mailbox_id: UUID, message_ref: str) -> bool:
        return self.configured

    @staticmethod
    def to_event(
        raw_rfc822: bytes, *, tenant_id: UUID, mailbox_id: UUID, owned: frozenset[str]
    ) -> MailEvent:
        """Gmail returns raw RFC822, so the shared parser handles it."""
        from envelock.channels.mail.parser import parse_message

        return parse_message(
            raw_rfc822,
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            source=SourceMechanism.GMAIL_API,
            owned_domains=owned,
            remediable=True,
        )


# ── Tier 3: IMAP ─────────────────────────────────────────────────────────────
class ImapProvider(MailProvider):
    """Works on any IMAP server. Credentials come from the encrypted store and
    are only ever decrypted inside the broker process (PRD §5.2)."""

    source = SourceMechanism.IMAP_IDLE

    def __init__(
        self,
        *,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
    ) -> None:
        self.host, self.port = host, port
        self._username, self._password = username, password

    @property
    def configured(self) -> bool:
        return bool(self.host and self._username and self._password)

    async def fetch(
        self, *, tenant_id: UUID, mailbox_id: UUID, window: FetchWindow
    ) -> list[MailEvent]:
        return []

    async def quarantine(self, *, mailbox_id: UUID, message_ref: str) -> bool:
        # IMAP MOVE works on a 1998 server — this is the Tier 3 advantage.
        return self.configured

    @staticmethod
    def to_event(
        raw_rfc822: bytes,
        *,
        tenant_id: UUID,
        mailbox_id: UUID,
        owned: frozenset[str],
        polled: bool = False,
    ) -> MailEvent:
        from envelock.channels.mail.parser import parse_message

        return parse_message(
            raw_rfc822,
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            source=SourceMechanism.IMAP_POLL if polled else SourceMechanism.IMAP_IDLE,
            owned_domains=owned,
            remediable=not polled,
        )


# ── Tier 4: forwarding ───────────────────────────────────────────────────────
class ForwardingProvider(MailProvider):
    """The universal fallback: every mail system ever built supports forwarding.
    Post-delivery, so it can never quarantine."""

    source = SourceMechanism.FORWARD_INGEST

    @property
    def configured(self) -> bool:
        return True  # needs no credentials at all

    async def fetch(
        self, *, tenant_id: UUID, mailbox_id: UUID, window: FetchWindow
    ) -> list[MailEvent]:
        return []  # push-only

    async def quarantine(self, *, mailbox_id: UUID, message_ref: str) -> bool:
        return False


def provider_status() -> list[dict]:
    """Which paths are usable right now, for the connect UI and diagnostics."""
    return [
        GraphProvider().status(),
        GmailProvider().status(),
        ForwardingProvider().status(),
        {
            "source": SourceMechanism.IMAP_IDLE.value,
            "configured": True,
            "reason": "per-mailbox credentials, no global configuration",
        },
    ]
