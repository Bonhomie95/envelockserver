"""Keep Tier-1 OAuth access tokens alive (PRD §17.1).

Access tokens expire in ~1 hour; without a refresh loop every Graph/Gmail mailbox
goes dark shortly after connection. The scheduler calls `refresh_due_tokens` on an
interval: it finds tokens near expiry, exchanges the sealed refresh token for a
fresh access token, and re-seals — all decryption happening only here in the
worker, never in the API process.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import oauth
from envelock.core.enums import SourceMechanism
from envelock.models import Mailbox, MailboxCredential
from envelock.security.crypto import CryptoError, SealedSecret, open_secret, seal

logger = logging.getLogger("envelock.oauth")

#: Refresh once a token is within this window of expiry (or already expired).
_REFRESH_MARGIN = timedelta(minutes=10)


def provider_from_sources(sources: list[str] | None) -> str | None:
    """Derive the OAuth provider from the mailbox's normalised sources."""
    s = set(sources or [])
    if SourceMechanism.GRAPH_API.value in s or SourceMechanism.ENTRA_LOGS.value in s:
        return "microsoft"
    if SourceMechanism.GMAIL_API.value in s or SourceMechanism.GOOGLE_REPORTS.value in s:
        return "google"
    return None


def _open_token_payload(cred: MailboxCredential) -> dict:
    sealed = SealedSecret(
        ciphertext=cred.ciphertext, wrapped_dek=cred.wrapped_dek, key_id=cred.key_id or ""
    )
    return json.loads(open_secret(sealed, aad=str(cred.mailbox_id).encode()).decode())


def _reseal(cred: MailboxCredential, payload: dict, expires_in: int) -> None:
    sealed = seal(json.dumps(payload).encode(), aad=str(cred.mailbox_id).encode())
    cred.ciphertext = sealed.ciphertext
    cred.wrapped_dek = sealed.wrapped_dek
    cred.key_id = sealed.key_id
    cred.token_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)


async def refresh_one(
    session: AsyncSession, cred: MailboxCredential, mailbox: Mailbox
) -> bool:
    """Refresh a single mailbox's access token. Returns True on success."""
    provider_name = provider_from_sources(mailbox.sources)
    prov = oauth.provider_for(provider_name) if provider_name else None
    if prov is None or not oauth.is_configured(prov):
        return False
    try:
        payload = _open_token_payload(cred)
    except CryptoError:
        mailbox.needs_reconnect = True
        mailbox.connection_error = "stored OAuth token could not be decrypted — reconnect"
        return False

    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        mailbox.needs_reconnect = True
        mailbox.connection_error = "no refresh token on file — reconnect to re-consent"
        return False

    try:
        tokens = await oauth.refresh_tokens(prov, refresh_token=refresh_token)
    except oauth.OAuthError as exc:
        logger.warning("oauth refresh failed for mailbox %s: %s", mailbox.id, exc)
        return False

    _reseal(
        cred,
        {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "scope": tokens.scope,
        },
        tokens.expires_in,
    )
    if mailbox.needs_reconnect:
        mailbox.needs_reconnect = False
        mailbox.connection_error = None
    return True


async def refresh_due_tokens(session: AsyncSession, *, now: datetime | None = None) -> int:
    """Refresh every OAuth token at or near expiry. Returns the count refreshed."""
    now = now or datetime.now(UTC)
    due_before = now + _REFRESH_MARGIN
    rows = (
        await session.execute(
            select(MailboxCredential, Mailbox)
            .join(Mailbox, Mailbox.id == MailboxCredential.mailbox_id)
            .where(
                MailboxCredential.kind == "oauth_token",
                Mailbox.is_active.is_(True),
                or_(
                    MailboxCredential.token_expires_at.is_(None),
                    MailboxCredential.token_expires_at <= due_before,
                ),
            )
        )
    ).all()
    refreshed = 0
    for cred, mailbox in rows:
        if await refresh_one(session, cred, mailbox):
            refreshed += 1
    if rows:
        await session.commit()
    return refreshed


async def current_access_token(
    session: AsyncSession, mailbox_id: UUID
) -> tuple[str, str] | None:
    """Return (access_token, provider) for a mailbox, refreshing first if stale.
    Used by the fetch worker. None if the mailbox has no usable OAuth credential."""
    row = (
        await session.execute(
            select(MailboxCredential, Mailbox)
            .join(Mailbox, Mailbox.id == MailboxCredential.mailbox_id)
            .where(
                MailboxCredential.mailbox_id == mailbox_id,
                MailboxCredential.kind == "oauth_token",
            )
        )
    ).first()
    if row is None:
        return None
    cred, mailbox = row
    provider_name = provider_from_sources(mailbox.sources)
    if provider_name is None:
        return None
    now = datetime.now(UTC)
    if cred.token_expires_at is None or cred.token_expires_at <= now + _REFRESH_MARGIN:
        if not await refresh_one(session, cred, mailbox):
            return None
        await session.commit()
    try:
        payload = _open_token_payload(cred)
    except CryptoError:
        return None
    token = payload.get("access_token")
    return (token, provider_name) if token else None
