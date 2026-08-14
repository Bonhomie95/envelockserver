"""The live IMAP worker: turn a connected mailbox into actual protection.

This is the piece that was missing. `connect_imap` stores an encrypted password
and marks the mailbox connected; without this worker nothing ever *reads* the
mailbox, so no inbound mail is analysed. Here we:

  1. decrypt the stored credential (only ever in this process),
  2. pull the messages we have not seen (`imap_sync.fetch_new`),
  3. run each through the real detection pipeline (`analyse_event`),
  4. for a Protected mailbox, move a flagged message out of the inbox
     (`imap_sync.quarantine_message`) — the quarantine that is the product,
  5. deliver the queued notifications,
  6. advance the per-mailbox UID cursor so the next poll only sees new mail.

The IMAP client is injectable end to end (`client_factory`) so the whole path is
tested without a live server. Each mailbox is polled in its own DB session and
its own try/except: one unreachable server or one poisoned message never aborts
the rest of the cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import imap_sync
from envelock.channels.mail.forward_runner import _recipients
from envelock.channels.mail.parser import parse_message
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox, MailboxCredential
from envelock.notify.dispatch import deliver_pending
from envelock.platform.pipeline import analyse_event
from envelock.security.crypto import CryptoError, SealedSecret, open_secret

logger = logging.getLogger("envelock.imap")

_IMAP_SOURCES = {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}

#: Last poll cycle's outcome, surfaced at GET /status/channels so a stalled or
#: erroring worker is visible in the dashboard rather than only in logs.
_LAST_CYCLE: dict = {
    "ran_at": None,
    "mailboxes": 0,
    "fetched": 0,
    "alerted": 0,
    "quarantined": 0,
    "errors": 0,
}


def worker_health() -> dict:
    """Health snapshot of the live IMAP worker for the ops status endpoint."""
    return dict(_LAST_CYCLE)


async def _owned_domains(session: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    rows = (
        await session.execute(
            select(Domain.registrable_domain).where(Domain.tenant_id == tenant_id)
        )
    ).all()
    return frozenset(d for (d,) in rows)


def _decrypt_password(cred: MailboxCredential) -> str:
    sealed = SealedSecret(
        ciphertext=cred.ciphertext, wrapped_dek=cred.wrapped_dek, key_id=cred.key_id or ""
    )
    return open_secret(sealed, aad=str(cred.mailbox_id).encode()).decode()


async def sync_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    client_factory=None,  # noqa: ANN001 — imap_sync.ClientFactory, injected in tests
) -> dict:
    """Poll one mailbox once and analyse every new message. Commits on success."""
    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)  # scope RLS to this mailbox's tenant
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if cred is None or cred.kind != "imap_password" or not cred.imap_host:
        return {"ok": False, "reason": "no imap credential", "fetched": 0}

    try:
        password = _decrypt_password(cred)
    except CryptoError:
        logger.warning("imap: could not decrypt credential for mailbox %s", mailbox.id)
        # The credential is dead (master key rotated, or ciphertext tampered). Flag
        # the mailbox so the UI prompts a reconnect instead of showing a healthy
        # "connected" state that silently protects nothing.
        mailbox.needs_reconnect = True
        mailbox.connection_error = (
            "stored password can no longer be decrypted — please reconnect this mailbox"
        )
        await session.commit()
        return {
            "ok": False,
            "reason": "credential could not be decrypted — reconnect required",
            "needs_reconnect": True,
            "fetched": 0,
        }

    host = cred.imap_host
    port = cred.imap_port or 993
    security = cred.imap_security or "ssl"
    username = (cred.imap_username or mailbox.address).strip()
    protected = mailbox.mailbox_class == MailboxClass.PROTECTED.value

    result = await asyncio.to_thread(
        imap_sync.fetch_new,
        host=host,
        port=port,
        security=security,
        username=username,
        password=password,
        since_uid=cred.imap_last_uid,
        uidvalidity=cred.imap_uidvalidity,
        limit=imap_sync.DEFAULT_LIMIT,
        client_factory=client_factory,
    )
    cred.imap_last_polled_at = datetime.now(UTC)

    if not result.ok:
        logger.warning("imap: poll failed for mailbox %s — %s", mailbox.id, result.error)
        if result.auth_failed:
            # The server rejected the password — reconnect needed, not transient.
            mailbox.needs_reconnect = True
            mailbox.connection_error = (
                "the mail server rejected the stored password — please reconnect"
            )
        await session.commit()
        return {
            "ok": False,
            "reason": result.error,
            "needs_reconnect": result.auth_failed,
            "fetched": 0,
        }

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)

    alerts: list[dict] = []
    quarantined = 0
    for msg in result.messages:
        event = parse_message(
            msg.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE if protected else SourceMechanism.IMAP_POLL,
            owned_domains=owned,
            remediable=protected,  # only an IDLE/Protected mailbox can quarantine
            source_ref=str(msg.uid),
        )
        pr = await analyse_event(
            session,
            event,
            tenant_id=mailbox.tenant_id,
            owned_domains=owned,
            recipients=recipients,
        )
        if pr.alert_id is not None:
            alerts.append(
                {
                    "uid": msg.uid,
                    "alert_id": str(pr.alert_id),
                    "tier": pr.assessment.tier.value if pr.assessment else None,
                    "title": pr.assessment.title if pr.assessment else None,
                }
            )
            # Protected mailbox + a message still in the inbox → pull it out.
            if protected:
                moved = await asyncio.to_thread(
                    imap_sync.quarantine_message,
                    host=host,
                    port=port,
                    security=security,
                    username=username,
                    password=password,
                    uid=msg.uid,
                    client_factory=client_factory,
                )
                if moved:
                    quarantined += 1
            # Fire the notifications this alert queued.
            await deliver_pending(session, alert_id=pr.alert_id)

    if result.uidvalidity is not None:
        cred.imap_uidvalidity = result.uidvalidity
    if result.highest_uid is not None:
        cred.imap_last_uid = result.highest_uid
    mailbox.last_sync_at = datetime.now(UTC)
    # A successful poll clears any prior connection problem.
    if mailbox.needs_reconnect:
        mailbox.needs_reconnect = False
        mailbox.connection_error = None

    await session.commit()
    return {
        "ok": True,
        "fetched": len(result.messages),
        "alerted": len(alerts),
        "quarantined": quarantined,
        "alerts": alerts,
    }


async def backfill_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    days: int,
    limit: int | None = None,
    client_factory=None,  # noqa: ANN001
) -> dict:
    """Onboarding backfill (E11): pull the last ``days`` of history and run each
    message through the pipeline so A9 stylometry and A12 baselines work on day one,
    not day ninety. Analysis + learning only — old mail is never quarantined.

    ``days`` is the look-back window and ``limit`` the message ceiling (defaults to
    ENVELOCK_BACKFILL_MAX_MESSAGES) — a large ``days`` scans effectively all history."""
    from datetime import timedelta

    from envelock.config import get_settings

    if limit is None:
        limit = get_settings().backfill_max_messages

    from envelock.channels.mail.parser import parse_message

    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if cred is None or cred.kind != "imap_password" or not cred.imap_host:
        return {"ok": False, "reason": "no imap credential", "analysed": 0}

    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)
    try:
        password = _decrypt_password(cred)
    except CryptoError:
        return {"ok": False, "reason": "credential could not be decrypted", "analysed": 0}

    since_date = (datetime.now(UTC) - timedelta(days=days)).date()
    result = await asyncio.to_thread(
        imap_sync.fetch_since,
        host=cred.imap_host,
        port=cred.imap_port or 993,
        security=cred.imap_security or "ssl",
        username=(cred.imap_username or mailbox.address).strip(),
        password=password,
        since_date=since_date,
        limit=limit,
        client_factory=client_factory,
    )
    if not result.ok:
        return {"ok": False, "reason": result.error, "analysed": 0}

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)
    analysed = 0
    for msg in result.messages:
        event = parse_message(
            msg.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_POLL,
            owned_domains=owned,
            remediable=False,  # never quarantine historical mail
            source_ref=str(msg.uid),
        )
        await analyse_event(
            session, event, tenant_id=mailbox.tenant_id,
            owned_domains=owned, recipients=recipients,
        )
        analysed += 1

    mailbox.backfilled_at = datetime.now(UTC)
    await session.commit()
    return {"ok": True, "analysed": analysed, "days": days}


async def _imap_mailboxes(session: AsyncSession) -> list[Mailbox]:
    """Every active mailbox that has an IMAP source and a stored credential."""
    rows = (
        (
            await session.execute(
                select(Mailbox)
                .join(MailboxCredential, MailboxCredential.mailbox_id == Mailbox.id)
                .where(
                    Mailbox.is_active.is_(True),
                    MailboxCredential.kind == "imap_password",
                )
            )
        )
        .scalars()
        .all()
    )
    return [m for m in rows if any(s in _IMAP_SOURCES for s in (m.sources or []))]


async def run_imap_poll_cycle(*, client_factory=None) -> dict:  # noqa: ANN001
    """Poll every connected IMAP mailbox once. Each mailbox gets its own session
    so a failure is isolated. Returns an aggregate summary for diagnostics."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        mailboxes = await _imap_mailboxes(session)
        mailbox_ids = [m.id for m in mailboxes]

    totals = {"mailboxes": 0, "fetched": 0, "alerted": 0, "quarantined": 0, "errors": 0}
    for mailbox_id in mailbox_ids:
        async with sessionmaker() as session:
            mailbox = await session.get(Mailbox, mailbox_id)
            if mailbox is None:
                continue
            try:
                summary = await sync_mailbox(
                    session, mailbox, client_factory=client_factory
                )
            except Exception:  # noqa: BLE001 — never let one mailbox kill the cycle
                logger.exception("imap: unexpected error polling mailbox %s", mailbox_id)
                totals["errors"] += 1
                continue
        totals["mailboxes"] += 1
        if summary.get("ok"):
            totals["fetched"] += summary.get("fetched", 0)
            totals["alerted"] += summary.get("alerted", 0)
            totals["quarantined"] += summary.get("quarantined", 0)
        else:
            totals["errors"] += 1
    _LAST_CYCLE.update(totals, ran_at=datetime.now(UTC).isoformat())
    return totals


async def imap_poll_loop(stop: asyncio.Event, *, interval_seconds: int) -> None:
    """Run `run_imap_poll_cycle` forever, `interval_seconds` apart, until stopped.

    Started from the FastAPI lifespan. A poll interval is a correct, reliable v1
    for both Protected and Monitored mailboxes; true IDLE (sub-second latency for
    Protected) is a latency optimisation layered on top later.
    """
    logger.info("imap poll loop started (interval=%ss)", interval_seconds)
    while not stop.is_set():
        try:
            totals = await run_imap_poll_cycle()
            if totals["mailboxes"]:
                logger.info("imap poll cycle: %s", totals)
        except Exception:  # noqa: BLE001
            logger.exception("imap: poll cycle crashed; continuing")
        # Sleep the interval, but wake immediately if asked to stop.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
    logger.info("imap poll loop stopped")


__all__ = ["sync_mailbox", "run_imap_poll_cycle", "imap_poll_loop"]
