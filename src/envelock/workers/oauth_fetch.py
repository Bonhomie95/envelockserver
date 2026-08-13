"""Live mail pull for Tier-1 (Graph / Gmail) OAuth mailboxes.

This closes the biggest launch gap: after OAuth consent a mailbox was marked
`FULL_API` but nothing ever read it — `gmail_fetch`/`graph_fetch` had no caller.
Here we decrypt the (refreshed) access token, pull recent mail, and run each
message through the same detection pipeline the IMAP worker uses. The pipeline
dedupes by (mailbox_id, rfc_message_id), so a webhook-less poll never
double-alerts.

A Graph subscription / Gmail Pub/Sub webhook (see api/webhooks.py) short-circuits
this for real-time delivery; polling is the always-correct fallback.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail.api_fetch import gmail_fetch, graph_fetch
from envelock.channels.mail.oauth_refresh import current_access_token
from envelock.core.enums import SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox
from envelock.notify.dispatch import deliver_pending
from envelock.platform.pipeline import analyse_event

logger = logging.getLogger("envelock.oauthfetch")

_OAUTH_SOURCES = {
    SourceMechanism.GRAPH_API.value,
    SourceMechanism.GMAIL_API.value,
}


async def _owned_domains(session: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    rows = (
        await session.execute(
            select(Domain.registrable_domain).where(Domain.tenant_id == tenant_id)
        )
    ).all()
    return frozenset(d for (d,) in rows)


async def _recipients(session: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    rows = (
        await session.execute(
            select(Mailbox.address).where(Mailbox.tenant_id == tenant_id)
        )
    ).all()
    return frozenset(a for (a,) in rows)


async def sync_oauth_mailbox(
    session: AsyncSession, mailbox: Mailbox, *, transport=None  # noqa: ANN001
) -> dict:
    """Fetch and analyse recent mail for one OAuth mailbox."""
    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)  # scope RLS to this mailbox's tenant
    tok = await current_access_token(session, mailbox.id)
    if tok is None:
        return {"ok": False, "reason": "no usable oauth token", "fetched": 0}
    access_token, provider = tok
    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)

    try:
        if provider == "google":
            events = await gmail_fetch(
                access_token=access_token,
                tenant_id=mailbox.tenant_id,
                mailbox_id=mailbox.id,
                owned_domains=owned,
                transport=transport,
            )
        else:
            events = await graph_fetch(
                access_token=access_token,
                tenant_id=mailbox.tenant_id,
                mailbox_id=mailbox.id,
                owned_domains=owned,
                mailbox_address=mailbox.address,
                transport=transport,
            )
    except Exception as exc:  # noqa: BLE001 — provider/network errors are non-fatal
        logger.warning("oauth fetch failed for mailbox %s: %s", mailbox.id, exc)
        return {"ok": False, "reason": str(exc), "fetched": 0}

    alerted = 0
    for event in events:
        pr = await analyse_event(
            session,
            event,
            tenant_id=mailbox.tenant_id,
            owned_domains=owned,
            recipients=recipients,
        )
        if pr.alert_id is not None:
            alerted += 1
            await deliver_pending(session, alert_id=pr.alert_id)

    mailbox.last_sync_at = datetime.now(UTC)
    await session.commit()
    return {"ok": True, "fetched": len(events), "alerted": alerted}


async def _oauth_mailboxes(session: AsyncSession) -> list[UUID]:
    rows = (
        await session.execute(
            select(Mailbox).where(Mailbox.is_active.is_(True))
        )
    ).scalars().all()
    return [m.id for m in rows if any(s in _OAUTH_SOURCES for s in (m.sources or []))]


async def fetch_all_oauth_mailboxes(*, transport=None) -> dict:  # noqa: ANN001
    """Poll every connected Tier-1 mailbox once. Per-mailbox session + try/except so
    one failure never aborts the cycle."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        ids = await _oauth_mailboxes(session)

    totals = {"mailboxes": 0, "fetched": 0, "alerted": 0, "errors": 0}
    for mailbox_id in ids:
        async with sessionmaker() as session:
            mailbox = await session.get(Mailbox, mailbox_id)
            if mailbox is None:
                continue
            try:
                summary = await sync_oauth_mailbox(session, mailbox, transport=transport)
            except Exception:  # noqa: BLE001
                logger.exception("oauth fetch: error on mailbox %s", mailbox_id)
                totals["errors"] += 1
                continue
        totals["mailboxes"] += 1
        if summary.get("ok"):
            totals["fetched"] += summary.get("fetched", 0)
            totals["alerted"] += summary.get("alerted", 0)
        else:
            totals["errors"] += 1
    return totals


__all__ = ["sync_oauth_mailbox", "fetch_all_oauth_mailboxes"]
