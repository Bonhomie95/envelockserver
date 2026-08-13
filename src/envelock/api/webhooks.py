"""Tier-1 push receivers (PRD §5, §12.11D — "Protected = real-time").

Microsoft Graph and Gmail can push a notification the instant mail arrives, which
is what makes sub-second quarantine possible instead of waiting for the next poll.
This module is the receiver those providers call:

* **Graph** validates a new subscription by echoing `validationToken`, then POSTs
  a change notification we turn into a targeted fetch of the affected mailbox.
* **Gmail** (via Pub/Sub push) POSTs `{message:{data: base64(json)}}` carrying the
  affected address; we fetch that mailbox.

The polling fetch job (workers/oauth_fetch) remains the always-correct fallback,
so a missed or unconfigured webhook only costs latency, never coverage.
"""

from __future__ import annotations

import base64
import json
import logging

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from envelock.db import get_sessionmaker
from envelock.models import Mailbox

logger = logging.getLogger("envelock.webhooks")

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


async def _fetch_mailbox_by_address(address: str) -> dict | None:
    from envelock.workers.oauth_fetch import sync_oauth_mailbox

    async with get_sessionmaker()() as session:
        mailbox = (
            await session.execute(
                select(Mailbox).where(
                    Mailbox.address == address.lower(), Mailbox.is_active.is_(True)
                )
            )
        ).scalars().first()
        if mailbox is None:
            return None
        return await sync_oauth_mailbox(session, mailbox)


@router.post("/graph")
@router.get("/graph")
async def graph_notifications(request: Request) -> Response:
    """Microsoft Graph change-notification endpoint.

    Subscription validation: Graph calls this with `?validationToken=...` and
    expects it echoed back as text/plain within 10s. Change notifications: a JSON
    body whose `value[].clientState` we set to the mailbox address at subscription
    time, so we can fetch exactly the affected mailbox."""
    token = request.query_params.get("validationToken")
    if token is not None:
        return Response(content=token, media_type="text/plain")

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return Response(status_code=202)

    for note in body.get("value", []) or []:
        address = note.get("clientState")
        if address:
            try:
                await _fetch_mailbox_by_address(address)
            except Exception as exc:  # noqa: BLE001 — never fail a provider callback
                logger.warning("graph webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)


@router.post("/gmail")
async def gmail_notifications(request: Request) -> Response:
    """Gmail Pub/Sub push endpoint. The message data base64-encodes
    `{"emailAddress": ..., "historyId": ...}`."""
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return Response(status_code=202)

    message = body.get("message") or {}
    data_b64 = message.get("data")
    if not data_b64:
        return Response(status_code=202)
    try:
        decoded = json.loads(base64.b64decode(data_b64).decode())
    except Exception:  # noqa: BLE001
        return Response(status_code=202)

    address = decoded.get("emailAddress")
    if address:
        try:
            await _fetch_mailbox_by_address(address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("gmail webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)
