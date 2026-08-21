"""Tier-1 push receivers (PRD §5, §12.11D — "Protected = real-time").

Microsoft Graph and Gmail can push a notification the instant mail arrives, which
is what makes sub-second quarantine possible instead of waiting for the next poll.
This module is the receiver those providers call:

* **Graph** validates a new subscription by echoing `validationToken`, then POSTs
  a change notification whose `clientState` we signed at subscription time — that
  signature is the authentication, and it names the one mailbox the notification
  is allowed to touch.
* **Gmail** (via Pub/Sub push) POSTs `{message:{data: base64(json)}}` to a URL
  that carries our `?token=`; the token is the authentication and the payload
  names the affected address, which must belong to a mailbox we hold.

Neither endpoint can carry a customer bearer token, so without those two checks
they are unauthenticated cross-tenant triggers: anyone could name a mailbox and
make us sync it, burning the tenant's provider quota and probing which addresses
we hold. The polling fetch job (workers/oauth_fetch) remains the always-correct
fallback, so rejecting a forged or unconfigured push costs latency, never
coverage.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from uuid import UUID

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from envelock.api._webhook_auth import verify_client_state, verify_push_token
from envelock.db import get_sessionmaker
from envelock.models import Mailbox

logger = logging.getLogger("envelock.webhooks")

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

#: Graph's validation handshake sends a short opaque token. Cap what we will
#: echo so the endpoint cannot be used as a general-purpose content reflector.
MAX_VALIDATION_TOKEN = 512


async def _fetch_mailbox(address: str, *, tenant_id: UUID | None) -> dict | None:
    """Sync one mailbox, scoped to the tenant the notification was issued for."""
    from envelock.workers.oauth_fetch import sync_oauth_mailbox

    async with get_sessionmaker()() as session:
        query = select(Mailbox).where(
            Mailbox.address == address.lower(), Mailbox.is_active.is_(True)
        )
        if tenant_id is not None:
            query = query.where(Mailbox.tenant_id == tenant_id)
        mailbox = (await session.execute(query)).scalars().first()
        if mailbox is None:
            return None
        return await sync_oauth_mailbox(session, mailbox)


@router.post("/graph")
@router.get("/graph")
async def graph_notifications(request: Request) -> Response:
    """Microsoft Graph change-notification endpoint."""
    token = request.query_params.get("validationToken")
    if token is not None:
        if len(token) > MAX_VALIDATION_TOKEN:
            return Response(status_code=400)
        return Response(content=token, media_type="text/plain")

    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return Response(status_code=202)

    for note in body.get("value", []) or []:
        verified = verify_client_state(note.get("clientState"))
        if verified is None:
            # Not from a subscription we created — say nothing useful about it.
            logger.warning("graph webhook rejected: clientState did not verify")
            continue
        tenant_id, address = verified
        try:
            await _fetch_mailbox(address, tenant_id=tenant_id)
        except Exception as exc:  # noqa: BLE001 — never fail a provider callback
            logger.warning("graph webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)


@router.post("/gmail")
async def gmail_notifications(request: Request) -> Response:
    """Gmail Pub/Sub push endpoint. The message data base64-encodes
    `{"emailAddress": ..., "historyId": ...}`."""
    if not verify_push_token(request.query_params.get("token")):
        logger.warning("gmail webhook rejected: missing or wrong push token")
        # 202 rather than 401: a Pub/Sub subscription retries on error for days,
        # and we do not want a forged caller to learn whether the token was close.
        return Response(status_code=202)

    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return Response(status_code=202)

    message = body.get("message") or {}
    data_b64 = message.get("data")
    if not data_b64:
        return Response(status_code=202)
    try:
        decoded = json.loads(base64.b64decode(data_b64).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return Response(status_code=202)

    address = decoded.get("emailAddress")
    if isinstance(address, str) and address:
        try:
            await _fetch_mailbox(address, tenant_id=None)
        except Exception as exc:  # noqa: BLE001
            logger.warning("gmail webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)
