"""Live message pull for the OAuth providers (Tier 1: Gmail, Microsoft 365).

The provider adapters normalise a raw RFC822 message into a `MailEvent`
(`GmailProvider.to_event` / `GraphProvider.to_event`); this module is the part
that actually *gets* the bytes from the provider's REST API. Both return raw MIME,
so the same downstream parser handles them.

Network access sits behind an injectable `HttpTransport` (mirroring
`oauth.Transport`) so the fetch + normalisation is unit-tested against a fake and
production uses a real httpx client. Access tokens are passed in by the caller
(decrypted from the stored OAuth credential in the worker process) — this module
never reads or stores them.

Live use needs a real OAuth app registration and a valid access token; the
fetch/normalisation logic here is complete and tested regardless.
"""

from __future__ import annotations

import base64
from typing import Protocol
from uuid import UUID

from envelock.channels.mail.parser import parse_message
from envelock.channels.mail.providers import GmailProvider
from envelock.core.enums import SourceMechanism
from envelock.core.events import MailEvent

GMAIL_API = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API = "https://graph.microsoft.com/v1.0"


class HttpTransport(Protocol):
    async def get_json(self, url: str, *, headers: dict) -> dict: ...
    async def get_bytes(self, url: str, *, headers: dict) -> bytes: ...


class HttpxTransport:
    """Default transport — real GETs against the provider API."""

    async def get_json(self, url: str, *, headers: dict) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.content


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def gmail_fetch(
    *,
    access_token: str,
    tenant_id: UUID,
    mailbox_id: UUID,
    owned_domains: frozenset[str],
    query: str = "newer_than:2d",
    limit: int = 50,
    transport: HttpTransport | None = None,
) -> list[MailEvent]:
    """Pull recent inbox messages from Gmail and normalise to MailEvents.

    Uses `format=raw`, which returns the full RFC822 message base64url-encoded, so
    the shared parser handles it exactly like an IMAP fetch.
    """
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)

    listing = await transport.get_json(
        f"{GMAIL_API}/users/me/messages?maxResults={limit}&q={query}",
        headers=headers,
    )
    events: list[MailEvent] = []
    for ref in listing.get("messages", []) or []:
        msg_id = ref.get("id")
        if not msg_id:
            continue
        detail = await transport.get_json(
            f"{GMAIL_API}/users/me/messages/{msg_id}?format=raw", headers=headers
        )
        raw_b64 = detail.get("raw")
        if not raw_b64:
            continue
        raw = base64.urlsafe_b64decode(raw_b64.encode() + b"===")
        events.append(
            GmailProvider.to_event(
                raw, tenant_id=tenant_id, mailbox_id=mailbox_id, owned=owned_domains
            )
        )
    return events


async def graph_fetch(
    *,
    access_token: str,
    tenant_id: UUID,
    mailbox_id: UUID,
    owned_domains: frozenset[str],
    mailbox_address: str | None = None,
    limit: int = 50,
    transport: HttpTransport | None = None,
) -> list[MailEvent]:
    """Pull recent inbox messages from Microsoft Graph and normalise to MailEvents.

    Lists message ids, then fetches each message's MIME via `/$value` (raw RFC822).
    """
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)

    base = f"{GRAPH_API}/users/{mailbox_address}" if mailbox_address else f"{GRAPH_API}/me"
    listing = await transport.get_json(
        f"{base}/mailFolders/inbox/messages?$top={limit}&$select=id"
        f"&$orderby=receivedDateTime%20desc",
        headers=headers,
    )
    events: list[MailEvent] = []
    for ref in listing.get("value", []) or []:
        msg_id = ref.get("id")
        if not msg_id:
            continue
        # `/$value` returns the full RFC822 MIME, so the shared parser gives the
        # same fidelity (URLs, auth results, attachments) as the IMAP/Gmail paths —
        # richer than Graph's JSON projection, which omits URL extraction.
        raw = await transport.get_bytes(f"{base}/messages/{msg_id}/$value", headers=headers)
        if not raw:
            continue
        events.append(
            parse_message(
                raw,
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                source=SourceMechanism.GRAPH_API,
                owned_domains=owned_domains,
                remediable=True,
                source_ref=msg_id,
            )
        )
    return events


__all__ = ["HttpTransport", "HttpxTransport", "gmail_fetch", "graph_fetch"]
