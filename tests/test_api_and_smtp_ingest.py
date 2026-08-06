"""Tier-1 OAuth fetch (Gmail/Graph) and the Tier-4 SMTP ingest front end.

The provider fetch methods and the forwarding pipeline existed but had no live
transport: Gmail/Graph `fetch()` returned [] and there was no SMTP server to
drive `ForwardingIngest`. These prove the wired transports with fakes — no live
credentials or bound socket required.
"""

from __future__ import annotations

import base64
from uuid import uuid4

import pytest

from envelock.channels.mail import api_fetch
from envelock.core.enums import MailDirection, SourceMechanism

pytestmark = pytest.mark.asyncio

OWNED = frozenset({"acme.com"})


def _raw(sender: str = "billing@evil-invoices.com") -> bytes:
    return (
        f"From: Accounts <{sender}>\r\n"
        "To: pay@acme.com\r\n"
        "Subject: invoice\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Pay at http://203.0.113.9/login now.\r\n"
    ).encode()


class FakeGmailTransport:
    def __init__(self, raws: list[bytes]) -> None:
        self._raws = raws

    async def get_json(self, url: str, *, headers: dict) -> dict:
        assert headers["Authorization"].startswith("Bearer ")
        if "/messages?" in url or "maxResults" in url:
            return {"messages": [{"id": f"m{i}"} for i in range(len(self._raws))]}
        # message detail: /messages/m{i}?format=raw
        idx = int(url.split("/messages/m", 1)[1].split("?", 1)[0])
        b64 = base64.urlsafe_b64encode(self._raws[idx]).decode().rstrip("=")
        return {"raw": b64}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # pragma: no cover
        return b""


class FakeGraphTransport:
    def __init__(self, raws: list[bytes]) -> None:
        self._raws = raws

    async def get_json(self, url: str, *, headers: dict) -> dict:
        return {"value": [{"id": f"g{i}"} for i in range(len(self._raws))]}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:
        idx = int(url.split("/messages/g", 1)[1].split("/", 1)[0])
        return self._raws[idx]


async def test_gmail_fetch_normalises_raw_to_mailevents():
    events = await api_fetch.gmail_fetch(
        access_token="tok",  # noqa: S106 — test token, not a secret
        tenant_id=uuid4(),
        mailbox_id=uuid4(),
        owned_domains=OWNED,
        transport=FakeGmailTransport([_raw()]),
    )
    assert len(events) == 1
    ev = events[0]
    assert ev.source is SourceMechanism.GMAIL_API
    assert ev.direction is MailDirection.INBOUND
    assert any("203.0.113.9" in u for u in ev.urls)


async def test_graph_fetch_normalises_mime_to_mailevents():
    events = await api_fetch.graph_fetch(
        access_token="tok",  # noqa: S106 — test token, not a secret
        tenant_id=uuid4(),
        mailbox_id=uuid4(),
        owned_domains=OWNED,
        transport=FakeGraphTransport([_raw(), _raw("x@evil-invoices.com")]),
    )
    assert len(events) == 2
    assert all(e.source is SourceMechanism.GRAPH_API for e in events)


# ── SMTP ingest front end ─────────────────────────────────────────────────────
class _FakeIngest:
    def __init__(self) -> None:
        self.rcpts: list[str] = []
        self.datas: list[tuple[str, bytes]] = []

    async def handle_rcpt(self, recipient: str):
        from envelock.channels.mail.ingest import IngestResult

        self.rcpts.append(recipient)
        ok = recipient.startswith("t-")
        return IngestResult(ok, "250 OK" if ok else "550 unknown recipient")

    async def handle_data(self, *, recipient: str, raw: bytes):
        from envelock.channels.mail.ingest import IngestResult

        self.datas.append((recipient, raw))
        return IngestResult(True, "250 Message accepted")


class _Envelope:
    def __init__(self) -> None:
        self.rcpt_tos: list[str] = []
        self.content = b""


async def test_smtp_handler_accepts_known_and_rejects_unknown_recipients():
    from envelock.workers.smtp_ingest import ForwardingSMTPHandler

    ingest = _FakeIngest()
    handler = ForwardingSMTPHandler(ingest=ingest)
    env = _Envelope()

    good = await handler.handle_RCPT(None, None, env, "t-abc12345@in.envelock.io", [])
    assert good == "250 OK"
    assert env.rcpt_tos == ["t-abc12345@in.envelock.io"]

    bad = await handler.handle_RCPT(None, None, env, "nobody@in.envelock.io", [])
    assert bad.startswith("550")


async def test_smtp_handler_runs_data_through_ingest():
    from envelock.workers.smtp_ingest import ForwardingSMTPHandler

    ingest = _FakeIngest()
    handler = ForwardingSMTPHandler(ingest=ingest)
    env = _Envelope()
    env.rcpt_tos = ["t-abc12345@in.envelock.io"]
    env.content = _raw()

    reply = await handler.handle_DATA(None, None, env)
    assert reply.startswith("250")
    assert ingest.datas and ingest.datas[0][0] == "t-abc12345@in.envelock.io"
    assert ingest.datas[0][1] == _raw()
