"""Production-hardening: idempotency, key rotation, provider backoff, worker
health, and a PRD-coverage gate that keeps the catalogue honest as code changes.
"""

from __future__ import annotations

import base64
import os
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from envelock.channels.mail import api_fetch
from envelock.channels.mail.parser import parse_message
from envelock.config import get_settings
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.models import Alert, Domain, Mailbox, MailboxCredential, Message, Tenant
from envelock.platform.pipeline import analyse_event
from envelock.security.crypto import (
    CryptoError,
    SealedSecret,
    _kek_from,
    _key_id_from,
    open_secret,
    rekey,
    seal,
)
from envelock.security.rotate_credentials import rotate

OWNED = frozenset({"acme.com"})


def _current_key() -> str:
    return get_settings().credential_master_key.get_secret_value()


def _phish(msg_id: str) -> bytes:
    return (
        b'From: "AP" <billing@evil-invoices.com>\r\n'
        b"To: pay@acme.com\r\n"
        b"Subject: urgent payment\r\n"
        b"Message-ID: <" + msg_id.encode() + b"@evil-invoices.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Pay at http://203.0.113.9/login now.\r\n"
    )


async def _mailbox(session) -> Mailbox:
    tid = uuid4()
    session.add(Tenant(id=tid, name="Acme"))
    await session.flush()
    session.add(Domain(tenant_id=tid, name="acme.com", registrable_domain="acme.com"))
    mb = Mailbox(
        tenant_id=tid,
        address="pay@acme.com",
        mailbox_class=MailboxClass.PROTECTED.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mb)
    await session.flush()
    return mb


# ── Idempotency ───────────────────────────────────────────────────────────────
async def test_same_message_is_not_processed_twice(session):
    """The same rfc_message_id on a mailbox (IMAP poll + a forwarded copy) must
    alert once, not twice."""
    mb = await _mailbox(session)

    def event(source):
        return parse_message(
            _phish("dup-1"),
            tenant_id=mb.tenant_id,
            mailbox_id=mb.id,
            source=source,
            owned_domains=OWNED,
            remediable=True,
        )

    first = await analyse_event(
        session, event(SourceMechanism.IMAP_IDLE), tenant_id=mb.tenant_id, owned_domains=OWNED
    )
    second = await analyse_event(
        session,
        event(SourceMechanism.FORWARD_INGEST),
        tenant_id=mb.tenant_id,
        owned_domains=OWNED,
    )
    await session.commit()

    assert first.alerted is True
    assert second.duplicate is True
    assert second.alerted is False

    messages = (
        (await session.execute(select(Message).where(Message.mailbox_id == mb.id)))
        .scalars()
        .all()
    )
    alerts = (
        (await session.execute(select(Alert).where(Alert.tenant_id == mb.tenant_id)))
        .scalars()
        .all()
    )
    assert len(messages) == 1  # stored once
    assert len(alerts) == 1  # alerted once


# ── Key rotation ──────────────────────────────────────────────────────────────
def test_rekey_moves_a_secret_between_master_keys():
    sealed = seal(b"app-password-123", aad=b"mbx")
    # settings key → a new key, then back, and the plaintext survives.
    resealed = rekey(
        sealed, aad=b"mbx", old_master_key=_current_key(), new_master_key="new-key-value"
    )
    back = rekey(
        resealed, aad=b"mbx", old_master_key="new-key-value", new_master_key=_current_key()
    )
    assert open_secret(back, aad=b"mbx") == b"app-password-123"
    # A wrong old key is a clean CryptoError, not a crash.
    with pytest.raises(CryptoError):
        rekey(resealed, aad=b"mbx", old_master_key="wrong", new_master_key=_current_key())


async def test_rotate_credentials_reseals_the_store(session):
    """The rotation tool re-seals stored credentials and clears needs_reconnect."""
    mb = await _mailbox(session)
    mb.needs_reconnect = True
    mailbox_id = mb.id  # capture before expire_all (async lazy-load would raise)

    # Seal the stored credential under an OLD key different from the settings key.
    old_key = "old-master-key-abc"
    dek = AESGCM.generate_key(bit_length=256)
    n1 = os.urandom(12)
    ct = n1 + AESGCM(dek).encrypt(n1, b"legacy-pw", str(mb.id).encode())
    n2 = os.urandom(12)
    wrapped = n2 + AESGCM(_kek_from(old_key)).encrypt(n2, dek, None)
    session.add(
        MailboxCredential(
            mailbox_id=mb.id,
            tenant_id=mb.tenant_id,
            kind="imap_password",
            imap_host="imap.acme.com",
            imap_port=993,
            ciphertext=ct,
            wrapped_dek=wrapped,
            key_id=_key_id_from(_kek_from(old_key)),
        )
    )
    await session.commit()

    summary = await rotate(old_key=old_key, new_key=_current_key(), dry_run=False)
    assert summary["rotated"] == 1

    # rotate() committed in its own session — drop this session's cache to re-read.
    session.expire_all()
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox_id)
        )
    ).scalar_one()
    opened = open_secret(
        SealedSecret(cred.ciphertext, cred.wrapped_dek, cred.key_id),
        aad=str(mailbox_id).encode(),
    )
    assert opened == b"legacy-pw"
    refreshed = await session.get(Mailbox, mailbox_id)
    assert refreshed.needs_reconnect is False


# ── Provider backoff ──────────────────────────────────────────────────────────
async def test_gmail_fetch_retries_transient_failure():
    calls = {"n": 0}

    class Flaky:
        async def get_json(self, url, *, headers):
            if "maxResults" in url:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise TimeoutError("429 throttled")
                return {"messages": [{"id": "m0"}]}
            return {"raw": base64.urlsafe_b64encode(_phish("g1")).decode().rstrip("=")}

        async def get_bytes(self, url, *, headers):  # pragma: no cover
            return b""

    events = await api_fetch.gmail_fetch(
        access_token="t",  # noqa: S106 — test token
        tenant_id=uuid4(),
        mailbox_id=uuid4(),
        owned_domains=OWNED,
        transport=Flaky(),
        backoff=0,
    )
    assert len(events) == 1
    assert calls["n"] == 2  # failed once, retried, succeeded


# ── Worker health ─────────────────────────────────────────────────────────────
async def test_worker_health_reflects_last_cycle(session):
    from envelock.workers.imap_fetch import run_imap_poll_cycle, worker_health

    await _mailbox(session)  # no credential → discovered, reported as an error
    await session.commit()
    await run_imap_poll_cycle()
    health = worker_health()
    assert health["ran_at"] is not None
    assert "mailboxes" in health


# ── PRD-coverage gate ─────────────────────────────────────────────────────────
def test_every_prd_abc_detection_is_registered():
    """CI gate: every A/B/C service code named in the PRD must be a registered
    detection, so the catalogue can't silently drift from the spec."""
    import re
    from pathlib import Path

    import envelock.detections.content  # noqa: F401
    import envelock.detections.identity  # noqa: F401
    import envelock.detections.impersonation  # noqa: F401
    import envelock.detections.sessions  # noqa: F401
    from envelock.detections.base import _REGISTRY

    prd = Path(__file__).resolve().parents[2] / "PRD.md"
    referenced = set(re.findall(r"\b([ABC][0-9]{1,2})\b", prd.read_text(encoding="utf-8")))
    missing = referenced - set(_REGISTRY.keys())
    assert not missing, f"PRD names detections not registered in code: {sorted(missing)}"
