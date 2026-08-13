"""Tests for the gap-closure work: domain verification, sender-domain reputation,
novel-vendor Critical, A1 attachment extraction, notification transports, the
scheduler jobs, OAuth refresh/fetch, retention purge, export tokens and ingest
IP filtering.
"""

from __future__ import annotations

import io
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import _totp_at
from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.risk.engine import assess

OWNED = frozenset({"acme.com"})
KNOWN = frozenset({"gemini.com"})


def _auth_header(client: TestClient, email: str = "gap@acme.com") -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _bootstrap(client: TestClient, h: dict, *, name: str, domain: str):
    return client.post(
        "/api/v1/tenants/bootstrap", json={"name": name, "domain": domain}, headers=h
    )


# ── 1. Domain verification (user requirement #1) ─────────────────────────────
def test_domain_verification_challenge_and_verify(client: TestClient, monkeypatch) -> None:
    h = _auth_header(client, "dv@acme.com")
    boot = _bootstrap(client, h, name="Acme", domain="acme.com")
    assert boot.status_code == 201

    challenge = client.get("/api/v1/domains/acme.com/verification", headers=h).json()
    assert challenge["verified"] is False
    assert challenge["txt"]["value"].startswith("envelock-verify=")

    # Fail first: DNS record not present.
    from envelock.api import tenants

    tenants.set_domain_verifier(lambda domain, token, method="txt": False)
    assert client.post("/api/v1/domains/acme.com/verify", headers=h).status_code == 422

    # Then succeed once the (injected) DNS check passes.
    tenants.set_domain_verifier(lambda domain, token, method="txt": True)
    ok = client.post("/api/v1/domains/acme.com/verify", headers=h)
    assert ok.status_code == 200 and ok.json()["verified"] is True
    tenants.set_domain_verifier(None)


def test_unverified_domain_blocks_forward_connect(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("ENVELOCK_REQUIRE_DOMAIN_VERIFICATION", "true")
    from envelock.config import get_settings

    get_settings.cache_clear()
    try:
        # A domain of its own so the append-only trial ledger doesn't drop this
        # tenant to Guard (which has no mailbox capacity).
        h = _auth_header(client, "gate@gatecorp.com")
        _bootstrap(client, h, name="Gate", domain="gatecorp.com")
        mb = client.post(
            "/api/v1/mailboxes",
            json={"address": "pay@gatecorp.com", "mailbox_class": "protected", "sources": []},
            headers=h,
        ).json()
        # Domain not verified → connecting for live mail is refused.
        resp = client.post(f"/api/v1/mailboxes/{mb['id']}/connect/forward", headers=h)
        assert resp.status_code == 403
        assert "verify control" in resp.json()["detail"]
    finally:
        monkeypatch.delenv("ENVELOCK_REQUIRE_DOMAIN_VERIFICATION", raising=False)
        get_settings.cache_clear()


# ── 2. Sender-domain reputation (user requirement #3) ────────────────────────
def test_dnsbl_reputation_flags_listed_domain(monkeypatch) -> None:
    from envelock.channels.external import reputation
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_DOMAIN_REPUTATION_ENABLED", "true")
    get_settings.cache_clear()
    try:
        rep = reputation.DomainReputation()
        # Inject the DNSBL answer: listed in the first zone, not the second.
        monkeypatch.setattr(
            rep, "_dnsbl_listed",
            lambda reg, zone: "127.0.1.2" if "spamhaus" in zone else None,
        )
        result = rep.check("evil-sender.com")
        assert result.listed is True
        assert any("spamhaus" in s for s in result.sources)
    finally:
        get_settings.cache_clear()


# ── 3. Novel-vendor Critical (no prior A1 baseline) ──────────────────────────
def _ctx(raw: str, counterparty=None, malicious=frozenset()) -> DetectionContext:
    event = parse_message(
        raw.encode(), tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
    )
    return DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, known_counterparties=KNOWN, counterparty=counterparty,
        malicious_domains=malicious,
    )


NOVEL_LOOKALIKE_BEC = """\
From: "Gemini Accounts" <billing@gemìni.com>
To: pay@acme.com
Subject: New supplier payment details
Message-ID: <x@xn--gemni-hva.com>
Content-Type: text/plain

Hello, please set up payment to our account.
Beneficiary bank IBAN GB33BUKB20201555555555. This is urgent, pay today.
"""


def test_novel_vendor_lookalike_reaches_critical() -> None:
    # A brand-new counterparty (no known bank ids) on a homoglyph domain, sending
    # payment instructions with urgency. A1 cannot fire (nothing to diff), but the
    # A2 + A4 combination must still reach Critical.
    cp = CounterpartyState(registrable_domain="xn--gemni-hva.com", message_count=0)
    findings = run_all(_ctx(NOVEL_LOOKALIKE_BEC, counterparty=cp))
    services = {f.service for f in findings}
    result = assess(findings)
    assert result is not None
    # Either homoglyph (A4) or cousin (A3) fires alongside the unverified-payee A2.
    assert "A2" in services
    assert result.tier is AlertTier.CRITICAL
    assert result.requires_callback is True


# ── 4. A1 attachment extraction (PDF/DOCX/OCR path) ──────────────────────────
def _docx_bytes(text: str) -> bytes:
    import docx

    d = docx.Document()
    d.add_paragraph(text)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _mime_with_docx(docx_bytes: bytes) -> bytes:
    import base64

    b64 = base64.encodebytes(docx_bytes).decode()
    return (
        "From: \"Gemini Accounts\" <billing@gemini.com>\n"
        "To: pay@acme.com\n"
        "Subject: Re: Invoice 4471\n"
        "Message-ID: <att@gemini.com>\n"
        "In-Reply-To: <old@gemini.com>\n"
        "References: <old@gemini.com>\n"
        'Content-Type: multipart/mixed; boundary="b"\n\n'
        "--b\n"
        "Content-Type: text/plain\n\n"
        "Hi, please see the updated invoice attached and remit accordingly.\n\n"
        "--b\n"
        "Content-Type: application/vnd.openxmlformats-officedocument."
        'wordprocessingml.document; name="invoice.docx"\n'
        "Content-Transfer-Encoding: base64\n"
        'Content-Disposition: attachment; filename="invoice.docx"\n\n'
        f"{b64}\n"
        "--b--\n"
    ).encode()


def test_a1_detects_bank_change_inside_docx_attachment() -> None:
    # The changed IBAN lives ONLY in the attached Word invoice, not the body — the
    # most common real BEC delivery vector, which A1 was previously blind to.
    docx = _docx_bytes("Please remit payment to our bank account IBAN GB33BUKB20201555555555")
    event = parse_message(
        _mime_with_docx(docx), tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
    )
    # Confirm the parser actually extracted the attachment text.
    assert any(a.extracted_text and "GB33BUKB" in a.extracted_text for a in event.attachments)

    cp = CounterpartyState(
        registrable_domain="gemini.com", message_count=40,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
        verified_phone="+18030000000",
    )
    ctx = DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, known_counterparties=KNOWN, counterparty=cp,
    )
    findings = run_all(ctx)
    a1 = next((f for f in findings if f.service == "A1"), None)
    assert a1 is not None and a1.tier is AlertTier.CRITICAL


# ── 5. Notification transports ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_push_sender_requires_keys() -> None:
    from envelock.notify.senders import Notification, PushSender

    sender = PushSender()
    sender.public_key = "pub"
    sender.private_key = "priv"  # force configured
    note = Notification(
        alert_id=uuid4(), tenant_id=uuid4(), tier=AlertTier.CRITICAL, title="t", body="b"
    )
    # No keys → cannot encrypt → not delivered (never a silent success).
    res = await sender.send(note, to="https://push.example/endpoint", keys=None)
    assert res.delivered is False


def test_ingest_ip_filter(monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.security.ipfilter import ingest_ip_allowed

    monkeypatch.setenv("ENVELOCK_INGEST_ALLOWED_IPS", "203.0.113.0/24, 198.51.100.7")
    get_settings.cache_clear()
    try:
        assert ingest_ip_allowed("203.0.113.55") is True
        assert ingest_ip_allowed("198.51.100.7") is True
        assert ingest_ip_allowed("10.0.0.1") is False
        assert ingest_ip_allowed(None) is False
    finally:
        get_settings.cache_clear()


# ── 6. Retention purge actually deletes ──────────────────────────────────────
@pytest.mark.asyncio
async def test_retention_purge_deletes_old_audit_events(session) -> None:
    from envelock.governance.retention import purge_expired
    from envelock.models import AuditEvent

    tid = uuid4()
    old = AuditEvent(tenant_id=tid, action="test.old")
    fresh = AuditEvent(tenant_id=tid, action="test.fresh")
    session.add_all([old, fresh])
    await session.flush()
    # Backdate the old one beyond the 365-day audit retention.
    old.created_at = datetime.now(UTC) - timedelta(days=400)
    await session.commit()

    counts = await purge_expired(session)
    assert counts.get("audit_event", 0) >= 1

    from sqlalchemy import select

    remaining = (
        await session.execute(select(AuditEvent.action).where(AuditEvent.tenant_id == tid))
    ).scalars().all()
    assert "test.fresh" in remaining and "test.old" not in remaining


# ── 7. OAuth token refresh ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_oauth_refresh_updates_expiry(session, monkeypatch) -> None:
    import json

    from envelock.channels.mail import oauth, oauth_refresh
    from envelock.models import Mailbox, MailboxCredential
    from envelock.security.crypto import seal

    # Configure the Google provider + a fake token endpoint.
    monkeypatch.setenv("ENVELOCK_GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("ENVELOCK_GOOGLE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("ENVELOCK_GOOGLE_REDIRECT_URI", "https://app/callback")
    from envelock.config import get_settings

    get_settings.cache_clear()

    class FakeTransport:
        async def post_form(self, url, data):
            assert data["grant_type"] == "refresh_token"
            return {"access_token": "fresh-access", "expires_in": 3600}

    oauth.set_default_transport(FakeTransport())
    try:
        from envelock.models import Tenant

        tid = uuid4()
        session.add(Tenant(id=tid, name="Acme"))
        await session.flush()
        mb = Mailbox(
            tenant_id=tid, address="user@acme.com",
            sources=[SourceMechanism.GMAIL_API.value],
        )
        session.add(mb)
        await session.flush()
        sealed = seal(
            json.dumps({"access_token": "old", "refresh_token": "rt"}).encode(),
            aad=str(mb.id).encode(),
        )
        session.add(
            MailboxCredential(
                mailbox_id=mb.id, tenant_id=tid, kind="oauth_token",
                ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek, key_id=sealed.key_id,
                token_expires_at=datetime.now(UTC) - timedelta(minutes=5),  # expired
            )
        )
        await session.commit()

        refreshed = await oauth_refresh.refresh_due_tokens(session)
        assert refreshed == 1
        tok = await oauth_refresh.current_access_token(session, mb.id)
        assert tok is not None and tok[0] == "fresh-access"
    finally:
        oauth.set_default_transport(None)
        get_settings.cache_clear()


# ── 8. Export tokens are persisted and authenticate a read-only feed ─────────
def test_export_token_persisted_and_authenticates(client: TestClient) -> None:
    h = _auth_header(client, "owner@exportco.com")
    _bootstrap(client, h, name="ExportCo", domain="exportco.com")
    created = client.post("/api/v1/export/tokens", json={"scopes": ["alerts:read"]}, headers=h)
    assert created.status_code == 201
    token = created.json()["token"]

    # The token now authenticates the read-only SIEM feed.
    feed = client.get("/api/v1/export/api/alerts", headers={"Authorization": f"Bearer {token}"})
    assert feed.status_code == 200
    assert "alerts" in feed.json()

    # A bogus token is rejected.
    bad = client.get("/api/v1/export/api/alerts", headers={"Authorization": "Bearer envk_nope"})
    assert bad.status_code == 401


# ── 9. Scheduler jobs run cleanly ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_scheduler_jobs_run(db) -> None:
    from envelock.workers import scheduler

    # These run across all tenants against an empty DB — they must not raise.
    esc = await scheduler.escalation_job()
    ret = await scheduler.retention_job()
    assert "escalated" in esc and "purged" in ret
