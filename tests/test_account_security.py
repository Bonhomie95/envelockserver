"""Step-up-protected account changes and robust mailbox deletion."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.db import get_sessionmaker
from envelock.main import app
from envelock.models import Alert, Finding, Message

PW = "a-long-enough-passphrase"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _session(client: TestClient, email: str, *, with_mfa: bool = False) -> dict:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": "Acme"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    if with_mfa:
        setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
        tokens = client.post(
            "/api/v1/auth/mfa/verify",
            json={
                "mfa_token": login["mfa_token"],
                "code": _totp_at(setup["secret"], int(time.time()) // 30),
            },
        ).json()
        return {
            "Authorization": f"Bearer {tokens['access_token']}",
            "_secret": setup["secret"],
        }
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    return {"Authorization": f"Bearer {skip['access_token']}"}


# ── Password change ───────────────────────────────────────────────────────────
def test_password_change_needs_the_current_password(client: TestClient) -> None:
    h = _session(client, "user@acme.com")
    bad = client.post(
        "/api/v1/auth/password",
        json={"current_password": "wrong-one-entirely", "new_password": "another-good-passphrase"},
        headers=h,
    )
    assert bad.status_code == 401


def test_password_change_succeeds_and_rejects_reuse(client: TestClient) -> None:
    h = _session(client, "user2@acme.com")
    same = client.post(
        "/api/v1/auth/password",
        json={"current_password": PW, "new_password": PW},
        headers=h,
    )
    assert same.status_code == 400  # must differ

    ok = client.post(
        "/api/v1/auth/password",
        json={"current_password": PW, "new_password": "a-brand-new-passphrase-9"},
        headers=h,
    )
    assert ok.status_code == 200
    assert ok.json()["sessions_revoked"] is True
    # The new password now works at login.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "user2@acme.com", "password": "a-brand-new-passphrase-9"},
        ).status_code
        == 200
    )


def test_password_change_requires_totp_when_mfa_on(client: TestClient) -> None:
    h = _session(client, "mfa@acme.com", with_mfa=True)
    headers = {"Authorization": h["Authorization"]}
    # Right password, but no code → refused.
    no_code = client.post(
        "/api/v1/auth/password",
        json={"current_password": PW, "new_password": "a-brand-new-passphrase-9"},
        headers=headers,
    )
    assert no_code.status_code == 401

    with_code = client.post(
        "/api/v1/auth/password",
        json={
            "current_password": PW,
            "new_password": "a-brand-new-passphrase-9",
            "mfa_code": _totp_at(h["_secret"], int(time.time()) // 30 + 1),
        },
        headers=headers,
    )
    assert with_code.status_code == 200


# ── MFA disable ───────────────────────────────────────────────────────────────
def test_mfa_disable_requires_password_and_code(client: TestClient) -> None:
    h = _session(client, "dis@acme.com", with_mfa=True)
    headers = {"Authorization": h["Authorization"]}
    bad = client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "wrong", "mfa_code": "000000"},
        headers=headers,
    )
    assert bad.status_code == 401

    ok = client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": PW, "mfa_code": _totp_at(h["_secret"], int(time.time()) // 30 + 1)},
        headers=headers,
    )
    assert ok.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).json()["mfa_enabled"] is False


# ── Phone change is a sensitive action ────────────────────────────────────────
def test_changing_a_verified_phone_requires_reauth(client: TestClient) -> None:
    h = _session(client, "phone@acme.com")
    # First add is low-friction.
    start = client.post(
        "/api/v1/auth/phone/start", json={"phone": "+1 415 555 0100"}, headers=h
    ).json()
    client.post("/api/v1/auth/phone/verify", json={"code": start["dev_code"]}, headers=h)

    # Now changing it without the password is refused.
    blocked = client.post("/api/v1/auth/phone/start", json={"phone": "+1 415 555 0199"}, headers=h)
    assert blocked.status_code == 401

    allowed = client.post(
        "/api/v1/auth/phone/start",
        json={"phone": "+1 415 555 0199", "current_password": PW},
        headers=h,
    )
    assert allowed.status_code == 200


# ── Mailbox delete no longer 500s on dependent rows ───────────────────────────
def test_delete_mailbox_with_messages_alerts_and_findings(client: TestClient) -> None:
    h = _session(client, "it@acme.com")
    client.post("/api/v1/tenants/bootstrap", json={"name": "Acme", "domain": "acme.com"}, headers=h)
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ceo@acme.com", "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()
    mid = mb["id"]

    me = client.get("/api/v1/auth/me", headers=h).json()
    tid = me["tenant_id"]

    async def _seed() -> str:
        from datetime import UTC, datetime
        from uuid import UUID

        async with get_sessionmaker()() as s:
            msg = Message(
                tenant_id=UUID(tid),
                mailbox_id=UUID(mid),
                direction="inbound",
                sender_address="vendor@example.com",
                received_at=datetime.now(UTC),
                source="imap_idle",
            )
            alert = Alert(
                tenant_id=UUID(tid), mailbox_id=UUID(mid), tier="high", title="x", body="y"
            )
            s.add_all([msg, alert])
            await s.flush()
            s.add(
                Finding(
                    tenant_id=UUID(tid),
                    mailbox_id=UUID(mid),
                    message_id=msg.id,
                    alert_id=alert.id,
                    service="A1",
                    tier="high",
                    score=90,
                    summary="s",
                )
            )
            await s.commit()
            return str(alert.id)

    import asyncio

    alert_id = asyncio.run(_seed())

    out = client.delete(f"/api/v1/mailboxes/{mid}", headers=h)
    assert out.status_code == 200
    assert out.json()["removed"] is True

    async def _alert_survived() -> bool:
        from uuid import UUID

        async with get_sessionmaker()() as s:
            row = await s.get(Alert, UUID(alert_id))
            return row is not None and row.mailbox_id is None

    # The mailbox is gone but its alert history is preserved, just detached.
    assert asyncio.run(_alert_survived()) is True
    remaining = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
    assert all(m["id"] != mid for m in remaining)
