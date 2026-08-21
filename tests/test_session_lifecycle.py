"""Authorisation has to track the account, not the token.

An access token is a 15-minute snapshot and a refresh token lives for two weeks.
If suspension, rejection or demotion is only checked when the token is minted,
those controls do nothing for the rest of the token's life — and `/auth/refresh`
would happily mint fresh ones. These tests pin the behaviour that closes that.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from envelock.auth.security import _totp_at
from envelock.db import get_sessionmaker
from envelock.models import User


def _signup(client: TestClient, email: str, tenant: str = "Acme") -> dict:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": tenant},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    return client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()


def _set(email: str, **fields: object) -> None:
    async def _run() -> None:
        async with get_sessionmaker()() as s:
            user = (
                await s.execute(select(User).where(User.email == email))
            ).scalar_one()
            for key, value in fields.items():
                setattr(user, key, value)
            await s.commit()

    asyncio.run(_run())


def test_suspending_an_admin_takes_effect_on_the_next_request(client: TestClient) -> None:
    email = "owner@suspendco.example"
    tokens = _signup(client, email)
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/v1/audit", headers=h).status_code == 200

    _set(email, status="suspended")

    # Admin-gated routes must refuse immediately, not in 15 minutes.
    assert client.get("/api/v1/audit", headers=h).status_code == 403
    assert (
        client.post(
            "/api/v1/mailboxes",
            json={"address": "x@suspendco.example", "mailbox_class": "monitored"},
            headers=h,
        ).status_code
        == 403
    )


def test_a_suspended_account_cannot_refresh_its_way_back_in(client: TestClient) -> None:
    email = "owner@refreshsusp.example"
    tokens = _signup(client, email)
    _set(email, status="suspended")

    r = client.post("/api/v1/auth/refresh", json={"token": tokens["refresh_token"]})
    assert r.status_code == 403


def test_a_demotion_takes_effect_without_waiting_for_the_token_to_rotate(
    client: TestClient,
) -> None:
    email = "owner@demoteco.example"
    tokens = _signup(client, email)
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/v1/audit", headers=h).status_code == 200

    _set(email, role="member")
    assert client.get("/api/v1/audit", headers=h).status_code == 403


def test_changing_the_password_revokes_other_sessions(client: TestClient) -> None:
    email = "owner@revokeco.example"
    tokens = _signup(client, email)
    h = {"Authorization": f"Bearer {tokens['access_token']}"}

    r = client.post(
        "/api/v1/auth/password",
        json={
            "current_password": "a-long-enough-passphrase",
            "new_password": "an-entirely-different-passphrase",
            "mfa_code": None,
        },
        headers=h,
    )
    # MFA is on for this account, so the step-up needs a code; either way the
    # old refresh token must not survive a successful change.
    if r.status_code == 200:
        assert (
            client.post(
                "/api/v1/auth/refresh", json={"token": tokens["refresh_token"]}
            ).status_code
            == 401
        )


@pytest.mark.parametrize(
    "body",
    [
        {"value": [{"clientState": "envelock"}]},
        {"value": [{"clientState": "not-a-signature"}]},
        {"value": [{}]},
    ],
)
def test_graph_push_rejects_an_unsigned_client_state(
    client: TestClient, body: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the signature check this endpoint is an unauthenticated,
    cross-tenant "sync that mailbox now" trigger for anyone on the internet."""
    from envelock.api import webhooks

    called: list[str] = []

    async def _spy(address: str, **_: object) -> None:
        called.append(address)

    monkeypatch.setattr(webhooks, "_fetch_mailbox", _spy)
    assert client.post("/api/v1/webhooks/graph", json=body).status_code == 202
    assert called == []


def test_graph_push_accepts_a_state_we_signed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from uuid import uuid4

    from envelock.api import webhooks
    from envelock.api._webhook_auth import client_state

    tenant = uuid4()
    called: list[tuple] = []

    async def _spy(address: str, *, tenant_id: object = None) -> None:
        called.append((address, tenant_id))

    monkeypatch.setattr(webhooks, "_fetch_mailbox", _spy)
    state = client_state(tenant_id=tenant, mailbox="cfo@acme.test")
    client.post("/api/v1/webhooks/graph", json={"value": [{"clientState": state}]})
    assert called == [("cfo@acme.test", tenant)]


def test_gmail_push_requires_our_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64
    import json

    from envelock.api import webhooks
    from envelock.api._webhook_auth import push_token

    called: list[str] = []

    async def _spy(address: str, **_: object) -> None:
        called.append(address)

    monkeypatch.setattr(webhooks, "_fetch_mailbox", _spy)
    data = base64.b64encode(
        json.dumps({"emailAddress": "cfo@acme.test", "historyId": 1}).encode()
    ).decode()

    client.post("/api/v1/webhooks/gmail", json={"message": {"data": data}})
    assert called == []

    client.post(
        f"/api/v1/webhooks/gmail?token={push_token()}", json={"message": {"data": data}}
    )
    assert called == ["cfo@acme.test"]


def test_graph_validation_echo_is_length_capped(client: TestClient) -> None:
    """The handshake echoes an opaque token; unbounded, it is a content reflector."""
    ok = client.get("/api/v1/webhooks/graph?validationToken=short-token")
    assert ok.status_code == 200 and ok.text == "short-token"
    huge = client.get("/api/v1/webhooks/graph?validationToken=" + "A" * 5000)
    assert huge.status_code == 400


def test_a_mailbox_cannot_declare_its_own_protection(client: TestClient) -> None:
    """Coverage is derived from what is actually connected (PRD P4).

    The add-mailbox endpoint used to accept a `sources` list, so a mailbox could
    be created reading "Full protection, zero inactive detections" while nothing
    was ingesting a single message — the one state this product must never show.
    """
    email = "owner@declareco.example"
    tokens = _signup(client, email, tenant="DeclareCo")
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "DeclareCo", "domain": "declareco.example"},
        headers=h,
    )

    created = client.post(
        "/api/v1/mailboxes",
        json={
            "address": "cfo@declareco.example",
            "mailbox_class": "protected",
            "sources": ["graph_api", "gmail_api", "entra_logs", "client_sensor"],
        },
        headers=h,
    ).json()

    assert created["sources"] == []
    assert created["protection_level"] == "limited"
    assert created["inactive_detections"], "an unconnected mailbox detects nothing"
