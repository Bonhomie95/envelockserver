"""Tier-1 OAuth connection flow (PRD §17.1).

The token exchange is exercised end to end against a fake transport, so the flow
is proven without a live Microsoft/Google app registration. Only the final
network call differs in production.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.channels.mail import oauth
from envelock.main import app


class _FakeTransport:
    """Stands in for the provider token endpoint."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def post_form(self, url: str, data: dict) -> dict:
        self.calls.append((url, data))
        return {
            "access_token": "access-xyz",
            "refresh_token": "refresh-abc",
            "expires_in": 3600,
            "scope": "Mail.Read",
        }


@pytest.fixture
def configured_ms(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_MS_CLIENT_ID", "ms-client")
    monkeypatch.setenv("ENVELOCK_MS_CLIENT_SECRET", "ms-secret")
    monkeypatch.setenv(
        "ENVELOCK_MS_REDIRECT_URI", "https://app.envelock.io/connect/oauth/microsoft/callback"
    )
    monkeypatch.setenv("ENVELOCK_CREDENTIAL_MASTER_KEY", "unit-test-master-key")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _admin(client: TestClient) -> dict[str, str]:
    pw = "a-long-enough-password"
    email = "admin@acme.com.ng"
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
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    # A tenant must exist and own the mailbox.
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme", "domain": "acme.com.ng"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "pay@acme.com.ng", "mailbox_class": "protected", "sources": []},
        headers=h,
    )
    return h


def test_authorize_returns_a_consent_url(client: TestClient, configured_ms: None) -> None:
    h = _admin(client)
    body = client.post(
        "/api/v1/connect/oauth/microsoft/authorize",
        json={"mailbox_address": "pay@acme.com.ng"},
        headers=h,
    ).json()
    assert "login.microsoftonline.com" in body["authorize_url"]
    assert "client_id=ms-client" in body["authorize_url"]
    assert body["state"]


def test_unconfigured_provider_reports_503(client: TestClient) -> None:
    # No creds set for microsoft in this test → not configured.
    from envelock.config import get_settings

    get_settings.cache_clear()
    h = _admin(client)
    r = client.post(
        "/api/v1/connect/oauth/microsoft/authorize",
        json={"mailbox_address": "pay@acme.com.ng"},
        headers=h,
    )
    assert r.status_code == 503


def test_callback_exchanges_code_and_flips_mailbox_to_tier1(
    client: TestClient, configured_ms: None
) -> None:
    fake = _FakeTransport()
    oauth.set_default_transport(fake)
    try:
        h = _admin(client)
        auth = client.post(
            "/api/v1/connect/oauth/microsoft/authorize",
            json={"mailbox_address": "pay@acme.com.ng"},
            headers=h,
        ).json()

        cb = client.get(
            "/api/v1/connect/oauth/microsoft/callback",
            params={"code": "the-auth-code", "state": auth["state"]},
        ).json()

        assert cb["connected"] is True
        assert cb["integration_tier"] == 1
        assert "graph_api" in cb["sources"]
        assert cb["has_refresh_token"] is True
        # The real token endpoint was called with the authorization code.
        assert fake.calls and fake.calls[0][1]["code"] == "the-auth-code"

        # The mailbox is now Tier-1 and its coverage reflects it.
        mailboxes = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
        assert any("graph_api" in m["sources"] for m in mailboxes)
    finally:
        oauth.set_default_transport(None)


def test_callback_rejects_a_forged_state(client: TestClient, configured_ms: None) -> None:
    _admin(client)
    r = client.get(
        "/api/v1/connect/oauth/microsoft/callback",
        params={"code": "x", "state": "forged.state"},
    )
    assert r.status_code == 400


def test_stored_oauth_token_is_encrypted_at_rest(
    client: TestClient, configured_ms: None
) -> None:
    """The refresh token is the durable secret — it must never sit in plaintext
    (PRD §5.2)."""
    import asyncio

    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.models import MailboxCredential
    from envelock.security.crypto import SealedSecret, open_secret

    fake = _FakeTransport()
    oauth.set_default_transport(fake)
    try:
        h = _admin(client)
        auth = client.post(
            "/api/v1/connect/oauth/microsoft/authorize",
            json={"mailbox_address": "pay@acme.com.ng"},
            headers=h,
        ).json()
        client.get(
            "/api/v1/connect/oauth/microsoft/callback",
            params={"code": "c", "state": auth["state"]},
        )

        async def _read() -> MailboxCredential | None:
            # Other tests share the SQLite file, so take the row this test just
            # sealed rather than assuming the table holds exactly one.
            async with get_sessionmaker()() as s:
                return (
                    (
                        await s.execute(
                            select(MailboxCredential).order_by(
                                MailboxCredential.created_at.desc()
                            )
                        )
                    )
                    .scalars()
                    .first()
                )

        cred = asyncio.run(_read())
        assert cred is not None
        assert cred.kind == "oauth_token"
        assert b"refresh-abc" not in cred.ciphertext  # not plaintext
        opened = open_secret(
            SealedSecret(cred.ciphertext, cred.wrapped_dek, cred.key_id),
            aad=str(cred.mailbox_id).encode(),
        )
        assert b"refresh-abc" in opened  # but recoverable with the key
    finally:
        oauth.set_default_transport(None)
