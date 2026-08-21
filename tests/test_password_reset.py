"""Forgot-password: MFA accounts reset with the authenticator; non-MFA accounts
reset via an emailed link. No user enumeration on the email path.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.asyncio


def _totp_at(secret: str, counter: int) -> str:
    import base64
    import hashlib
    import hmac
    import struct

    pad = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + pad)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off : off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def _totp_now(secret: str) -> str:
    return _totp_at(secret, int(time.time()) // 30)


@pytest.fixture
def client() -> Iterator[TestClient]:
    from envelock.api.auth import _reset_store
    from envelock.main import app

    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _register_with_mfa(client: TestClient, email: str, pw: str) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    secret = setup["secret"]
    client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": _totp_now(secret)},
    )
    return secret


def _register_no_mfa(client: TestClient, email: str, pw: str) -> None:
    # Register then skip MFA enrolment — login stays in the mfa_setup_required state,
    # so mfa_enabled is False on the account.
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
    )


async def test_mfa_account_resets_with_authenticator(client: TestClient):
    email, pw = "owner@resetco.dev", "original-passphrase-1"
    secret = _register_with_mfa(client, email, pw)

    forgot = client.post("/api/v1/auth/password/forgot", json={"email": email}).json()
    # Every account gets the same answer and the same emailed link — otherwise
    # the response is a free "does this address exist, and does it have MFA?"
    # oracle. An MFA account additionally has to supply its authenticator code.
    assert forgot["method"] == "email"
    assert "reset_token" not in forgot
    token = forgot["reset_link"].split("token=", 1)[1]

    # No code at all is rejected for an MFA account.
    assert (
        client.post(
            "/api/v1/auth/password/reset",
            json={"token": token, "new_password": "a-brand-new-passphrase-9"},
        ).status_code
        == 401
    )

    # Wrong code is rejected.
    bad = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": "a-brand-new-passphrase-9", "code": "000000"},
    )
    assert bad.status_code == 401

    # Correct code resets the password.
    new_pw = "a-brand-new-passphrase-9"
    ok = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": new_pw, "code": _totp_now(secret)},
    )
    assert ok.status_code == 200
    assert ok.json()["sessions_revoked"] is True

    # The link is single-use: replaying it after a successful reset fails.
    replay = client.post(
        "/api/v1/auth/password/reset",
        json={
            "token": token,
            "new_password": "yet-another-passphrase-3",
            "code": _totp_now(secret),
        },
    )
    assert replay.status_code == 401

    # The new password now logs in; the old one does not.
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": new_pw}).status_code
        == 200
    )
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": pw}).status_code == 401
    )


async def test_non_mfa_account_resets_via_emailed_link(client: TestClient):
    email, pw = "solo@resetsolo.dev", "original-passphrase-2"
    _register_no_mfa(client, email, pw)

    forgot = client.post("/api/v1/auth/password/forgot", json={"email": email}).json()
    assert forgot["method"] == "email"
    # In development the link is returned for convenience; extract the token.
    assert "reset_link" in forgot
    token = forgot["reset_link"].split("token=", 1)[1]

    new_pw = "totally-different-passphrase-7"
    ok = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": new_pw},  # no code needed
    )
    assert ok.status_code == 200
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": new_pw}).status_code
        == 200
    )


async def test_unknown_email_does_not_enumerate(client: TestClient):
    r = client.post("/api/v1/auth/password/forgot", json={"email": "nobody@nowhere-xyz.dev"})
    assert r.status_code == 200
    body = r.json()
    assert body["method"] == "email"  # same shape as a real non-MFA account
    assert "reset_token" not in body  # never hand a token for a non-existent user


async def test_weak_new_password_is_rejected(client: TestClient):
    email, pw = "weak@resetweak.dev", "original-passphrase-3"
    _register_no_mfa(client, email, pw)
    token = (
        client.post("/api/v1/auth/password/forgot", json={"email": email})
        .json()["reset_link"]
        .split("token=", 1)[1]
    )
    r = client.post("/api/v1/auth/password/reset", json={"token": token, "new_password": "short"})
    assert r.status_code == 422


async def test_bogus_token_is_rejected(client: TestClient):
    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "not-a-real-token", "new_password": "a-fine-long-passphrase-1"},
    )
    assert r.status_code == 401
