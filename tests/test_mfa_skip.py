"""Deferrable MFA (skip-for-now + authenticated enrolment).

MFA stays strongly encouraged — the dashboard nags until it is on — but a user
can start a session before enrolling, then turn it on later from inside that
session. These cover both halves and the invariant that matters most: an account
that already has MFA can never bypass it with /skip.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _register_and_login(client: TestClient, email: str) -> dict:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
    )
    return client.post(
        "/api/v1/auth/login", json={"email": email, "password": pw}
    ).json()


def test_skip_issues_a_working_session(client: TestClient) -> None:
    login = _register_and_login(client, "skipper@acme.com")
    assert login["mfa_setup_required"] is True

    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]})
    assert skip.status_code == 200
    body = skip.json()
    assert body["mfa_enabled"] is False
    assert body["mfa_deferred"] is True

    # The session actually works, and /me reports MFA as still off (drives the
    # dashboard alert).
    h = {"Authorization": f"Bearer {body['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["mfa_enabled"] is False


def test_enroll_then_activate_turns_mfa_on(client: TestClient) -> None:
    login = _register_and_login(client, "later@acme.com")
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}

    enroll = client.post("/api/v1/auth/mfa/enroll", headers=h).json()
    assert "otpauth_uri" in enroll

    activate = client.post(
        "/api/v1/auth/mfa/activate",
        json={"code": _totp_at(enroll["secret"], int(time.time()) // 30)},
        headers=h,
    )
    assert activate.status_code == 200
    body = activate.json()
    assert body["mfa_enabled"] is True
    assert len(body["recovery_codes"]) == 10

    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["mfa_enabled"] is True


def test_skip_is_refused_once_mfa_is_enabled(client: TestClient) -> None:
    """The whole point of MFA: an account that has it cannot bypass it."""
    login = _register_and_login(client, "secured@acme.com")
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=h).json()
    client.post(
        "/api/v1/auth/mfa/activate",
        json={"code": _totp_at(enroll["secret"], int(time.time()) // 30)},
        headers=h,
    )

    # A fresh login now must not be skippable.
    login2 = client.post(
        "/api/v1/auth/login",
        json={"email": "secured@acme.com", "password": "a-long-enough-passphrase"},
    ).json()
    assert login2["mfa_required"] is True
    refused = client.post("/api/v1/auth/mfa/skip", json={"token": login2["mfa_token"]})
    assert refused.status_code == 409


def test_activate_rejects_a_wrong_code(client: TestClient) -> None:
    login = _register_and_login(client, "typo@acme.com")
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/auth/mfa/enroll", headers=h)

    bad = client.post("/api/v1/auth/mfa/activate", json={"code": "000000"}, headers=h)
    assert bad.status_code == 401
    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["mfa_enabled"] is False
