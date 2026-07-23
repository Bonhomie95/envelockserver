"""Our own account security (PRD §15.1): mandatory MFA already ships; these cover
the added passphrase-strength policy and verified-phone second channel."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import assess_passphrase
from envelock.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _session(client: TestClient, email: str, password: str = "a-long-enough-passphrase") -> dict:  # noqa: S107 — test credential
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "tenant_name": "Acme"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    from envelock.auth.security import _totp_at

    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# ── Passphrase strength ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "weak",
    ["password1234", "aaaaaaaaaaaa", "administrator", "lowercaseonly"],
)
def test_weak_passphrases_are_rejected(weak: str) -> None:
    with pytest.raises(ValueError):
        assess_passphrase(weak)


@pytest.mark.parametrize(
    "strong",
    ["correct-Horse-9-battery", "a-long-enough-passphrase-here", "Tr0ubadour-and-3"],
)
def test_strong_passphrases_pass(strong: str) -> None:
    assess_passphrase(strong)  # must not raise


def test_register_rejects_a_weak_password(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={"email": "weak@acme.com", "password": "password", "tenant_name": "Acme"},
    )
    assert r.status_code == 422


# ── Verified phone ───────────────────────────────────────────────────────────
def test_phone_verification_round_trip(client: TestClient) -> None:
    h = _session(client, "owner@acme.com")

    start = client.post(
        "/api/v1/auth/phone/start", json={"phone": "+1 415 555 0142"}, headers=h
    ).json()
    # Dev surfaces the code (production sends it by SMS only).
    assert "dev_code" in start
    code = start["dev_code"]

    ok = client.post("/api/v1/auth/phone/verify", json={"code": code}, headers=h)
    assert ok.status_code == 200
    assert ok.json()["phone_verified"] is True

    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["phone"] == "+1 415 555 0142"
    assert me["phone_verified"] is True


def test_phone_verification_rejects_a_wrong_code(client: TestClient) -> None:
    h = _session(client, "wrong@acme.com")
    client.post("/api/v1/auth/phone/start", json={"phone": "+1 415 555 0143"}, headers=h)
    r = client.post("/api/v1/auth/phone/verify", json={"code": "000000"}, headers=h)
    assert r.status_code in (401, 400)

    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["phone_verified"] is False


def test_phone_endpoints_require_a_session(client: TestClient) -> None:
    assert (
        client.post("/api/v1/auth/phone/start", json={"phone": "+1 415 555 0100"}).status_code
        == 401
    )
