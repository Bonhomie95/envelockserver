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


def test_phone_start_is_rate_limited_against_sms_bombing(client: TestClient) -> None:
    """Sending an SMS is metered and abusable — the endpoint must throttle so a
    signed-in caller cannot bomb a number or run up cost."""
    h = _session(client, "spammer@acme.com")
    codes = [
        client.post(
            "/api/v1/auth/phone/start", json={"phone": "+1 415 555 0180"}, headers=h
        ).status_code
        for _ in range(8)
    ]
    assert 429 in codes, "phone/start must throttle SMS sends"


# ── Disposable email blocking ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "bad", ["x@mailinator.com", "y@guerrillamail.com", "z@10minutemail.com"]
)
def test_register_rejects_disposable_email(client: TestClient, bad: str) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={"email": bad, "password": "violet-Tractor-42-canyon", "tenant_name": "Acme"},
    )
    assert r.status_code == 422


def test_register_accepts_a_real_email(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": "founder@acme.com",
            "password": "violet-Tractor-42-canyon",
            "tenant_name": "Acme",
        },
    )
    assert r.status_code == 201


def test_disposable_check_matches_subdomains() -> None:
    from envelock.auth.email_policy import is_disposable_email

    assert is_disposable_email("a@mailinator.com")
    assert is_disposable_email("a@sub.mailinator.com")  # eTLD+1 match
    assert not is_disposable_email("a@acme.com")


# ── One company, one tenant (trial-abuse prevention) ─────────────────────────
def test_same_corporate_domain_joins_one_tenant(client: TestClient) -> None:
    """A second person from the same corporate domain joins the existing tenant as
    a member — companies can't fragment into many tenants (or many trials)."""
    h1 = _session(client, "alice@joinco-uniq.com")
    me1 = client.get("/api/v1/auth/me", headers=h1).json()
    h2 = _session(client, "bob@joinco-uniq.com")
    me2 = client.get("/api/v1/auth/me", headers=h2).json()

    assert me1["tenant_id"] == me2["tenant_id"]
    assert me1["role"] == "owner"
    assert me2["role"] == "member"


@pytest.mark.parametrize(
    "email",
    ["a@gmail.com", "b@outlook.com", "c@hotmail.com", "d@yahoo.com", "e@icloud.com"],
)
def test_consumer_free_mail_signups_are_rejected(client: TestClient, email: str) -> None:
    """Envelock protects a company domain, so consumer inboxes can't register.
    A company on Google Workspace / Microsoft 365 uses its own domain and is
    unaffected (covered by test_workspace_company_domain_is_allowed)."""
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "a-long-enough-passphrase", "tenant_name": "X"},
    )
    assert r.status_code == 422
    assert "work email" in r.json()["detail"].lower()


def test_workspace_company_domain_is_allowed(client: TestClient) -> None:
    """A custom company domain — even one hosted on Google Workspace / M365 — is
    not a consumer domain, so it registers normally."""
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": "cfo@workspace-customer-uniq.com",
            "password": "a-long-enough-passphrase",
            "tenant_name": "Workspace Customer",
        },
    )
    assert r.status_code == 201
