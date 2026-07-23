"""Payment gate and trial ledger (PRD §12.7, §17.1).

Exercised end to end against a fake payment transport, so the funnel is proven
without a live Stripe/Paystack account. Only the final HTTP call differs in
production.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.billing import payments
from envelock.main import app


class _FakeStripe:
    """Returns a card with a stable fingerprint, like Stripe's PaymentMethod."""

    def __init__(self, fingerprint: str = "fp_reused") -> None:
        self.fingerprint = fingerprint

    async def request(self, method: str, url: str, *, headers: dict, json=None) -> dict:
        if "payment_methods" in url:
            return {
                "id": "pm_123",
                "card": {
                    "fingerprint": self.fingerprint,
                    "brand": "visa",
                    "last4": "4242",
                },
            }
        return {"id": "sub_123", "status": "active"}


@pytest.fixture
def configured_stripe(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_STRIPE_SECRET_KEY", "sk_test_x")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _owner(client: TestClient, email: str) -> dict[str, str]:
    pw = "a-long-enough-password"
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
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme", "domain": "acme.com.ng"},
        headers=h,
    )
    return h


def test_confirm_opens_the_gate_and_starts_the_trial(
    client: TestClient, configured_stripe: None
) -> None:
    payments.set_default_transport(_FakeStripe())
    try:
        h = _owner(client, "owner@acme.com.ng")
        body = client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_123", "identifier": "acme.com.ng"},
            headers=h,
        ).json()

        assert body["gate_passed"] is True
        assert body["trial_allowed"] is True
        assert body["trial_started"] is True
        assert body["trial_ends_at"]
        # The fingerprint is anti-abuse state and must never be returned.
        assert "fingerprint" not in body["instrument"]
        assert body["instrument"]["last4"] == "4242"
    finally:
        payments.set_default_transport(None)


def test_second_trial_for_same_domain_is_refused(
    client: TestClient, configured_stripe: None
) -> None:
    """The ledger is permanent — a domain gets one trial, ever (PRD §12.7)."""
    payments.set_default_transport(_FakeStripe())
    try:
        h1 = _owner(client, "first@acme.com.ng")
        client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_1", "identifier": "acme.com.ng"},
            headers=h1,
        )
        # A different tenant tries the same registrable domain later.
        h2 = _owner(client, "second@acme.com.ng")
        body = client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_2", "identifier": "acme.com.ng"},
            headers=h2,
        ).json()

        assert body["gate_passed"] is True  # they can still subscribe
        assert body["trial_allowed"] is False  # but no fresh trial
        assert body["eligibility"] == "already_used"
    finally:
        payments.set_default_transport(None)


def test_unconfigured_provider_reports_503(client: TestClient) -> None:
    from envelock.config import get_settings

    get_settings.cache_clear()
    h = _owner(client, "owner@acme.com.ng")
    r = client.post(
        "/api/v1/billing/confirm",
        json={"provider": "stripe", "reference": "pm_1", "identifier": "acme.com.ng"},
        headers=h,
    )
    assert r.status_code == 503


def test_ledger_entry_is_persisted(client: TestClient, configured_stripe: None) -> None:
    import asyncio

    from envelock.db import get_sessionmaker
    from envelock.models import DomainTrialLedger

    payments.set_default_transport(_FakeStripe())
    try:
        h = _owner(client, "owner@acme.com.ng")
        client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_1", "identifier": "acme.com.ng"},
            headers=h,
        )

        async def _read() -> DomainTrialLedger | None:
            async with get_sessionmaker()() as s:
                return await s.get(DomainTrialLedger, "acme.com.ng")

        row = asyncio.run(_read())
        assert row is not None
        assert row.outcome == "active"
        assert row.payment_fingerprint == "fp_reused"
    finally:
        payments.set_default_transport(None)
