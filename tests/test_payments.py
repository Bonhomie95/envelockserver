"""Payment gate and trial ledger (PRD §12.7, §17.1).

Exercised end to end against a fake payment transport, so the funnel is proven
without a live processor account. Only the final HTTP call differs in production.
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

    async def request(
        self, method: str, url: str, *, headers: dict, json=None, data=None
    ) -> dict:
        if "payment_methods" in url:
            return {
                "id": "pm_123",
                "card": {
                    "fingerprint": self.fingerprint,
                    "brand": "visa",
                    "last4": "4242",
                },
            }
        if "checkout/sessions" in url:
            return {"id": "cs_test_123", "url": "https://checkout.stripe.com/c/pay/cs_test_123"}
        if "billing_portal/sessions" in url:
            return {"url": "https://billing.stripe.com/p/session/test_123"}
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
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme", "domain": "acme.com"},
        headers=h,
    )
    return h


def test_confirm_opens_the_gate_and_starts_the_trial(
    client: TestClient, configured_stripe: None
) -> None:
    payments.set_default_transport(_FakeStripe())
    try:
        # Unique domain — the trial ledger is permanent and never cleared, so a
        # shared domain would carry another test's entry.
        dom = "confirmco-uniq.com"
        h = _owner(client, f"owner@{dom}")
        body = client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_123", "identifier": dom},
            headers=h,
        ).json()

        assert body["gate_passed"] is True
        # The trial started at signup; adding a card mid-trial is this tenant's own
        # trial, never "already used", and keeps the trial active.
        assert body["trial_allowed"] is True
        assert body["trial_ends_at"]
        # The fingerprint is anti-abuse state and must never be returned.
        assert "fingerprint" not in body["instrument"]
        assert body["instrument"]["last4"] == "4242"
        # The tenant is on the top plan with an active trial.
        tenant = client.get("/api/v1/tenant", headers=h).json()
        assert tenant["trial"]["active"] is True
        assert tenant["trial"]["payment_method_ok"] is True
    finally:
        payments.set_default_transport(None)


def test_colleagues_share_one_tenant_and_one_trial(
    client: TestClient, configured_stripe: None
) -> None:
    """A company gets ONE tenant and ONE trial. A second person from the same
    corporate domain joins the existing tenant as a member — they cannot spin up a
    second workspace or a second trial (PRD §12.7)."""
    # A domain unique to this test — the trial ledger is permanent (never cleared),
    # so a shared domain would carry a prior test's trial entry.
    dom = "teamco-share-uniq.com"
    payments.set_default_transport(_FakeStripe())
    try:
        h1 = _owner(client, f"first@{dom}")
        me1 = client.get("/api/v1/auth/me", headers=h1).json()
        assert me1["role"] == "owner"
        first = client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_1", "identifier": dom},
            headers=h1,
        ).json()
        # The trial began at signup; confirm attaches the card and keeps it active.
        assert first["gate_passed"] is True
        assert first["trial_allowed"] is True

        # A colleague on the same domain signs up.
        h2 = _owner(client, f"second@{dom}")
        me2 = client.get("/api/v1/auth/me", headers=h2).json()
        assert me2["tenant_id"] == me1["tenant_id"]  # same company, same tenant
        assert me2["role"] == "member"  # not a second owner

        # Billing is owner-only, so a member cannot open a second trial.
        r = client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_2", "identifier": dom},
            headers=h2,
        )
        assert r.status_code == 403
    finally:
        payments.set_default_transport(None)


def test_unconfigured_provider_reports_503(client: TestClient) -> None:
    from envelock.config import get_settings

    get_settings.cache_clear()
    h = _owner(client, "owner@acme.com")
    r = client.post(
        "/api/v1/billing/confirm",
        json={"provider": "stripe", "reference": "pm_1", "identifier": "acme.com"},
        headers=h,
    )
    assert r.status_code == 503


def test_ledger_entry_is_persisted(client: TestClient, configured_stripe: None) -> None:
    import asyncio

    from envelock.db import get_sessionmaker
    from envelock.models import DomainTrialLedger

    payments.set_default_transport(_FakeStripe())
    try:
        # Unique domain so this test owns its ledger row (the ledger is permanent
        # and shared across the whole session).
        dom = "ledgerco-uniq.com"
        h = _owner(client, f"owner@{dom}")
        # Signup already recorded the ledger row (trial started at signup). Confirm
        # backfills the payment fingerprint that keeps the anti-abuse lock useful.
        client.post(
            "/api/v1/billing/confirm",
            json={"provider": "stripe", "reference": "pm_1", "identifier": dom},
            headers=h,
        )

        async def _read() -> DomainTrialLedger | None:
            async with get_sessionmaker()() as s:
                return await s.get(DomainTrialLedger, dom)

        row = asyncio.run(_read())
        assert row is not None
        assert row.outcome == "active"
        assert row.payment_fingerprint == "fp_reused"
    finally:
        payments.set_default_transport(None)


# ── Regional acquirers behind the same interface ─────────────────────────────
class _FakeAcquirer:
    """A regional processor returning a stored-card token as the fingerprint."""

    async def request(
        self, method: str, url: str, *, headers: dict, json=None, data=None
    ) -> dict:
        if "storedPaymentMethods" in url:  # Adyen
            return {"id": "sp_1", "networkToken": "ntok_abc", "brand": "mc", "lastFour": "1111"}
        return {"pspReference": "psp_1", "resultCode": "Authorised"}


@pytest.mark.asyncio
async def test_regional_provider_verifies_through_the_same_interface() -> None:
    """Adyen (Europe) must satisfy the PaymentProvider contract exactly like
    Stripe — one region per rail, no branching in the funnel (PRD §12.8)."""
    adyen = payments.provider_for("adyen")
    assert adyen is not None
    instrument = await adyen.verify_instrument("sp_1", transport=_FakeAcquirer())
    assert instrument.provider == "adyen"
    assert instrument.fingerprint == "ntok_abc"
    assert instrument.last4 == "1111"


def test_configured_providers_span_the_americas_europe_and_asia() -> None:
    """The real rails are Stripe (North America + global) plus one acquirer each
    for Europe, Latin America and Asia. A dev-only sandbox rides alongside so the
    funnel is demonstrable without keys — it is never a real rail."""
    from envelock.billing.payments import _PROVIDERS

    assert {"stripe", "adyen", "mercadopago", "razorpay"} <= set(_PROVIDERS)
    assert "sandbox" in _PROVIDERS


def test_sandbox_provider_is_dev_only_and_verifies(monkeypatch) -> None:
    """The sandbox is configured only in development and never leaks into a real
    deployment; when active it yields a stable fingerprint like any real card."""
    import asyncio

    from envelock.billing.payments import PaymentError, provider_for
    from envelock.config import get_settings

    sandbox = provider_for("sandbox")
    assert sandbox is not None

    # Development: configured, and verifies any reference into a stable fingerprint.
    monkeypatch.setattr(get_settings(), "env", "development")
    assert sandbox.is_configured() is True
    inst = asyncio.run(sandbox.verify_instrument("4242424242424242"))
    assert inst.provider == "sandbox" and inst.fingerprint and inst.last4 == "4242"

    # Production: never configured, and refuses even if called directly.
    monkeypatch.setattr(get_settings(), "env", "production")
    assert sandbox.is_configured() is False
    try:
        asyncio.run(sandbox.verify_instrument("4242424242424242"))
        raise AssertionError("sandbox must refuse outside development")
    except PaymentError:
        pass


# ── Stripe hosted Checkout ───────────────────────────────────────────────────
def _sign(payload: bytes, secret: str, *, ts: int | None = None) -> str:
    import hashlib
    import hmac

    t = str(ts if ts is not None else int(time.time()))
    sig = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}"


def test_stripe_checkout_session_returns_redirect_url(
    client: TestClient, configured_stripe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With Stripe + a Price configured, /billing/checkout returns a hosted URL to
    redirect to — no card data touches us."""
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_STRIPE_PRICE_COMPLETE", "price_complete_x")
    get_settings.cache_clear()
    payments.set_default_transport(_FakeStripe())
    try:
        h = _owner(client, "owner@checkoutco-uniq.com")
        r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
        assert r.status_code == 200
        assert r.json()["url"].startswith("https://checkout.stripe.com/")
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()


def test_checkout_requires_stripe_configured(client: TestClient) -> None:
    """No Stripe key → the endpoint reports 503 rather than pretending to charge."""
    h = _owner(client, "owner@nostripe-uniq.com")
    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 503


def test_webhook_signature_is_verified() -> None:
    secret = "whsec_test"  # noqa: S105 — test secret
    payload = b'{"type":"ping"}'

    event = payments.verify_stripe_webhook(payload, _sign(payload, secret), secret)
    assert event["type"] == "ping"

    # Forged signature and a stale timestamp are both rejected.
    with pytest.raises(payments.WebhookError):
        payments.verify_stripe_webhook(payload, "t=1,v1=deadbeef", secret)
    stale = _sign(payload, secret, ts=int(time.time()) - 10_000)
    with pytest.raises(payments.WebhookError):
        payments.verify_stripe_webhook(payload, stale, secret)


def test_stripe_webhook_activates_the_plan(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A validly signed checkout.session.completed opens the gate and sets the
    plan — the webhook is the source of truth for activation."""
    import json as _json

    from envelock.config import get_settings

    secret = "whsec_test"  # noqa: S105 — test secret
    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", secret)
    get_settings.cache_clear()
    try:
        h = _owner(client, "owner@webhookco-uniq.com")
        tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]
        event = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "client_reference_id": tid,
                    "metadata": {
                        "tenant_id": tid,
                        "plan": "complete",
                        "domain": "webhookco-uniq.com",
                    },
                }
            },
        }
        payload = _json.dumps(event).encode()
        r = client.post(
            "/api/v1/billing/stripe/webhook",
            content=payload,
            headers={
                "Stripe-Signature": _sign(payload, secret),
                "Content-Type": "application/json",
            },
        )
        assert r.status_code == 200 and r.json()["received"] is True

        tenant = client.get("/api/v1/tenant", headers=h).json()
        assert tenant["trial"]["payment_method_ok"] is True
        assert tenant["subscribed_plan"] == "complete"
    finally:
        get_settings.cache_clear()


def test_stripe_webhook_rejects_a_forged_event(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", "whsec_test")
    get_settings.cache_clear()
    try:
        r = client.post(
            "/api/v1/billing/stripe/webhook",
            content=b'{"type":"checkout.session.completed"}',
            headers={"Stripe-Signature": "t=1,v1=deadbeef", "Content-Type": "application/json"},
        )
        assert r.status_code == 400
    finally:
        get_settings.cache_clear()


def _complete_checkout(client: TestClient, h: dict, tid: str, domain: str, secret: str) -> None:
    import json as _json

    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": tid,
                "customer": "cus_test_1",
                "metadata": {"tenant_id": tid, "plan": "complete", "domain": domain},
            }
        },
    }
    payload = _json.dumps(event).encode()
    r = client.post(
        "/api/v1/billing/stripe/webhook",
        content=payload,
        headers={"Stripe-Signature": _sign(payload, secret), "Content-Type": "application/json"},
    )
    assert r.status_code == 200


def test_portal_opens_after_checkout_stores_customer(
    client: TestClient, configured_stripe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checkout stores the Stripe customer id; the portal then opens against it."""
    from envelock.config import get_settings

    secret = "whsec_test"  # noqa: S105
    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", secret)
    get_settings.cache_clear()
    payments.set_default_transport(_FakeStripe())
    try:
        dom = "portalco-uniq.com"
        h = _owner(client, f"owner@{dom}")
        tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]

        # Before any checkout, the portal has no customer to open.
        assert client.post("/api/v1/billing/portal", json={}, headers=h).status_code == 409

        _complete_checkout(client, h, tid, dom, secret)

        r = client.post("/api/v1/billing/portal", json={}, headers=h)
        assert r.status_code == 200
        assert r.json()["url"].startswith("https://billing.stripe.com/")
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()


def test_subscription_deleted_drops_tenant_to_guard(
    client: TestClient, configured_stripe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the subscription ends, the tenant falls back to Guard (free), never
    locked out."""
    import json as _json

    from envelock.config import get_settings

    secret = "whsec_test"  # noqa: S105
    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", secret)
    get_settings.cache_clear()
    payments.set_default_transport(_FakeStripe())
    try:
        dom = "cancelco-uniq.com"
        h = _owner(client, f"owner@{dom}")
        tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]
        _complete_checkout(client, h, tid, dom, secret)
        assert client.get("/api/v1/tenant", headers=h).json()["subscribed_plan"] == "complete"

        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_test_1", "metadata": {"tenant_id": tid}}},
        }
        payload = _json.dumps(event).encode()
        r = client.post(
            "/api/v1/billing/stripe/webhook",
            content=payload,
            headers={
                "Stripe-Signature": _sign(payload, secret),
                "Content-Type": "application/json",
            },
        )
        assert r.status_code == 200

        tenant = client.get("/api/v1/tenant", headers=h).json()
        assert tenant["subscribed_plan"] == "guard"
        assert tenant["trial"]["payment_method_ok"] is False
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()
