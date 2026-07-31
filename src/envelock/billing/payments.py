"""Payment providers behind one interface (PRD §12.7, §12.8, §17.1).

Pricing and the trial ledger were already built; this is the piece that actually
charges — and, just as important, the piece that yields a **reusable instrument
fingerprint** the domain-trial anti-abuse ledger keys on (§12.7).

Three principles:

* **One interface, thin providers.** `PaymentProvider` defines the two operations
  the funnel needs — collect and verify an instrument, then create a subscription.
  Stripe, Adyen, Mercado Pago and Razorpay are separate implementations; the
  funnel never branches on which one.
* **One rail per region, so conversion never depends on geography.** Stripe is the
  primary processor for North America and most of the world; Adyen covers Europe,
  Mercado Pago covers Latin America, and Razorpay covers South and Southeast Asia.
* **Injectable transport.** The network call sits behind a `Transport` so the flow
  is tested against a fake; only the live HTTP call differs in production.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from envelock.config import get_settings


class PaymentError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Instrument:
    """A verified payment method. `fingerprint` is stable across signups, which is
    what lets the domain-trial ledger catch repeat trial abuse (PRD §12.7).

    Bank transfer yields no reusable fingerprint — the ledger carries the full
    anti-abuse weight there, and those signups warrant a soft review flag.
    """

    provider: str
    reference: str
    fingerprint: str | None
    brand: str | None = None
    last4: str | None = None
    reusable: bool = True


@dataclass(frozen=True, slots=True)
class Subscription:
    provider: str
    reference: str
    status: str
    amount_cents: int
    currency: str
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CheckoutSession:
    """A hosted-checkout redirect. The card form lives on the provider's domain,
    so raw card data never touches us — the PCI-simplest way to take a card."""

    provider: str
    id: str
    url: str


# ── Transport (injectable for tests) ─────────────────────────────────────────
class Transport(Protocol):
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict,
        json: dict | None = None,
        data: dict | None = None,
    ) -> dict: ...


class HttpxTransport:
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict,
        json: dict | None = None,
        data: dict | None = None,
    ) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            # Stripe (and most acquirers) speak form-encoding; `data` takes
            # precedence when a caller needs it, else fall back to JSON.
            resp = await client.request(
                method, url, headers=headers, data=data, json=None if data else json
            )
        if resp.status_code >= 400:
            raise PaymentError(f"{url} returned {resp.status_code}: {resp.text[:200]}")
        return resp.json()


_DEFAULT_TRANSPORT: Transport | None = None


def set_default_transport(transport: Transport | None) -> None:
    global _DEFAULT_TRANSPORT
    _DEFAULT_TRANSPORT = transport


def _transport(explicit: Transport | None) -> Transport:
    return explicit or _DEFAULT_TRANSPORT or HttpxTransport()


# ── Provider interface ───────────────────────────────────────────────────────
class PaymentProvider(Protocol):
    id: str

    def is_configured(self) -> bool: ...

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument: ...

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription: ...


# ── Stripe ───────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Stripe:
    id: str = "stripe"

    def _key(self) -> str | None:
        s = get_settings().stripe_secret_key
        return s.get_secret_value() if s else None

    def is_configured(self) -> bool:
        return bool(self._key())

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._key()}"}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        # `reference` is a PaymentMethod id collected client-side (pm_...). We
        # retrieve it to read the card fingerprint Stripe computes for us.
        body = await _transport(transport).request(
            "GET",
            f"https://api.stripe.com/v1/payment_methods/{reference}",
            headers=self._headers(),
        )
        card = body.get("card") or {}
        return Instrument(
            provider=self.id,
            reference=reference,
            fingerprint=card.get("fingerprint"),
            brand=card.get("brand"),
            last4=card.get("last4"),
        )

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription:
        body = await _transport(transport).request(
            "POST",
            "https://api.stripe.com/v1/subscriptions",
            headers=self._headers(),
            data={
                "customer_email": customer_email,
                "amount": amount_cents,
                "currency": currency,
                "interval": interval,
            },
        )
        return Subscription(
            provider=self.id,
            reference=body.get("id", ""),
            status=body.get("status", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )

    async def create_checkout_session(
        self,
        *,
        price_id: str,
        customer_email: str,
        success_url: str,
        cancel_url: str,
        client_reference_id: str,
        metadata: dict[str, str] | None = None,
        transport: Transport | None = None,
    ) -> CheckoutSession:
        """Create a hosted Stripe Checkout Session in subscription mode.

        Pricing lives in Stripe as a Price object, referenced by id — no amount is
        passed here, so a price change never needs a redeploy. `metadata` and
        `client_reference_id` ride through to the webhook so we can attribute the
        completed payment to the right tenant and plan.
        """
        if not self.is_configured():
            raise PaymentError("Stripe is not configured on this deployment")
        # Stripe wants form-encoded, nested keys.
        form: dict[str, str] = {
            "mode": "subscription",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": "1",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "customer_email": customer_email,
            "client_reference_id": client_reference_id,
        }
        for k, v in (metadata or {}).items():
            form[f"metadata[{k}]"] = v
            # Mirror onto the subscription so it's visible after the session expires.
            form[f"subscription_data[metadata][{k}]"] = v
        body = await _transport(transport).request(
            "POST",
            "https://api.stripe.com/v1/checkout/sessions",
            headers=self._headers(),
            data=form,
        )
        return CheckoutSession(
            provider=self.id, id=body.get("id", ""), url=body.get("url", "")
        )

    async def create_billing_portal_session(
        self,
        *,
        customer_id: str,
        return_url: str,
        transport: Transport | None = None,
    ) -> str:
        """Open the Stripe-hosted billing portal so the customer can update their
        card, see invoices, or cancel — self-service, no code from us. Returns the
        one-time URL to redirect to."""
        if not self.is_configured():
            raise PaymentError("Stripe is not configured on this deployment")
        body = await _transport(transport).request(
            "POST",
            "https://api.stripe.com/v1/billing_portal/sessions",
            headers=self._headers(),
            data={"customer": customer_id, "return_url": return_url},
        )
        return body.get("url", "")


# ── Adyen (Europe / global enterprise) ───────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Adyen:
    id: str = "adyen"

    def _key(self) -> str | None:
        s = get_settings().adyen_api_key
        return s.get_secret_value() if s else None

    def is_configured(self) -> bool:
        return bool(self._key() and get_settings().adyen_merchant_account)

    def _headers(self) -> dict:
        return {"X-API-Key": self._key() or ""}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        # `reference` is a stored-payment-method id; its details carry the
        # network token Adyen keeps stable across a shopper's transactions.
        body = await _transport(transport).request(
            "GET",
            f"https://checkout-test.adyen.com/v71/storedPaymentMethods/{reference}",
            headers=self._headers(),
        )
        return Instrument(
            provider=self.id,
            reference=reference,
            fingerprint=body.get("networkToken") or body.get("id"),
            brand=body.get("brand"),
            last4=body.get("lastFour"),
        )

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription:
        body = await _transport(transport).request(
            "POST",
            "https://checkout-test.adyen.com/v71/payments",
            headers=self._headers(),
            json={
                "merchantAccount": get_settings().adyen_merchant_account,
                "shopperEmail": customer_email,
                "amount": {"value": amount_cents, "currency": currency.upper()},
                "recurringProcessingModel": "Subscription",
                "shopperInteraction": "ContAuth",
            },
        )
        return Subscription(
            provider=self.id,
            reference=body.get("pspReference", ""),
            status=body.get("resultCode", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )


# ── Mercado Pago (Latin America) ─────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _MercadoPago:
    id: str = "mercadopago"

    def _token(self) -> str | None:
        s = get_settings().mercadopago_access_token
        return s.get_secret_value() if s else None

    def is_configured(self) -> bool:
        return bool(self._token())

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}"}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        body = await _transport(transport).request(
            "GET",
            f"https://api.mercadopago.com/v1/payments/{reference}",
            headers=self._headers(),
        )
        card = (body or {}).get("card") or {}
        return Instrument(
            provider=self.id,
            reference=reference,
            # The saved-card id is stable per card for the customer.
            fingerprint=str(card.get("id")) if card.get("id") else None,
            brand=(body.get("payment_method_id") or None),
            last4=card.get("last_four_digits"),
        )

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription:
        body = await _transport(transport).request(
            "POST",
            "https://api.mercadopago.com/preapproval",
            headers=self._headers(),
            json={
                "payer_email": customer_email,
                "auto_recurring": {
                    "frequency": 1,
                    "frequency_type": "months" if interval == "monthly" else interval,
                    "transaction_amount": amount_cents / 100,
                    "currency_id": currency.upper(),
                },
                "reason": "Envelock subscription",
            },
        )
        return Subscription(
            provider=self.id,
            reference=str((body or {}).get("id", "")),
            status=(body or {}).get("status", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )


# ── Razorpay (South and Southeast Asia) ──────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Razorpay:
    id: str = "razorpay"

    def _auth(self) -> tuple[str, str] | None:
        s = get_settings()
        secret = s.razorpay_key_secret.get_secret_value() if s.razorpay_key_secret else None
        return (s.razorpay_key_id, secret) if (s.razorpay_key_id and secret) else None

    def is_configured(self) -> bool:
        return self._auth() is not None

    def _headers(self) -> dict:
        import base64

        pair = self._auth() or ("", "")
        token = base64.b64encode(f"{pair[0]}:{pair[1]}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        body = await _transport(transport).request(
            "GET",
            f"https://api.razorpay.com/v1/payments/{reference}",
            headers=self._headers(),
        )
        card = (body or {}).get("card") or {}
        return Instrument(
            provider=self.id,
            reference=reference,
            # Razorpay's token id is stable for a saved card.
            fingerprint=body.get("token_id") or card.get("id"),
            brand=card.get("network"),
            last4=card.get("last4"),
        )

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription:
        body = await _transport(transport).request(
            "POST",
            "https://api.razorpay.com/v1/subscriptions",
            headers=self._headers(),
            json={
                "total_count": 12,
                "customer_notify": 1,
                "notes": {"email": customer_email, "interval": interval},
            },
        )
        return Subscription(
            provider=self.id,
            reference=(body or {}).get("id", ""),
            status=(body or {}).get("status", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )


# ── Sandbox (development only) ───────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Sandbox:
    """A no-network processor for local development and demos.

    It is *only ever* configured when `env == "development"`, so it can never be
    selected in staging or production — a real key is required there. It accepts
    any non-empty reference and derives a stable fingerprint from it, so the
    domain-trial anti-abuse ledger still behaves exactly as with a real card.
    """

    id: str = "sandbox"

    def is_configured(self) -> bool:
        return get_settings().env == "development"

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        if not self.is_configured():  # defence in depth — never live outside dev
            raise PaymentError("sandbox payments are only available in development")
        ref = (reference or "").strip()
        if not ref:
            raise PaymentError("a card reference is required")
        import hashlib

        fingerprint = "sbx_" + hashlib.sha256(ref.encode()).hexdigest()[:24]
        return Instrument(
            provider=self.id,
            reference=ref,
            fingerprint=fingerprint,
            brand="Sandbox",
            last4=ref[-4:].rjust(4, "0"),
        )

    async def create_subscription(
        self,
        *,
        customer_email: str,
        amount_cents: int,
        currency: str,
        interval: str,
        transport: Transport | None = None,
    ) -> Subscription:
        return Subscription(
            provider=self.id,
            reference="sub_sandbox",
            status="active",
            amount_cents=amount_cents,
            currency=currency,
            raw={"sandbox": True, "email": customer_email, "interval": interval},
        )


_PROVIDERS: dict[str, PaymentProvider] = {
    p.id: p for p in (_Stripe(), _Adyen(), _MercadoPago(), _Razorpay(), _Sandbox())
}


def provider_for(name: str) -> PaymentProvider | None:
    return _PROVIDERS.get(name.lower())


def configured_providers() -> list[str]:
    return [pid for pid, p in _PROVIDERS.items() if p.is_configured()]


class WebhookError(Exception):
    """Raised when a webhook signature can't be verified — treat as hostile."""


def verify_stripe_webhook(
    payload: bytes, sig_header: str | None, secret: str, *, tolerance: int = 300
) -> dict:
    """Verify a Stripe webhook signature and return the parsed event.

    Implements Stripe's scheme without the SDK: the `Stripe-Signature` header
    carries `t=<unix>,v1=<hex hmac>`; the signed payload is `"{t}.{raw body}"`
    HMAC-SHA256'd with the endpoint's signing secret. We constant-time compare and
    reject stale timestamps, so a replayed or forged event never reaches the
    handler. Anything unverifiable raises — a payment state change must never be
    driven by an unauthenticated request.
    """
    import hashlib
    import hmac
    import json as _json
    import time

    if not secret:
        raise WebhookError("no webhook signing secret configured")
    if not sig_header:
        raise WebhookError("missing signature header")

    parts = dict(
        p.split("=", 1) for p in sig_header.split(",") if "=" in p
    )
    timestamp, provided = parts.get("t"), parts.get("v1")
    if not timestamp or not provided:
        raise WebhookError("malformed signature header")
    if tolerance and abs(time.time() - int(timestamp)) > tolerance:
        raise WebhookError("timestamp outside tolerance")

    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise WebhookError("signature mismatch")

    try:
        return _json.loads(payload)
    except ValueError as exc:
        raise WebhookError("invalid JSON payload") from exc
