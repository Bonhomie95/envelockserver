"""Payment providers behind one interface (PRD §12.7, §12.8, §17.1).

Pricing and the trial ledger were already built; this is the piece that actually
charges — and, just as important, the piece that yields a **reusable instrument
fingerprint** the domain-trial anti-abuse ledger keys on (§12.7).

Three principles:

* **One interface, thin providers.** `PaymentProvider` defines the two operations
  the funnel needs — collect and verify an instrument, then create a subscription.
  Stripe, Paystack and Flutterwave are separate implementations; the funnel never
  branches on which one.
* **Payment rails, not price, drive conversion in our markets.** Stripe alone
  loses a large share of Nigerian signups, so Paystack and Flutterwave are
  first-class, not afterthoughts.
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


# ── Transport (injectable for tests) ─────────────────────────────────────────
class Transport(Protocol):
    async def request(
        self, method: str, url: str, *, headers: dict, json: dict | None = None
    ) -> dict: ...


class HttpxTransport:
    async def request(
        self, method: str, url: str, *, headers: dict, json: dict | None = None
    ) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.request(method, url, headers=headers, json=json)
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
            json={
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


# ── Paystack (Nigeria / Africa) ──────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Paystack:
    id: str = "paystack"

    def _key(self) -> str | None:
        s = get_settings().paystack_secret_key
        return s.get_secret_value() if s else None

    def is_configured(self) -> bool:
        return bool(self._key())

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._key()}"}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        # `reference` is a transaction reference; verifying it returns the
        # authorization object whose `authorization_code`/`signature` is reusable.
        body = await _transport(transport).request(
            "GET",
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=self._headers(),
        )
        data = (body or {}).get("data") or {}
        auth = data.get("authorization") or {}
        return Instrument(
            provider=self.id,
            reference=reference,
            # Paystack's `signature` is stable per card across transactions.
            fingerprint=auth.get("signature"),
            brand=auth.get("brand") or auth.get("card_type"),
            last4=auth.get("last4"),
            reusable=bool(auth.get("reusable", True)),
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
            "https://api.paystack.co/subscription",
            headers=self._headers(),
            json={
                "customer": customer_email,
                "amount": amount_cents,
                "currency": currency.upper(),
                "interval": interval,
            },
        )
        data = (body or {}).get("data") or {}
        return Subscription(
            provider=self.id,
            reference=data.get("subscription_code", ""),
            status=data.get("status", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )


# ── Flutterwave (Nigeria / Africa) ───────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _Flutterwave:
    id: str = "flutterwave"

    def _key(self) -> str | None:
        s = get_settings().flutterwave_secret_key
        return s.get_secret_value() if s else None

    def is_configured(self) -> bool:
        return bool(self._key())

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._key()}"}

    async def verify_instrument(
        self, reference: str, *, transport: Transport | None = None
    ) -> Instrument:
        body = await _transport(transport).request(
            "GET",
            f"https://api.flutterwave.com/v3/transactions/{reference}/verify",
            headers=self._headers(),
        )
        data = (body or {}).get("data") or {}
        card = data.get("card") or {}
        return Instrument(
            provider=self.id,
            reference=reference,
            # Flutterwave hashes the card into a stable token.
            fingerprint=card.get("token") or card.get("first_6digits"),
            brand=card.get("type"),
            last4=card.get("last_4digits"),
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
            "https://api.flutterwave.com/v3/payment-plans",
            headers=self._headers(),
            json={
                "amount": amount_cents / 100,
                "interval": interval,
                "currency": currency.upper(),
                "name": f"Envelock {interval}",
            },
        )
        data = (body or {}).get("data") or {}
        return Subscription(
            provider=self.id,
            reference=str(data.get("id", "")),
            status=data.get("status", "unknown"),
            amount_cents=amount_cents,
            currency=currency,
            raw=body,
        )


_PROVIDERS: dict[str, PaymentProvider] = {
    p.id: p for p in (_Stripe(), _Paystack(), _Flutterwave())
}


def provider_for(name: str) -> PaymentProvider | None:
    return _PROVIDERS.get(name.lower())


def configured_providers() -> list[str]:
    return [pid for pid, p in _PROVIDERS.items() if p.is_configured()]
