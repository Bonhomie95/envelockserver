"""Plan-based mailbox seat caps and the anti-abuse rules around them.

Rules under test:
  * Trial sits on the top plan → 7 mailboxes; a lapsed/unpaid tenant (Guard) → 0.
  * Adding beyond the cap is refused until seats are bought (or the plan upgraded).
  * A domain's trial can't be reused by deleting the account and re-registering.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.main import app

PW = "a-long-enough-passphrase"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _owner(client: TestClient, domain: str) -> dict:
    email = f"owner@{domain}"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _add(client: TestClient, h: dict, address: str) -> int:
    return client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected", "sources": []},
        headers=h,
    ).status_code


def _lapse_trial(client: TestClient, h: dict) -> None:
    from envelock.db import get_sessionmaker
    from envelock.models import Tenant

    tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]

    async def _run() -> None:
        async with get_sessionmaker()() as s:
            t = await s.get(Tenant, UUID(tid))
            t.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
            await s.commit()

    asyncio.run(_run())


def test_trial_caps_mailboxes_at_the_top_plan_allowance(client: TestClient) -> None:
    """On the Complete trial a tenant may protect 7 mailboxes; the 8th is refused."""
    h = _owner(client, "capco.example")
    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["mailboxes"]["capacity"] == 7

    for i in range(7):
        assert _add(client, h, f"box{i}@capco.example") == 201
    assert _add(client, h, "overflow@capco.example") == 402

    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["mailboxes"] == {
        "used": 7,
        "capacity": 7,
        "included": 7,
        "extra_seats": 0,
        "can_add": False,
    }


def test_guard_cannot_add_any_mailbox(client: TestClient) -> None:
    """Free/Guard (lapsed, unpaid) → capacity 0, no mailboxes until they upgrade."""
    h = _owner(client, "freeco.example")
    _lapse_trial(client, h)
    assert client.get("/api/v1/tenant", headers=h).json()["mailboxes"]["capacity"] == 0
    assert _add(client, h, "cfo@freeco.example") == 402


def test_bulk_add_respects_the_seat_cap(client: TestClient) -> None:
    """A big paste is filled up to the cap; the rest are reported for purchase."""
    h = _owner(client, "bulkco.example")  # Complete trial → cap 7
    addrs = [f"user{i}@bulkco.example" for i in range(10)]
    r = client.post(
        "/api/v1/mailboxes/bulk",
        json={"addresses": addrs, "mailbox_class": "protected"},
        headers=h,
    ).json()
    assert r["created_count"] == 7
    assert r["over_limit_count"] == 3
    assert r["capacity"] == 7


def test_buying_seats_raises_capacity(client: TestClient) -> None:
    """Extra seats (bought via the dev sandbox rail) lift the cap immediately."""
    h = _owner(client, "seatbuy.example")  # cap 7
    for i in range(7):
        assert _add(client, h, f"box{i}@seatbuy.example") == 201
    assert _add(client, h, "eighth@seatbuy.example") == 402  # full

    bought = client.post(
        "/api/v1/billing/seats",
        json={"count": 3, "provider": "sandbox", "reference": "4242424242424242"},
        headers=h,
    )
    assert bought.status_code == 200 and bought.json()["extra_mailbox_seats"] == 3

    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["mailboxes"]["capacity"] == 10
    assert _add(client, h, "eighth@seatbuy.example") == 201  # now fits


def test_trial_cannot_be_reused_after_deleting_the_account(client: TestClient) -> None:
    """Delete the account and re-register the same domain → no fresh trial, so the
    tenant lands on Guard and cannot add mailboxes (the ledger is permanent)."""
    domain = "reabuse.example"
    h = _owner(client, domain)
    assert _add(client, h, "cfo@reabuse.example") == 201  # trial works the first time

    # Delete the whole account (confirmed with the password).
    d = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
    assert d.status_code == 200 and d.json()["domain_ledger_retained"] is True

    # Re-register the very same domain.
    h2 = _owner(client, domain)
    t = client.get("/api/v1/tenant", headers=h2).json()
    assert t["trial"]["active"] is False
    assert t["mailboxes"]["capacity"] == 0
    assert _add(client, h2, "cfo@reabuse.example") == 402
