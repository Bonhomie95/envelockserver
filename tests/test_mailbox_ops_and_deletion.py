"""Plan entitlement gate, forwarding connect, per-mailbox activity, and full
account deletion that keeps the anti-abuse domain ledger."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.db import get_sessionmaker
from envelock.main import app
from envelock.models import DomainTrialLedger, Tenant

PW = "a-long-enough-passphrase"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _session(client: TestClient, email: str, domain: str) -> dict:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _tenant_id(client: TestClient, h: dict) -> str:
    return client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]


def _add(client: TestClient, h: dict, address: str) -> str:
    return client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()["id"]


# ── Forwarding connect ────────────────────────────────────────────────────────
def test_forwarding_connect_marks_covered_alert_only(client: TestClient) -> None:
    h = _session(client, "it@fwd.example", "fwd.example")
    mid = _add(client, h, "ceo@fwd.example")

    out = client.post(f"/api/v1/mailboxes/{mid}/connect/forward", headers=h)
    assert out.status_code == 200
    body = out.json()
    assert "forward_ingest" in body["sources"]
    # Forwarding is post-delivery → alert-only → Limited is the honest ceiling.
    assert body["protection_level"] == "limited"


# ── Per-mailbox activity ──────────────────────────────────────────────────────
def test_mailbox_activity_shows_connection_events(client: TestClient) -> None:
    h = _session(client, "it@act.example", "act.example")
    mid = _add(client, h, "cfo@act.example")
    client.post(f"/api/v1/mailboxes/{mid}/connect/forward", headers=h)

    act = client.get(f"/api/v1/mailboxes/{mid}/activity", headers=h).json()
    assert act["connected"] is True
    assert act["messages_scanned"] == 0
    assert act["alerts_raised"] == 0
    actions = [e["action"] for e in act["events"]]
    assert "mailbox.connected" in actions  # both the add and the forward-connect


# ── Plan entitlement gate ─────────────────────────────────────────────────────
def test_mailbox_add_blocked_after_trial_lapses(client: TestClient) -> None:
    h = _session(client, "it@lapse.example", "lapse.example")
    tid = _tenant_id(client, h)

    async def _expire() -> None:
        async with get_sessionmaker()() as s:
            tenant = await s.get(Tenant, UUID(tid))
            assert tenant is not None
            tenant.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
            tenant.payment_method_ok = False
            await s.commit()

    asyncio.run(_expire())

    blocked = client.post(
        "/api/v1/mailboxes",
        json={"address": "new@lapse.example", "mailbox_class": "protected", "sources": []},
        headers=h,
    )
    assert blocked.status_code == 402  # add a payment method to protect mailboxes


# ── Full account deletion keeps the domain ledger ─────────────────────────────
def test_delete_account_keeps_domain_ledger_and_blocks_re_trial(client: TestClient) -> None:
    h = _session(client, "owner@delco.example", "delco.example")
    _add(client, h, "ceo@delco.example")

    # Wrong password is refused.
    bad = client.request(
        "DELETE", "/api/v1/tenant", json={"password": "wrong"}, headers=h
    )
    assert bad.status_code == 401

    ok = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
    assert ok.status_code == 200
    assert ok.json()["domain_ledger_retained"] is True

    # The ledger row survives deletion by design.
    async def _ledger_exists() -> bool:
        async with get_sessionmaker()() as s:
            return await s.get(DomainTrialLedger, "delco.example") is not None

    assert asyncio.run(_ledger_exists()) is True

    # A returning owner on the same domain gets NO fresh trial — paid from the start.
    h2 = _session(client, "owner2@delco.example", "delco.example")
    tenant = client.get("/api/v1/tenant", headers=h2).json()
    assert tenant["trial"]["active"] is False
    assert tenant["plan"] == "guard"
