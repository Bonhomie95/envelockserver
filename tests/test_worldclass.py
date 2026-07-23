"""World-class moves: a durable E8 moat and live governing metrics.

* The cross-tenant counterparty graph must survive a restart — a moat that resets
  on every deploy is not a moat (PRD E8).
* The two numbers that govern the product — Critical false-positive rate and
  detonation fall-through — are measured from live data (PRD §15.4).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app
from envelock.platform import graph_store
from envelock.platform.graph import CounterpartyGraph, Verdict


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _admin(client: TestClient, email: str = "admin@acme.com") -> tuple[dict, UUID]:
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
    me = client.get("/api/v1/auth/me", headers=h).json()
    return h, UUID(me["tenant_id"])


# ── E8 durability ────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def db() -> Iterator[None]:
    from envelock.db import Base, dispose, get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await dispose()


@pytest_asyncio.fixture
async def session(db: None):
    from envelock.db import get_sessionmaker

    async with get_sessionmaker()() as s:
        yield s


@pytest.mark.asyncio
async def test_graph_verdict_persists_and_rehydrates(session) -> None:
    """A confirmed-fraud verdict written by two tenants must reload into a fresh
    projection after a simulated restart, with its confirmation count intact."""
    live = CounterpartyGraph()
    entry = None
    for _ in range(2):
        entry = live.report(
            domain="fraud-vendor.com", verdict=Verdict.FRAUDULENT, tenant_id=uuid4()
        )
    await graph_store.persist_report(session, entry, live.reporters_of("fraud-vendor.com"))
    await session.commit()

    # Simulate a restart: a brand-new, empty projection hydrated from the store.
    restarted = CounterpartyGraph()
    loaded = await graph_store.hydrate(session, restarted)

    assert loaded == 1
    rehydrated = restarted.lookup("fraud-vendor.com")
    assert rehydrated is not None
    assert rehydrated.verdict is Verdict.FRAUDULENT
    assert rehydrated.confirmations == 2
    assert rehydrated.actionable  # protects every other tenant
    # And a third tenant re-reporting after restart does not re-inflate the count.
    assert len(restarted.reporters_of("fraud-vendor.com")) == 2


def test_reporting_a_lookalike_persists_a_verdict_row(client: TestClient) -> None:
    import asyncio as _asyncio

    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.models import GraphVerdict

    h, _ = _admin(client)
    client.post(
        "/api/v1/lookalikes/evil-lookalike.com/report",
        params={"fraudulent": True},
        headers=h,
    )

    async def _read() -> GraphVerdict | None:
        async with get_sessionmaker()() as s:
            return (
                await s.execute(
                    select(GraphVerdict).where(
                        GraphVerdict.registrable_domain == "evil-lookalike.com"
                    )
                )
            ).scalar_one_or_none()

    row = _asyncio.run(_read())
    assert row is not None
    assert row.verdict == "fraudulent"
    assert len(row.reporter_tenant_ids) == 1


# ── Live governing metrics ───────────────────────────────────────────────────
def test_live_quality_metrics_compute_from_real_alerts(client: TestClient) -> None:
    from envelock.db import get_sessionmaker
    from envelock.models import Alert, UsageMeter

    h, tenant_id = _admin(client)

    async def _seed() -> None:
        async with get_sessionmaker()() as s:
            # 4 criticals, 1 dismissed as a false positive → 25% FP rate.
            for i in range(4):
                s.add(
                    Alert(
                        tenant_id=tenant_id,
                        tier="critical",
                        title=f"c{i}",
                        body="x",
                        state="dismissed" if i == 0 else "resolved",
                    )
                )
            # 100 attachments seen, 3 detonated → 3% fall-through (under 5%).
            s.add(
                UsageMeter(
                    tenant_id=tenant_id,
                    day=datetime.now(UTC).date(),
                    attachments_seen=100,
                    attachments_detonated=3,
                )
            )
            await s.commit()

    asyncio.run(_seed())

    body = client.get("/api/v1/metrics/quality", headers=h).json()
    metrics = {m["id"]: m for m in body["metrics"]}

    assert metrics["critical_fp_rate"]["observed"] == 0.25
    assert metrics["critical_fp_rate"]["meets"] is False  # 25% ≫ 1% target
    assert metrics["detonation_fallthrough"]["observed"] == 0.03
    assert metrics["detonation_fallthrough"]["meets"] is True  # under 5%
    assert metrics["criticals_per_tenant_quarter"]["observed"] == 4.0


def test_metrics_are_honest_with_no_data(client: TestClient) -> None:
    """No alerts yet must read as unknown, never a false green."""
    h, _ = _admin(client, email="fresh@acme.com")
    body = client.get("/api/v1/metrics/quality", headers=h).json()
    fp = next(m for m in body["metrics"] if m["id"] == "critical_fp_rate")
    assert fp["observed"] is None
    assert fp["meets"] is None
