"""New wiring: notification dispatch, escalation cycle, and the E8 feedback loop
from confirmed-fraud alert resolution.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio

from envelock.core.enums import AlertTier
from envelock.models import Alert, Tenant, User
from envelock.notify.dispatch import deliver_pending, run_escalation_cycle
from envelock.notify.senders import Dispatcher
from envelock.platform import alerts as alert_svc
from envelock.platform.graph import GRAPH, Verdict
from envelock.risk.engine import RiskAssessment


@pytest_asyncio.fixture
async def session() -> AsyncIterator:
    from envelock.db import Base, dispose, get_engine, get_sessionmaker

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with get_sessionmaker()() as s:
        yield s
    await dispose()


def _assessment(tier: AlertTier) -> RiskAssessment:
    return RiskAssessment(
        tier=tier,
        score=90,
        title="Bank details changed on a known vendor",
        body="",
        services=("A1",),
        requires_callback=True,
        callback_phone="+1 800 000 0000",
        rationale=(),
    )


async def _tenant_with_admin(session, *, email: str, phone: str | None = None):
    tenant = Tenant(id=uuid4(), name="Acme")
    session.add(tenant)
    admin = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email=email,
        role="owner",
        is_admin=True,
        out_of_band_email="it@acme.com",
        phone=phone,
    )
    session.add(admin)
    await session.flush()
    return tenant, admin


@pytest.mark.asyncio
async def test_deliver_pending_sends_in_app_and_skips_unconfigured(session) -> None:
    from envelock.notify.ladder import Recipient

    tenant, admin = await _tenant_with_admin(session, email="a@acme.com")
    alert = await alert_svc.raise_alert(
        session,
        tenant_id=tenant.id,
        mailbox_id=None,
        assessment=_assessment(AlertTier.CRITICAL),
        findings=[],
        recipients=[
            Recipient(
                user_id=str(admin.id),
                is_admin=True,
                has_push_subscription=False,
                out_of_band_email="it@acme.com",
                phone=None,
                has_sensor=False,
            )
        ],
        counterparty_domain="vendor.com",
    )
    await session.flush()

    touched = await deliver_pending(session, alert_id=alert.id)
    by_rung = {d.rung: d.status for d in touched}

    # L0 in-app always sends; L2 email is unconfigured in tests → skipped, not failed.
    assert by_rung["L0"] == "sent"
    assert by_rung.get("L2") in {"skipped", "sent"}
    assert all(d.status != "pending" for d in touched)


@pytest.mark.asyncio
async def test_resolving_a_critical_feeds_the_e8_graph(session) -> None:
    GRAPH.clear()
    tenant, admin = await _tenant_with_admin(session, email="b@acme.com")
    alert = await alert_svc.raise_alert(
        session,
        tenant_id=tenant.id,
        mailbox_id=None,
        assessment=_assessment(AlertTier.CRITICAL),
        findings=[],
        counterparty_domain="fraudster.com",
    )
    await session.flush()

    # A second tenant independently confirms the same domain → actionable.
    GRAPH.report(domain="fraudster.com", verdict=Verdict.FRAUDULENT, tenant_id=uuid4())

    resolved = await alert_svc.resolve(
        session, alert_id=alert.id, tenant_id=tenant.id, actor_id=admin.id, dismissed=False
    )
    assert resolved is not None and resolved.state == "resolved"

    entry = GRAPH.lookup("fraudster.com")
    assert entry is not None
    assert entry.verdict is Verdict.FRAUDULENT
    assert entry.actionable  # now protects every other tenant


@pytest.mark.asyncio
async def test_dismissing_a_false_positive_does_not_feed_the_graph(session) -> None:
    GRAPH.clear()
    tenant, admin = await _tenant_with_admin(session, email="c@acme.com")
    alert = await alert_svc.raise_alert(
        session,
        tenant_id=tenant.id,
        mailbox_id=None,
        assessment=_assessment(AlertTier.CRITICAL),
        findings=[],
        counterparty_domain="legit-vendor.com",
    )
    await session.flush()

    await alert_svc.resolve(
        session, alert_id=alert.id, tenant_id=tenant.id, actor_id=admin.id, dismissed=True
    )
    # A dismissal is a false positive — it must never propagate as fraud.
    assert GRAPH.lookup("legit-vendor.com") is None


@pytest.mark.asyncio
async def test_escalation_cycle_marks_old_criticals(session) -> None:
    tenant, admin = await _tenant_with_admin(
        session, email="d@acme.com", phone="+1 800 111 2222"
    )
    alert = await alert_svc.raise_alert(
        session,
        tenant_id=tenant.id,
        mailbox_id=None,
        assessment=_assessment(AlertTier.CRITICAL),
        findings=[],
        counterparty_domain="vendor.com",
    )
    # Backdate it past the 15-minute escalation threshold.
    alert.created_at = datetime.now(UTC) - timedelta(minutes=20)
    await session.flush()

    done = await run_escalation_cycle(session, tenant_id=tenant.id, dispatcher=Dispatcher())
    assert len(done) == 1
    assert done[0]["to"] == "it_admin"

    refreshed = await session.get(Alert, alert.id)
    assert refreshed.escalated_at is not None


@pytest.mark.asyncio
async def test_unverified_phone_is_never_an_sms_destination(session) -> None:
    """A Critical fraud alert must not be SMS'd to an unproven number an attacker
    could have set — only verified phones are ladder destinations."""
    from envelock.api.channels import _tenant_recipients

    tenant = Tenant(id=uuid4(), name="Acme")
    session.add(tenant)
    session.add(
        User(
            id=uuid4(), tenant_id=tenant.id, email="unverified@acme.com",
            role="owner", is_admin=True, phone="+1 415 555 0199", phone_verified=False,
        )
    )
    session.add(
        User(
            id=uuid4(), tenant_id=tenant.id, email="verified@acme.com",
            role="member", is_admin=False, phone="+1 415 555 0142", phone_verified=True,
        )
    )
    await session.flush()

    recipients = await _tenant_recipients(session, tenant.id)
    phones = {r.phone for r in recipients}
    assert "+1 415 555 0142" in phones  # verified survives
    assert "+1 415 555 0199" not in phones  # unverified is dropped
    assert None in phones
