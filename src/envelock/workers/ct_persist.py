"""Persist a Channel-3 lookalike match and raise a weaponisation-scored alert.

The CT watcher (D2) is the free Guard tier's primary sensor. Before this module a
match was counted in stats and thrown away; now every match that touches a
protected domain becomes a durable `LookalikeDomain` row and — once we confirm the
lookalike can actually send mail (MX present, D4) — a High alert. A lookalike
without MX is Low and logged for context, exactly as the alert model prescribes.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import AlertTier
from envelock.detections.base import FindingResult
from envelock.models import Domain, LookalikeDomain
from envelock.platform.alerts import raise_alert
from envelock.risk.engine import RiskAssessment

logger = logging.getLogger("envelock.ctpersist")


async def _tenants_protecting(session: AsyncSession, registrable: str) -> list[tuple[UUID, UUID]]:
    """(tenant_id, domain_id) for every tenant protecting this registrable domain."""
    rows = (
        await session.execute(
            select(Domain.tenant_id, Domain.id).where(
                Domain.registrable_domain == registrable
            )
        )
    ).all()
    return [(t, d) for (t, d) in rows]


async def persist_observation(session: AsyncSession, obs) -> int:  # noqa: ANN001
    """Persist a DomainObservation for every tenant that protects the target domain.
    Returns the number of tenants alerted."""
    if not obs.is_match or not obs.protected_domain:
        return 0

    # Weaponisation scoring (D4): does the lookalike have MX? Armed → High.
    has_mx = False
    try:
        from envelock.channels.external.brand import probe_domain

        probe = await probe_domain(obs.domain)
        has_mx = probe.has_mx
    except Exception as exc:  # noqa: BLE001 — MX probe is best-effort
        logger.debug("mx probe failed for %s: %s", obs.domain, exc)

    tenants = await _tenants_protecting(session, obs.protected_domain)
    alerted = 0
    for tenant_id, _domain_id in tenants:
        existing = (
            await session.execute(
                select(LookalikeDomain).where(
                    LookalikeDomain.tenant_id == tenant_id,
                    LookalikeDomain.candidate_domain == obs.domain,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            session.add(
                LookalikeDomain(
                    tenant_id=tenant_id,
                    protected_domain=obs.protected_domain,
                    candidate_domain=obs.domain,
                    technique=obs.technique or "cousin",
                    similarity=Decimal(str(round(obs.similarity or 0.0, 3))),
                    has_mx=has_mx,
                    has_web=False,
                    first_seen_source=obs.source,
                    status="open",
                )
            )
        else:
            existing.has_mx = existing.has_mx or has_mx

        # Only raise an alert when the lookalike is armed (D4). An unarmed lookalike
        # is Low — persisted for context, no interrupt.
        if has_mx:
            tier = AlertTier.HIGH
            finding = FindingResult(
                service="D4",
                tier=tier,
                score=70,
                summary=(
                    f"Armed lookalike domain {obs.domain} "
                    f"({obs.technique}) targeting {obs.protected_domain} — "
                    "MX records are configured, so it can send mail."
                ),
                evidence={
                    "candidate": obs.domain,
                    "protected": obs.protected_domain,
                    "technique": obs.technique,
                    "similarity": round(obs.similarity or 0.0, 3),
                    "has_mx": True,
                    "source": obs.source,
                },
            )
            assessment = RiskAssessment(
                tier=tier,
                score=70,
                title=f"Armed lookalike domain: {obs.domain}",
                body=(
                    f"A lookalike of {obs.protected_domain} was just issued a "
                    f"certificate and has mail (MX) configured: {obs.domain}. "
                    "It is positioned to impersonate you."
                ),
                services=("D2", "D4"),
                requires_callback=False,
                callback_phone=None,
                rationale=("Certificate Transparency match", "MX present → armed"),
            )
            await raise_alert(
                session,
                tenant_id=tenant_id,
                mailbox_id=None,
                assessment=assessment,
                findings=[finding],
                counterparty_domain=obs.domain,
            )
            alerted += 1

    await session.commit()
    return alerted
