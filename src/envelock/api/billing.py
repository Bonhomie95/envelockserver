"""Billing endpoints — the payment gate and trial ledger (PRD §12.7, §17.1).

The funnel (§12.7) is: sign up free → verify the domain → **payment method
required (THE GATE)** → integration + backfill → trial clock starts. This module
is the gate: it verifies a real payment instrument, records the append-only
domain-trial ledger entry that makes "one trial per domain, ever" enforceable,
and marks the tenant clear to integrate.

Billing is owner-only (PRD §15.1). Nothing here charges an account that has no
payment method attached — cost is incurred only after the gate is passed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import CurrentUser, OwnerUser
from envelock.billing import payments, trial
from envelock.config import get_settings
from envelock.db import get_session
from envelock.models import DomainTrialLedger, Tenant
from envelock.util.domains import is_free_mail, registrable_domain

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/providers")
async def payment_providers(principal: CurrentUser) -> dict:
    """Which payment rails are wired. One acquirer per region keeps conversion
    independent of geography (PRD §12.8)."""
    return {"configured": payments.configured_providers()}


class ConfirmRequest(BaseModel):
    provider: str
    #: Instrument reference collected client-side (a Stripe pm_…, or the acquirer's
    #: stored-payment-method / transaction reference).
    reference: str = Field(min_length=1, max_length=256)
    #: The mail-carrying domain the trial locks to. Free-mail addresses lock on
    #: mailbox + instrument instead (PRD §12.6).
    identifier: str = Field(min_length=1, max_length=320)


@router.post("/confirm")
async def confirm_payment_method(
    req: ConfirmRequest, principal: OwnerUser, session: Session
) -> dict:
    """Verify the instrument, record the trial ledger, open the gate.

    The domain trial ledger is append-only and permanent — it survives account
    deletion, which *is* the anti-abuse mechanism (§12.7). A registrable domain is
    not personal data, so retaining it through erasure is defensible.
    """
    provider = payments.provider_for(req.provider)
    if provider is None:
        raise HTTPException(404, "unknown payment provider")
    if not provider.is_configured():
        raise HTTPException(
            503, f"{req.provider} is not configured on this deployment"
        )

    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    try:
        instrument = await provider.verify_instrument(req.reference)
    except payments.PaymentError as exc:
        raise HTTPException(402, f"could not verify payment method: {exc}") from exc

    key = trial.trial_key(req.identifier, instrument.fingerprint)
    reg = registrable_domain(req.identifier)
    is_domain_trial = bool(reg and not is_free_mail(reg))

    existing = None
    related: list[trial.LedgerEntry] = []
    if is_domain_trial:
        row = await session.get(DomainTrialLedger, reg)
        if row is not None:
            existing = _to_entry(row)
        # Related-domain / shared-instrument soft flag (§12.7).
        if instrument.fingerprint:
            fp_rows = (
                (
                    await session.execute(
                        select(DomainTrialLedger).where(
                            DomainTrialLedger.payment_fingerprint
                            == instrument.fingerprint
                        )
                    )
                )
                .scalars()
                .all()
            )
            related = [_to_entry(r) for r in fp_rows if r.registrable_domain != reg]

    settings = get_settings()
    decision = trial.evaluate(
        identifier=req.identifier,
        existing=existing,
        related_entries=related,
        payment_fingerprint=instrument.fingerprint,
        trial_days=settings.trial_days,
    )

    # The gate is now passed regardless — a returning customer who cannot re-trial
    # can still subscribe. Cost (backfill, analysis) is incurred only after this.
    tenant.payment_method_ok = True

    now = datetime.now(UTC)
    started_trial = False
    if decision.allowed and existing is None:
        # First trial for this domain: record the permanent ledger entry and
        # start the clock.
        if is_domain_trial:
            session.add(
                DomainTrialLedger(
                    registrable_domain=reg,
                    first_trial_at=now,
                    first_tenant_id=tenant.id,
                    outcome="active",
                    payment_fingerprint=instrument.fingerprint,
                )
            )
        tenant.trial_started_at = now
        tenant.trial_ends_at = now + timedelta(days=settings.trial_days)
        started_trial = True

    await session.commit()

    return {
        "gate_passed": True,
        "trial_key": key,
        "eligibility": decision.eligibility.value,
        "trial_allowed": decision.allowed,
        "trial_started": started_trial,
        "trial_ends_at": tenant.trial_ends_at.isoformat()
        if tenant.trial_ends_at
        else None,
        "reason": decision.reason,
        "instrument": {
            "provider": instrument.provider,
            "brand": instrument.brand,
            "last4": instrument.last4,
            "reusable": instrument.reusable,
            # The fingerprint is anti-abuse state, never returned to the client.
        },
    }


def _to_entry(row: DomainTrialLedger) -> trial.LedgerEntry:
    return trial.LedgerEntry(
        registrable_domain=row.registrable_domain,
        first_trial_at=row.first_trial_at,
        outcome=row.outcome,
        payment_fingerprint=row.payment_fingerprint,
        override_by=str(row.override_by) if row.override_by else None,
    )
