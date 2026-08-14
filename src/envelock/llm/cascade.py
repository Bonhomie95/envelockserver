"""The cascade entry point the pipeline calls after rule scoring.

Order of operations, cheapest first:
  1. Is the cascade even on? (`ENVELOCK_LLM_PROVIDER` != none)   — a dict lookup
  2. Does the rule verdict warrant a judge? (the gate)          — in-memory
  3. Is this mailbox under its monthly cap?                     — one indexed query
  4. Only then call the provider.

Policy: the judge can **confirm or escalate** a verdict (a confident fraud verdict
on a High promotes it to Critical and attaches the callback), and it annotates the
alert with a plain-language rationale. It never lowers a rule tier — recall on real
payment fraud (§15.4, >95% target) must not depend on a model's confidence.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.config import get_settings
from envelock.core.enums import AlertTier
from envelock.core.events import MailEvent
from envelock.llm.base import LlmVerdict, Transport
from envelock.llm.gate import should_escalate
from envelock.llm.judge import Judge
from envelock.llm.providers import get_provider
from envelock.models import LlmUsage
from envelock.risk.engine import RiskAssessment

logger = logging.getLogger("envelock.llm")

_ORDER = {
    AlertTier.LOW: 0, AlertTier.MEDIUM: 1, AlertTier.HIGH: 2, AlertTier.CRITICAL: 3,
}
_BY_RANK = {v: k for k, v in _ORDER.items()}


def _promote(tier: AlertTier) -> AlertTier:
    return _BY_RANK[min(3, _ORDER[tier] + 1)]


async def _under_cap(
    session: AsyncSession, mailbox_id: UUID | None, period: str
) -> LlmUsage | None:
    """Return the mailbox's usage row if under the monthly cap, else None."""
    cap = get_settings().llm_max_calls_per_mailbox_month
    row = (
        await session.execute(
            select(LlmUsage).where(
                LlmUsage.mailbox_id == mailbox_id, LlmUsage.period == period
            )
        )
    ).scalar_one_or_none()
    if row is not None and row.calls >= cap:
        return None
    return row  # may be None (first call this period) — caller creates it


async def refine(
    session: AsyncSession,
    event,  # noqa: ANN001 — Event
    assessment: RiskAssessment | None,
    *,
    tenant_id: UUID,
    transport: Transport | None = None,
    provider=None,  # noqa: ANN001 — test injection
) -> tuple[RiskAssessment | None, LlmVerdict | None]:
    """Maybe run the LLM judge and fold its verdict into the assessment. Returns the
    (possibly promoted) assessment and the verdict (None when the cascade didn't run
    or the provider failed)."""
    if not isinstance(event, MailEvent):
        return assessment, None
    prov = provider if provider is not None else get_provider(transport)
    if prov is None or not prov.configured:
        return assessment, None
    if not should_escalate(assessment):
        return assessment, None

    mailbox_id = getattr(event, "mailbox_id", None)
    period = datetime.now(UTC).strftime("%Y-%m")
    cap = get_settings().llm_max_calls_per_mailbox_month
    usage = await _under_cap(session, mailbox_id, period)
    if usage is None:
        # Either at the cap, or first call — distinguish by re-checking existence.
        existing = (
            await session.execute(
                select(LlmUsage).where(
                    LlmUsage.mailbox_id == mailbox_id, LlmUsage.period == period
                )
            )
        ).scalar_one_or_none()
        if existing is not None and existing.calls >= cap:
            logger.info("llm cascade: mailbox %s at monthly cap", mailbox_id)
            return assessment, None
        usage = existing

    verdict = await Judge(prov).evaluate(
        sender=event.sender.address,
        subject=event.subject or "",
        body=_analyzable_body(event),
        signals=list(assessment.services) if assessment else [],
    )
    if verdict is None:
        return assessment, None

    # Meter the call (cost is the number that predicts COGS — always record it).
    if usage is None:
        usage = LlmUsage(
            tenant_id=tenant_id, mailbox_id=mailbox_id, period=period, calls=0, cost_micros=0
        )
        session.add(usage)
    usage.calls = (usage.calls or 0) + 1
    usage.cost_micros = (usage.cost_micros or 0) + verdict.cost_micros

    # Apply the verdict — escalate only, never demote.
    minc = get_settings().llm_min_confidence
    if (
        assessment is not None
        and verdict.escalate
        and verdict.confidence >= minc
        and assessment.tier is not AlertTier.CRITICAL
    ):
        new_tier = _promote(assessment.tier)
        # Client-facing: plain reason only — no confidence %, no model name. The
        # numbers stay internal (in the verdict + finding evidence).
        reason = verdict.rationale or "our fraud review found signs of a payment scam."
        client_line = f"Our fraud check agrees this looks like a scam: {reason}"
        assessment = replace(
            assessment,
            tier=new_tier,
            requires_callback=assessment.requires_callback or new_tier is AlertTier.CRITICAL,
            rationale=(*assessment.rationale, client_line),
            body=assessment.body + "\n" + client_line,
        )
    elif assessment is not None and verdict.rationale:
        # Not escalating, but a short plain note still adds context on the alert.
        note = f"Note: {verdict.rationale}"
        assessment = replace(assessment, body=assessment.body + "\n" + note)

    return assessment, verdict


def _analyzable_body(event: MailEvent) -> str:
    parts = [event.body_text or ""]
    for att in event.attachments:
        if att.extracted_text:
            parts.append(att.extracted_text)
    return "\n".join(p for p in parts if p)


__all__ = ["refine"]
