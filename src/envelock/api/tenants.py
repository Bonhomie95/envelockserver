"""Tenant, mailbox, alert and counterparty endpoints — the dashboard's data.

Everything here is persisted, tenant-scoped, and checked against the caller's
tenant on every access. Tenant isolation is verified, never assumed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser
from envelock.channels.mail.ingest import ingest_address, new_ingest_token, onboarding_instructions
from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.db import get_session
from envelock.detections.base import inactive_for
from envelock.models import (
    Alert,
    AuditEvent,
    BankRecord,
    Counterparty,
    Domain,
    LookalikeDomain,
    Mailbox,
    Tenant,
)
from envelock.platform import alerts as alert_svc
from envelock.platform import graph_store
from envelock.platform.graph import GRAPH, RiskProfile, Verdict
from envelock.platform.remediation import (
    RemediationAction,
    plan_remediation,
)
from envelock.util.domains import registrable_domain

router = APIRouter(prefix="/api/v1", tags=["tenant"])

Session = Annotated[AsyncSession, Depends(get_session)]


async def _tenant_or_404(session: AsyncSession, tenant_id: UUID) -> Tenant:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    return tenant


# ── Bootstrap ────────────────────────────────────────────────────────────────
class BootstrapRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str


@router.post("/tenants/bootstrap", status_code=201)
async def bootstrap(req: BootstrapRequest, principal: CurrentUser, session: Session) -> dict:
    """Create the tenant record and its first domain for the signed-in user."""
    existing = await session.get(Tenant, principal.tenant_id)
    if existing is None:
        existing = Tenant(id=principal.tenant_id, name=req.name)
        session.add(existing)
        await session.flush()

    reg = registrable_domain(req.domain)
    if not reg:
        raise HTTPException(422, "invalid domain")

    domain = (
        await session.execute(
            select(Domain).where(
                Domain.tenant_id == principal.tenant_id, Domain.registrable_domain == reg
            )
        )
    ).scalar_one_or_none()
    if domain is None:
        domain = Domain(
            tenant_id=principal.tenant_id,
            name=reg,
            registrable_domain=reg,
            verification_token=new_ingest_token(),
        )
        session.add(domain)

    await session.commit()
    return {
        "tenant_id": str(existing.id),
        "name": existing.name,
        "domain": reg,
        "verification": {
            "record": f"envelock-verify={domain.verification_token}",
            "host": f"_envelock.{reg}",
            "type": "TXT",
        },
        "ingest_address": ingest_address(domain.verification_token or ""),
    }


# ── Mailboxes ────────────────────────────────────────────────────────────────
class MailboxRequest(BaseModel):
    address: str
    mailbox_class: MailboxClass = MailboxClass.MONITORED
    sources: list[SourceMechanism] = Field(default_factory=list)
    is_shared: bool = False
    known_user_count: int = 1


def _mailbox_payload(m: Mailbox) -> dict:
    caps = capabilities_for(frozenset(SourceMechanism(s) for s in (m.sources or []) if s))
    return {
        "id": str(m.id),
        "address": m.address,
        "mailbox_class": m.mailbox_class,
        "sources": m.sources or [],
        "protection_level": protection_level(caps).value,
        "inactive_detections": inactive_for(caps),
        "is_shared": m.is_shared,
        "last_sync_at": m.last_sync_at.isoformat() if m.last_sync_at else None,
    }


@router.post("/mailboxes", status_code=201)
async def add_mailbox(req: MailboxRequest, principal: AdminUser, session: Session) -> dict:
    await _tenant_or_404(session, principal.tenant_id)
    caps = capabilities_for(frozenset(req.sources))
    mailbox = Mailbox(
        tenant_id=principal.tenant_id,
        address=req.address.lower(),
        mailbox_class=req.mailbox_class.value,
        sources=[s.value for s in req.sources],
        protection_level=protection_level(caps).value,
        inactive_detections=inactive_for(caps),
        is_shared=req.is_shared,
        known_user_count=req.known_user_count,
    )
    session.add(mailbox)
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        detail={"address": mailbox.address, "sources": mailbox.sources},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


@router.get("/mailboxes")
async def list_mailboxes(principal: CurrentUser, session: Session) -> dict:
    rows = (
        (await session.execute(select(Mailbox).where(Mailbox.tenant_id == principal.tenant_id)))
        .scalars()
        .all()
    )
    return {"mailboxes": [_mailbox_payload(m) for m in rows]}


# ── Alerts ───────────────────────────────────────────────────────────────────
def _alert_payload(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "tier": a.tier,
        "title": a.title,
        "body": a.body,
        "state": a.state,
        "mailbox_id": str(a.mailbox_id) if a.mailbox_id else None,
        "requires_callback": a.requires_callback,
        "callback_phone": a.callback_phone,
        "created_at": a.created_at.isoformat(),
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "escalated_at": a.escalated_at.isoformat() if a.escalated_at else None,
    }


@router.get("/alerts")
async def list_alerts(
    principal: CurrentUser, session: Session, state: str | None = None, limit: int = 100
) -> dict:
    query = select(Alert).where(Alert.tenant_id == principal.tenant_id)
    if state:
        query = query.where(Alert.state == state)
    rows = (
        (await session.execute(query.order_by(Alert.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return {"alerts": [_alert_payload(a) for a in rows], "count": len(rows)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: UUID, principal: CurrentUser, session: Session) -> dict:
    alert = await alert_svc.acknowledge(
        session, alert_id=alert_id, tenant_id=principal.tenant_id, actor_id=principal.user_id
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: UUID, principal: CurrentUser, session: Session, dismiss: bool = False
) -> dict:
    alert = await alert_svc.resolve(
        session,
        alert_id=alert_id,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        dismissed=dismiss,
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/quarantine")
async def quarantine(alert_id: UUID, principal: CurrentUser, session: Session) -> dict:
    """E2. Refuses honestly on forwarding-connected mailboxes."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != principal.tenant_id:
        raise HTTPException(404, "alert not found")

    source = SourceMechanism.FORWARD_INGEST
    caps = frozenset()
    if alert.mailbox_id:
        mailbox = await session.get(Mailbox, alert.mailbox_id)
        if mailbox and mailbox.sources:
            sources = frozenset(SourceMechanism(s) for s in mailbox.sources if s)
            caps = capabilities_for(sources)
            source = next(iter(sources))

    result = plan_remediation(
        action=RemediationAction.QUARANTINE, capabilities=caps, source=source
    )
    if result.succeeded:
        await alert_svc.record_audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=alert_svc.AuditAction.MESSAGE_QUARANTINED,
            target_type="alert",
            target_id=alert.id,
        )
        await session.commit()
    return {"succeeded": result.succeeded, "reason": result.reason, "alert_only": result.alert_only}


# ── Oversight (E4/E5/E6) ─────────────────────────────────────────────────────
@router.get("/oversight")
async def oversight(principal: AdminUser, session: Session) -> dict:
    summary = await alert_svc.oversight_summary(session, tenant_id=principal.tenant_id)
    mailboxes = (
        (await session.execute(select(Mailbox).where(Mailbox.tenant_id == principal.tenant_id)))
        .scalars()
        .all()
    )
    domains = (
        await session.execute(
            select(func.count()).select_from(Domain).where(Domain.tenant_id == principal.tenant_id)
        )
    ).scalar_one()
    return {
        **summary,
        "mailboxes": len(mailboxes),
        "domains": domains,
        "coverage": {
            level: sum(1 for m in mailboxes if m.protection_level == level)
            for level in ("full", "standard", "limited")
        },
    }


@router.get("/audit")
async def audit_trail(principal: AdminUser, session: Session, limit: int = 100) -> dict:
    """E5 — who read it, who acted, who ignored it."""
    rows = (
        (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == principal.tenant_id)
                .order_by(AuditEvent.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return {
        "events": [
            {
                "id": str(e.id),
                "action": e.action,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "target_type": e.target_type,
                "target_id": str(e.target_id) if e.target_id else None,
                "detail": e.detail,
                "at": e.created_at.isoformat(),
            }
            for e in rows
        ]
    }


@router.get("/escalations")
async def escalations(principal: AdminUser, session: Session) -> dict:
    steps = await alert_svc.due_escalations(session)
    mine = []
    for step in steps:
        alert = await session.get(Alert, step.alert_id)
        if alert and alert.tenant_id == principal.tenant_id:
            mine.append(
                {
                    "alert_id": str(step.alert_id),
                    "to": step.to,
                    "minutes_open": step.minutes_open,
                    "tier": step.tier.value,
                }
            )
    return {"due": mine, "count": len(mine)}


# ── Counterparties (E10) ─────────────────────────────────────────────────────
class BankRecordRequest(BaseModel):
    scheme: str
    identifier: str
    bank_name: str | None = None


@router.get("/counterparties")
async def list_counterparties(principal: CurrentUser, session: Session) -> dict:
    rows = (
        (
            await session.execute(
                select(Counterparty).where(Counterparty.tenant_id == principal.tenant_id)
            )
        )
        .scalars()
        .all()
    )
    out = []
    for c in rows:
        entry = GRAPH.lookup(c.registrable_domain)
        profile = RiskProfile(
            domain=c.registrable_domain,
            first_seen=c.first_seen_at,
            message_count=c.message_count,
            bank_records=0,
            verified_phone=c.verified_phone,
            auth_pass_rate=1.0,
            incidents=0,
            graph_verdict=entry.verdict if entry else None,
            domain_age_days=None,
        )
        out.append(
            {
                "domain": c.registrable_domain,
                "display_name": c.display_name,
                "message_count": c.message_count,
                "verified_phone": c.verified_phone,
                "risk_score": profile.score,
                "tier": profile.tier.value,
                "advice": profile.advice,
            }
        )
    return {"counterparties": sorted(out, key=lambda c: -c["risk_score"])}


@router.post("/counterparties/{domain}/phone")
async def set_phone(domain: str, phone: str, principal: AdminUser, session: Session) -> dict:
    """A2 — the number we prompt users to call. Never the one in the email."""
    reg = registrable_domain(domain)
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "counterparty not seen yet")
    row.verified_phone = phone
    await session.commit()
    return {"domain": reg, "verified_phone": phone}


@router.post("/counterparties/{domain}/bank-records", status_code=201)
async def add_bank_record(
    domain: str, req: BankRecordRequest, principal: AdminUser, session: Session
) -> dict:
    reg = registrable_domain(domain)
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = Counterparty(
            tenant_id=principal.tenant_id,
            registrable_domain=reg,
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
        )
        session.add(row)
        await session.flush()

    record = BankRecord(
        tenant_id=principal.tenant_id,
        counterparty_id=row.id,
        scheme=req.scheme,
        identifier=req.identifier.replace(" ", "").upper(),
        bank_name=req.bank_name,
        first_seen_at=datetime.now(UTC),
        verified_at=datetime.now(UTC),
        verified_by=principal.user_id,
    )
    session.add(record)
    await session.commit()
    return {"domain": reg, "identifier": record.identifier, "verified": True}


# ── Lookalikes (D1–D4, D7) ───────────────────────────────────────────────────
@router.get("/lookalikes")
async def list_lookalikes(principal: CurrentUser, session: Session) -> dict:
    rows = (
        (
            await session.execute(
                select(LookalikeDomain)
                .where(LookalikeDomain.tenant_id == principal.tenant_id)
                .order_by(LookalikeDomain.has_mx.desc(), LookalikeDomain.similarity.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "lookalikes": [
            {
                "candidate": row.candidate_domain,
                "protected": row.protected_domain,
                "technique": row.technique,
                "similarity": float(row.similarity),
                "armed": row.has_mx,
                "status": row.status,
                "first_seen_source": row.first_seen_source,
            }
            for row in rows
        ],
        "armed_count": sum(1 for row in rows if row.has_mx),
    }


@router.post("/lookalikes/{candidate}/report")
async def report_lookalike(
    candidate: str, principal: AdminUser, session: Session, fraudulent: bool = True
) -> dict:
    """E8 — one tenant's confirmation protects every other tenant."""
    entry = GRAPH.report(
        domain=candidate,
        verdict=Verdict.FRAUDULENT if fraudulent else Verdict.LEGITIMATE,
        tenant_id=principal.tenant_id,
    )
    # Write through so the moat survives a restart and is shared across instances.
    await graph_store.persist_report(
        session, entry, GRAPH.reporters_of(candidate)
    )
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="lookalike.reported",
        detail={"domain": candidate, "fraudulent": fraudulent},
    )
    await session.commit()
    return {
        "domain": entry.registrable_domain,
        "verdict": entry.verdict.value,
        "confirmations": entry.confirmations,
        "confidence": round(entry.confidence, 3),
        "shared_with_all_tenants": entry.actionable,
    }


@router.get("/ingest-address")
async def get_ingest_address(principal: AdminUser, session: Session) -> dict:
    domain = (
        await session.execute(
            select(Domain).where(Domain.tenant_id == principal.tenant_id).limit(1)
        )
    ).scalar_one_or_none()
    token = (domain.verification_token if domain else None) or new_ingest_token()
    return onboarding_instructions(token)
