"""Channel endpoints: brand posture, client sensor, simulation, worker status."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser
from envelock.channels.external.brand import (
    build_takedown,
    check_posture,
    probe_domain,
)
from envelock.channels.mail.broker import ImapBroker
from envelock.channels.mail.providers import provider_status
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import IdentityEventKind, SourceMechanism
from envelock.core.events import DeviceContext, IdentityEvent, NetworkContext
from envelock.db import get_session
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.detections.cascade import AttachmentCascade, UrlCascade
from envelock.models import Domain, LookalikeDomain, Mailbox, SensorSession
from envelock.notify.senders import Dispatcher
from envelock.platform.graph import GRAPH, SimulationRun, plan_backfill, simulations
from envelock.platform.pipeline import analyse_event
from envelock.util.domains import registrable_domain
from envelock.workers.watchers import (
    CertTransparencyWatcher,
    RdapClient,
    ZoneFileWatcher,
)

router = APIRouter(prefix="/api/v1", tags=["channels"])
Session = Annotated[AsyncSession, Depends(get_session)]

_BROKER = ImapBroker()
_CASCADE = AttachmentCascade()
_URLS = UrlCascade()
_RDAP = RdapClient()
_CT = CertTransparencyWatcher()


# ── D5 / D6 — brand posture ──────────────────────────────────────────────────
@router.get("/brand/{domain}/posture")
async def brand_posture(domain: str) -> dict:
    """Public: needs no mailbox access, so it works before signup."""
    reg = registrable_domain(domain)
    if not reg:
        raise HTTPException(422, "invalid domain")
    posture = await check_posture(reg)
    return {
        "domain": posture.domain,
        "spf_present": posture.spf_present,
        "dkim_selectors": list(posture.dkim_selectors_found),
        "dmarc_present": posture.dmarc_present,
        "dmarc_policy": posture.dmarc_policy,
        "dmarc_pct": posture.dmarc_pct,
        "protected": posture.protected,
        "tier": posture.tier.value,
        "summary": posture.summary,
        "recommendations": posture.recommendations,
    }


@router.get("/brand/{domain}/probe")
async def brand_probe(domain: str) -> dict:
    """D4 — a lookalike with MX configured is armed."""
    probe = await probe_domain(domain)
    return {
        "domain": probe.domain,
        "has_mx": probe.has_mx,
        "has_a": probe.has_a,
        "mx_hosts": list(probe.mx_hosts),
        "armed": probe.armed,
    }


@router.get("/brand/{domain}/registration")
async def brand_registration(domain: str) -> dict:
    """RDAP. Registrant identity is usually redacted post-GDPR; creation date is
    the field we actually need."""
    data = await _RDAP.lookup(domain)
    if data is None:
        return {"domain": registrable_domain(domain), "available": False}
    return {**data, "age_days": _RDAP.age_days(data.get("registered_at")), "available": True}


@router.post("/lookalikes/{candidate}/takedown")
async def takedown(candidate: str, principal: AdminUser, session: Session) -> dict:
    """D7 — turns an alert into a resolution."""
    row = (
        await session.execute(
            select(LookalikeDomain).where(
                LookalikeDomain.tenant_id == principal.tenant_id,
                LookalikeDomain.candidate_domain == registrable_domain(candidate),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "lookalike not found")

    registration = await _RDAP.lookup(row.candidate_domain)
    packet = build_takedown(
        candidate=row.candidate_domain,
        protected=row.protected_domain,
        technique=row.technique,
        registrar=(registration or {}).get("registrar"),
        registered_at=row.registered_at,
        has_mx=row.has_mx,
    )
    row.status = "takedown_requested"
    await session.commit()
    return {
        "candidate": packet.candidate,
        "subject": packet.subject,
        "body": packet.body,
        "registrar": (registration or {}).get("registrar"),
        "evidence": packet.evidence,
    }


# ── Channel 2 — client sensor ────────────────────────────────────────────────
class SensorHeartbeat(BaseModel):
    mailbox_address: str
    device_fingerprint: str = Field(min_length=8, max_length=128)
    browser: str | None = None
    os: str | None = None
    mail_client: str | None = None
    ip: str | None = None
    country: str | None = None


class SensorMessageOpened(BaseModel):
    mailbox_address: str
    device_fingerprint: str
    message_ref: str


@router.post("/sensor/heartbeat")
async def sensor_heartbeat(
    req: SensorHeartbeat, principal: CurrentUser, session: Session
) -> dict:
    """The sensor is what gives ISP mailboxes Group C at all (PRD §7.7)."""
    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    now = datetime.now(UTC)
    existing = (
        await session.execute(
            select(SensorSession).where(
                SensorSession.mailbox_id == mailbox.id,
                SensorSession.device_fingerprint == req.device_fingerprint,
                SensorSession.ended_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        session.add(
            SensorSession(
                tenant_id=principal.tenant_id,
                mailbox_id=mailbox.id,
                user_id=principal.user_id,
                device_fingerprint=req.device_fingerprint,
                ip=req.ip,
                country=req.country,
                browser=req.browser,
                os=req.os,
                mail_client=req.mail_client,
                started_at=now,
                last_seen_at=now,
            )
        )
    else:
        existing.last_seen_at = now

    await session.commit()
    return {"acknowledged": True, "at": now.isoformat()}


@router.post("/sensor/message-opened")
async def sensor_message_opened(
    req: SensorMessageOpened, principal: CurrentUser, session: Session
) -> dict:
    """Attested reads. C11 fires when a \\Seen flag flips with *no* attestation —
    cleaner than any audit log, and it needs no enterprise licence."""
    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")
    return {"recorded": True, "message_ref": req.message_ref}


class FlagChanged(BaseModel):
    mailbox_address: str
    message_ref: str
    flag: str = "seen"


@router.post("/sensor/flag-changed")
async def flag_changed(req: FlagChanged, principal: CurrentUser, session: Session) -> dict:
    """Called by the IMAP broker. Runs C11 through the real pipeline."""
    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    now = datetime.now(UTC)
    event = IdentityEvent(
        tenant_id=principal.tenant_id,
        mailbox_id=mailbox.id,
        occurred_at=now,
        ingested_at=now,
        source=SourceMechanism.IMAP_FLAGS,
        kind=IdentityEventKind.FLAG_CHANGED,
        target=req.message_ref,
        after=req.flag,
        sensor_attested=False,
        network=NetworkContext(),
        device=DeviceContext(),
    )
    domains = {
        d for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(
                    Domain.tenant_id == principal.tenant_id
                )
            )
        ).all()
    }
    result = await analyse_event(
        session, event, tenant_id=principal.tenant_id, owned_domains=frozenset(domains)
    )
    await session.commit()
    return {
        "findings": [
            {"service": f.service, "tier": f.tier.value, "summary": f.summary}
            for f in result.findings
        ],
        "alerted": result.alerted,
    }


@router.get("/sensor/config")
async def sensor_config(principal: CurrentUser) -> dict:
    from envelock.config import get_settings

    settings = get_settings()
    return {
        "heartbeat_seconds": 60,
        "vapid_public_key": settings.vapid_public_key,
        "push_available": bool(settings.vapid_public_key),
        "endpoints": {
            "heartbeat": "/api/v1/sensor/heartbeat",
            "message_opened": "/api/v1/sensor/message-opened",
        },
    }


# ── E12 — attack simulation ──────────────────────────────────────────────────
class SimulationRequest(BaseModel):
    protected_domain: str
    vendor_domain: str = "supplier-example.com"


@router.post("/simulate")
async def simulate(req: SimulationRequest, principal: AdminUser, session: Session) -> dict:
    """Benign look-alike attacks that prove the product works. Every message
    carries an X-Envelock-Simulation header so it can never be mistaken for a
    real incident."""
    from envelock.channels.mail.parser import parse_message

    owned = frozenset({registrable_domain(req.protected_domain)})
    mailbox = (
        await session.execute(
            select(Mailbox).where(Mailbox.tenant_id == principal.tenant_id).limit(1)
        )
    ).scalar_one_or_none()

    # A simulation is only meaningful against a *known* vendor: A1 needs a
    # bank record to diff against and A3 needs the real domain to compare with.
    # Without that seed the run would report "not detected" for detections that
    # are working correctly — worse than not running it.
    vendor = registrable_domain(req.vendor_domain)
    seeded = CounterpartyState(
        registrable_domain=vendor,
        message_count=40,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
        verified_phone="+00 000 000 0000",
        last_seen_at=datetime.now(UTC),
    )

    runs: list[SimulationRun] = []
    for sim in simulations(
        protected_domain=req.protected_domain, vendor_domain=req.vendor_domain
    ):
        event = parse_message(
            sim.raw_message.encode(),
            tenant_id=principal.tenant_id,
            mailbox_id=mailbox.id if mailbox else uuid4(),
            source=SourceMechanism.IMAP_IDLE,
            owned_domains=owned,
            remediable=True,
        )
        ctx = DetectionContext(
            event=event,
            tenant_id=str(principal.tenant_id),
            capabilities=capabilities_for(
                frozenset({SourceMechanism.IMAP_IDLE, SourceMechanism.CLIENT_SENSOR})
            ),
            owned_domains=owned,
            known_counterparties=frozenset({vendor}),
            counterparty=seeded,
            now=datetime.now(UTC),
        )
        findings = run_all(ctx)
        result = type("R", (), {"findings": findings})()
        runs.append(
            SimulationRun(
                simulation_id=sim.id,
                expected=sim.expects,
                detected=[f.service for f in result.findings],
            )
        )

    return {
        "runs": [
            {
                "id": r.simulation_id,
                "expected": r.expected,
                "detected": r.detected,
                "passed": r.passed,
            }
            for r in runs
        ],
        "passed": sum(1 for r in runs if r.passed),
        "total": len(runs),
        "note": "Simulations are analysed but never stored as alerts.",
    }


# ── Tier 4 ingest over HTTP ──────────────────────────────────────────────────
class IngestRequest(BaseModel):
    raw_message: str
    mailbox_address: str


@router.post("/ingest", status_code=202)
async def ingest_message(
    req: IngestRequest, principal: AdminUser, session: Session
) -> dict:
    """Push a message through the real pipeline: detections run, counterparties
    are learned, and any alert is persisted.

    The SMTP listener uses the same path — this is its HTTP equivalent, which
    also makes the system demonstrable without configuring mail flow.
    """
    from envelock.channels.mail.parser import parse_message

    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    domains = {
        d
        for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(
                    Domain.tenant_id == principal.tenant_id
                )
            )
        ).all()
    }
    sources = frozenset(SourceMechanism(s) for s in (mailbox.sources or []) if s)
    source = next(iter(sources), SourceMechanism.FORWARD_INGEST)

    event = parse_message(
        req.raw_message.encode(),
        tenant_id=principal.tenant_id,
        mailbox_id=mailbox.id,
        source=source,
        owned_domains=frozenset(domains),
        remediable=True,
    )
    result = await analyse_event(
        session,
        event,
        tenant_id=principal.tenant_id,
        owned_domains=frozenset(domains),
    )
    await session.commit()

    return {
        "alerted": result.alerted,
        "alert_id": str(result.alert_id) if result.alert_id else None,
        "tier": result.assessment.tier.value if result.assessment else None,
        "findings": [
            {"service": f.service, "tier": f.tier.value, "summary": f.summary}
            for f in result.findings
        ],
        "latency_seconds": result.latency_seconds,
    }


# ── E11 — backfill ───────────────────────────────────────────────────────────
@router.post("/mailboxes/{mailbox_id}/backfill")
async def backfill(mailbox_id: UUID, principal: AdminUser, session: Session) -> dict:
    mailbox = await session.get(Mailbox, mailbox_id)
    if mailbox is None or mailbox.tenant_id != principal.tenant_id:
        raise HTTPException(404, "mailbox not found")
    plan = plan_backfill(mailbox_id=mailbox_id, in_trial=True)
    return {
        "mailbox": mailbox.address,
        "days": plan.days,
        "since": plan.since.isoformat(),
        "estimated_batches": plan.estimated_batches,
        "reason": plan.reason,
    }


# ── Operational status ───────────────────────────────────────────────────────
@router.get("/status/channels")
async def channel_status(principal: CurrentUser) -> dict:
    return {
        "mail_providers": provider_status(),
        "imap_broker": _BROKER.snapshot(),
        "notification_rungs": Dispatcher().status(),
        "zone_files": ZoneFileWatcher().status(),
        "cert_transparency": _CT.stats.payload(),
        "counterparty_graph": {"domains": len(GRAPH), "actionable": len(GRAPH.known_bad())},
    }


@router.get("/status/cost")
async def cost_status(principal: AdminUser) -> dict:
    """Fall-through is the number that predicts COGS (PRD §12.12D)."""
    return {
        "attachments": _CASCADE.metrics.payload(),
        "urls": _URLS.metrics.payload(),
        "detonation_enabled": _CASCADE.detonation_enabled,
    }
