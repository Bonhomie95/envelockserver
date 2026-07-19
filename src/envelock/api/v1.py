"""Public API v1.

Enough surface to exercise the product end to end: quote pricing, check trial
eligibility, scan a domain for lookalikes (no integration required), and submit a
raw message for analysis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from envelock.billing import pricing, trial
from envelock.channels.external.lookalike import permutations, score_candidate
from envelock.channels.mail.parser import parse_message
from envelock.connect.advisor import PROVIDERS
from envelock.connect.lookup import build_plan, plan_payload
from envelock.core.capabilities import (
    Capability,
    capabilities_for,
    protection_level,
)
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.detections import identity as _identity  # noqa: F401  (registers)
from envelock.detections import impersonation as _impersonation  # noqa: F401  (registers)
from envelock.detections.base import (
    CounterpartyState,
    DetectionContext,
    inactive_for,
    registry,
    run_all,
)
from envelock.risk.engine import assess
from envelock.util.domains import registrable_domain

router = APIRouter(prefix="/api/v1")


# ── Pricing ──────────────────────────────────────────────────────────────────
class QuoteRequest(BaseModel):
    plan: pricing.Plan = pricing.Plan.COMPLETE
    term: pricing.BillingTerm = pricing.BillingTerm.MONTHLY
    mail_domains: int = Field(default=1, ge=0, le=1000)
    protected: int = Field(default=0, ge=0)
    monitored: int = Field(default=0, ge=0)
    solo_mailboxes: int = Field(default=0, ge=0)


@router.post("/pricing/quote")
async def pricing_quote(req: QuoteRequest) -> dict:
    q = pricing.quote(
        plan=req.plan,
        term=req.term,
        mail_domains=req.mail_domains,
        protected=req.protected,
        monitored=req.monitored,
        solo_mailboxes=req.solo_mailboxes,
    )
    return {
        "plan": q.plan,
        "term": q.term,
        "platform_cents": q.platform_cents,
        "protected_cents": q.protected_cents,
        "monitored_cents": q.monitored_cents,
        "subtotal_cents": q.subtotal_cents,
        "discount_cents": q.discount_cents,
        "total_cents": q.total_cents,
        "total_usd": q.total_usd,
        "breakdown": q.breakdown,
    }


# ── Trial ────────────────────────────────────────────────────────────────────
class TrialCheckRequest(BaseModel):
    identifier: str
    payment_fingerprint: str | None = None


@router.post("/trial/check")
async def trial_check(req: TrialCheckRequest) -> dict:
    decision = trial.evaluate(identifier=req.identifier, existing=None)
    return {
        "eligibility": decision.eligibility,
        "allowed": decision.allowed,
        "trial_key": decision.trial_key,
        "reason": decision.reason,
        "ends_at": decision.ends_at.isoformat() if decision.ends_at else None,
    }


# ── Channel 3 — works with zero integration ──────────────────────────────────
class DomainScanRequest(BaseModel):
    domain: str
    #: Domains observed in CT logs / zone files. In production the worker feeds
    #: these continuously; supplying them here makes the endpoint demoable.
    observed: list[str] = Field(default_factory=list)


@router.post("/domains/scan")
async def domain_scan(req: DomainScanRequest) -> dict:
    protected = registrable_domain(req.domain)
    if not protected:
        raise HTTPException(422, "invalid domain")

    candidates = req.observed or sorted(permutations(protected))[:200]
    hits = []
    for candidate in candidates:
        # `has_mx` is resolved by the worker via DNS; defaulted here.
        hit = score_candidate(candidate, protected)
        if hit is not None:
            hits.append(
                {
                    "candidate": hit.candidate,
                    "technique": hit.technique,
                    "similarity": hit.similarity,
                    "tier": hit.tier,
                    "armed": hit.is_armed,
                }
            )
    hits.sort(key=lambda h: h["similarity"], reverse=True)
    return {
        "protected_domain": protected,
        "candidates_checked": len(candidates),
        "hits": hits[:100],
        "note": "Channel 3 requires no mailbox access — this is the Guard tier.",
    }


# ── Connection advisor ───────────────────────────────────────────────────────
@router.get("/domains/{domain}/connect")
async def domain_connect(domain: str) -> dict:
    """Tell an IT team exactly how to connect this domain's mail.

    MX lookup identifies the provider, then we return the specific setup path.
    Every provider has one — an unrecognised MX record changes the *method*, not
    whether we can protect the mailbox (PRD §5).
    """
    reg = registrable_domain(domain)
    if not reg:
        raise HTTPException(422, "invalid domain")
    return plan_payload(await build_plan(reg))


@router.get("/providers")
async def providers() -> dict:
    """Every mail provider we recognise by name. The list is not the limit of
    what we support — it is what we can pre-configure automatically."""
    return {
        "count": len(PROVIDERS),
        "providers": [
            {
                "id": p.id,
                "name": p.name,
                "aliases": list(p.aliases),
                "imap_host": p.imap_host,
                "notes": p.notes,
                "best_method": p.methods[0].name if p.methods else None,
            }
            for p in PROVIDERS
        ],
    }


@router.get("/domains/{domain}/permutations")
async def domain_permutations(domain: str, limit: int = 200) -> dict:
    perms = sorted(permutations(domain))
    return {"domain": registrable_domain(domain), "count": len(perms), "sample": perms[:limit]}


# ── Coverage ─────────────────────────────────────────────────────────────────
@router.get("/coverage")
async def coverage(sources: str) -> dict:
    """Derived protection level and the *named* inactive detections (PRD E7)."""
    try:
        parsed = frozenset(SourceMechanism(s.strip()) for s in sources.split(",") if s.strip())
    except ValueError as exc:
        raise HTTPException(422, f"unknown source mechanism: {exc}") from exc

    caps = capabilities_for(parsed)
    return {
        "sources": sorted(parsed),
        "capabilities": sorted(caps),
        "protection_level": protection_level(caps),
        "active_detections": sorted(
            d.service for d in registry().values() if d.requires <= caps
        ),
        "inactive_detections": inactive_for(caps),
    }


# ── Analysis ─────────────────────────────────────────────────────────────────
class AnalyseRequest(BaseModel):
    raw_message: str
    owned_domains: list[str] = Field(default_factory=list)
    known_counterparties: list[str] = Field(default_factory=list)
    counterparty_known_bank_ids: list[str] = Field(default_factory=list)
    counterparty_message_count: int = 0
    counterparty_phone: str | None = None
    source: SourceMechanism = SourceMechanism.FORWARD_INGEST
    mailbox_class: MailboxClass = MailboxClass.PROTECTED


@router.post("/analyse")
async def analyse(req: AnalyseRequest) -> dict:
    """Run the detection suite over a raw RFC822 message."""
    tenant_id, mailbox_id = uuid4(), uuid4()
    owned = frozenset(registrable_domain(d) for d in req.owned_domains)
    known = frozenset(registrable_domain(d) for d in req.known_counterparties)

    # Remediability is a property of the source, not a request parameter: the
    # parser still refuses it for post-delivery sources (PRD §4 fn.3).
    caps = capabilities_for(frozenset({req.source}))

    event = parse_message(
        req.raw_message.encode(),
        tenant_id=tenant_id,
        mailbox_id=mailbox_id,
        source=req.source,
        owned_domains=owned,
        remediable=Capability.MODIFY_MESSAGE in caps,
    )

    sender_domain = registrable_domain(event.sender.domain)
    counterparty = None
    if req.counterparty_message_count or req.counterparty_known_bank_ids:
        counterparty = CounterpartyState(
            registrable_domain=sender_domain,
            message_count=req.counterparty_message_count,
            known_bank_ids=frozenset(req.counterparty_known_bank_ids),
            verified_phone=req.counterparty_phone,
        )

    ctx = DetectionContext(
        event=event,
        tenant_id=str(tenant_id),
        capabilities=caps,
        owned_domains=owned,
        known_counterparties=known,
        counterparty=counterparty,
        now=datetime.now(UTC),
    )

    findings = run_all(ctx)
    assessment = assess(findings)

    return {
        "message": {
            "from": event.sender.address,
            "display_name": event.sender.display,
            "reply_to": event.reply_to.address if event.reply_to else None,
            "subject": event.subject,
            "attachments": [a.filename for a in event.attachments],
            "urls": list(event.urls),
            "remediable": event.remediable,
        },
        "findings": [
            {
                "service": f.service,
                "tier": f.tier,
                "score": f.score,
                "summary": f.summary,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        "assessment": None
        if assessment is None
        else {
            "tier": assessment.tier,
            "score": assessment.score,
            "title": assessment.title,
            "body": assessment.body,
            "services": list(assessment.services),
            "requires_callback": assessment.requires_callback,
            "callback_phone": assessment.callback_phone,
            "rationale": list(assessment.rationale),
            "alertable": assessment.is_alertable,
        },
    }


@router.get("/catalogue")
async def catalogue() -> dict:
    """Every registered detection and what it needs to run."""
    return {
        "services": sorted(
            (
                {"service": d.service, "requires": sorted(d.requires)}
                for d in registry().values()
            ),
            key=lambda d: str(d["service"]),
        )
    }
