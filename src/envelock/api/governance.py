"""Retention, export and detection-quality endpoints (PRD §15.2–§15.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser, OwnerUser
from envelock.core.enums import AlertTier
from envelock.db import get_session
from envelock.governance import export as ex
from envelock.governance import quality, retention
from envelock.models import Alert, UsageMeter

router = APIRouter(prefix="/api/v1", tags=["governance"])
Session = Annotated[AsyncSession, Depends(get_session)]


# ── Retention (§15.2) ────────────────────────────────────────────────────────
@router.get("/retention/schedule")
async def retention_schedule() -> dict:
    """Public. Buyers ask for this in the first call, so it needs no auth."""
    return {
        "schedule": retention.schedule_payload(),
        "churn": {
            "grace_days": retention.CHURN_GRACE_DAYS,
            "deletion_deadline_days": retention.CHURN_DELETION_DEADLINE_DAYS,
        },
    }


@router.get("/retention/deletion-plan")
async def deletion_plan(principal: OwnerUser) -> dict:
    """What deletion would remove and what survives it, for this tenant.

    Deletion must be demonstrable, so this is a report a customer can hold — not
    an internal note (PRD §15.2).
    """
    plan = retention.deletion_plan(closed_at=datetime.now(UTC))
    plan["tenant_id"] = str(principal.tenant_id)
    return plan


# ── Detection quality (§15.4) ────────────────────────────────────────────────
@router.get("/quality/targets")
async def quality_targets() -> dict:
    return {"targets": quality.targets_payload()}


class ConfusionInput(BaseModel):
    service: str
    true_positive: int = Field(default=0, ge=0)
    false_positive: int = Field(default=0, ge=0)
    false_negative: int = Field(default=0, ge=0)
    true_negative: int = Field(default=0, ge=0)


def _target(target_id: str) -> quality.Target | None:
    return next((t for t in quality.TARGETS if t.id == target_id), None)


def _measure(target_id: str, observed: float | None, *, sample: int) -> dict:
    """Compare a live number against its PRD §15.4 target."""
    target = _target(target_id)
    out: dict = {
        "id": target_id,
        "name": target.name if target else target_id,
        "observed": observed,
        "target": target.target if target else None,
        "unit": target.unit if target else None,
        "sample_size": sample,
    }
    # With no data yet, "meets" is unknowable rather than falsely green.
    out["meets"] = (
        None if observed is None or sample == 0 or target is None else target.meets(observed)
    )
    return out


@router.get("/metrics/quality")
async def live_quality_metrics(principal: AdminUser, session: Session) -> dict:
    """The two numbers that actually govern the product, measured from live data
    (PRD §15.4): the Critical false-positive rate and the detonation fall-through
    rate. Instrumented from day one — a security tool that cannot see its own
    noise floor will be muted before anyone tunes it.
    """
    tid = principal.tenant_id

    # Critical false-positive rate — a Critical dismissed as not-real is a false
    # positive; every one of them spent a human interrupt and maybe quarantined
    # real mail, so this is the number P5 is really about.
    total_crit = (
        await session.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.tenant_id == tid, Alert.tier == AlertTier.CRITICAL.value)
        )
    ).scalar_one()
    dismissed_crit = (
        await session.execute(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.tenant_id == tid,
                Alert.tier == AlertTier.CRITICAL.value,
                Alert.state == "dismissed",
            )
        )
    ).scalar_one()
    fp_rate = (dismissed_crit / total_crit) if total_crit else None

    # Criticals in the trailing quarter — above the target the channel gets muted.
    since = datetime.now(UTC) - timedelta(days=90)
    crit_quarter = (
        await session.execute(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.tenant_id == tid,
                Alert.tier == AlertTier.CRITICAL.value,
                Alert.created_at >= since,
            )
        )
    ).scalar_one()

    # Detonation fall-through — the single number that predicts COGS (§12.12D).
    seen, detonated = (
        await session.execute(
            select(
                func.coalesce(func.sum(UsageMeter.attachments_seen), 0),
                func.coalesce(func.sum(UsageMeter.attachments_detonated), 0),
            ).where(UsageMeter.tenant_id == tid)
        )
    ).one()
    fallthrough = (detonated / seen) if seen else None

    return {
        "tenant_id": str(tid),
        "metrics": [
            _measure("critical_fp_rate", fp_rate, sample=int(total_crit)),
            _measure(
                "criticals_per_tenant_quarter", float(crit_quarter), sample=int(crit_quarter)
            ),
            _measure("detonation_fallthrough", fallthrough, sample=int(seen)),
        ],
    }


@router.post("/quality/evaluate")
async def quality_evaluate(rows: list[ConfusionInput], principal: AdminUser) -> dict:
    """Roll per-detection outcomes into the tier-level targets."""
    if not rows:
        raise HTTPException(422, "no rows supplied")
    return quality.evaluate(
        [
            quality.Confusion(
                service=r.service,
                true_positive=r.true_positive,
                false_positive=r.false_positive,
                false_negative=r.false_negative,
                true_negative=r.true_negative,
            )
            for r in rows
        ]
    )


# ── Export and SIEM (§15.3) ──────────────────────────────────────────────────
async def _tenant_alerts(
    session: AsyncSession, tenant_id, *, limit: int = 5000
) -> list[ex.AlertRecord]:
    """The tenant's real alerts, newest first, shaped for every export format.

    Joins each alert's mailbox address and its lead finding's service so the CSV,
    JSONL and CEF an auditor or SIEM ingests carries the same detail the dashboard
    shows — not a placeholder."""
    from envelock.models import Finding, Mailbox, User

    rows = (
        await session.execute(
            select(Alert)
            .where(Alert.tenant_id == tenant_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    records: list[ex.AlertRecord] = []
    for a in rows:
        mailbox_addr = "domain-monitoring"
        if a.mailbox_id is not None:
            mb = await session.get(Mailbox, a.mailbox_id)
            if mb is not None:
                mailbox_addr = mb.address
        lead = (
            await session.execute(
                select(Finding.service)
                .where(Finding.alert_id == a.id)
                .order_by(Finding.score.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        acked_by = None
        if a.acknowledged_by is not None:
            u = await session.get(User, a.acknowledged_by)
            acked_by = u.email if u else str(a.acknowledged_by)
        records.append(
            ex.AlertRecord(
                id=str(a.id),
                tier=AlertTier(a.tier),
                service=lead or "-",
                title=a.title,
                mailbox=mailbox_addr,
                detail=a.body.replace("\n", " | ")[:500],
                raised_at=_aware(a.created_at),
                state=a.state,
                acknowledged_at=_aware(a.acknowledged_at),
                acknowledged_by=acked_by,
            )
        )
    return records


def _aware(dt):  # noqa: ANN001, ANN201
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


@router.get("/export/alerts.csv")
async def export_csv(principal: AdminUser, session: Session) -> Response:
    """What auditors actually ask for."""
    return Response(
        content=ex.to_csv(await _tenant_alerts(session, principal.tenant_id)),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="envelock-alerts.csv"'},
    )


@router.get("/export/alerts.jsonl")
async def export_jsonl(principal: AdminUser, session: Session) -> Response:
    records = await _tenant_alerts(session, principal.tenant_id)
    body = "\n".join(ex.to_json_line(a) for a in records)
    return Response(content=body, media_type="application/x-ndjson")


@router.get("/export/alerts.cef")
async def export_cef(principal: AdminUser, session: Session, syslog: bool = False) -> Response:
    """CEF for ArcSight, Splunk, QRadar and Sentinel; RFC 5424 framing optional."""
    fmt = ex.to_syslog if syslog else ex.to_cef
    records = await _tenant_alerts(session, principal.tenant_id)
    return Response(
        content="\n".join(fmt(a) for a in records),
        media_type="text/plain",
    )


class WebhookTestRequest(BaseModel):
    secret: str | None = None


@router.post("/export/webhooks/test")
async def webhook_test(req: WebhookTestRequest, principal: AdminUser) -> dict:
    """Returns a signed sample delivery so a customer can validate their
    verification code before going live."""
    secret = req.secret or ex.generate_webhook_secret()
    envelope = ex.webhook_envelope(
        ex.WebhookEvent.ALERT_RAISED,
        str(principal.tenant_id),
        {"alert_id": "alt_test", "tier": "critical", "detection": "A1"},
    )
    import json

    payload = json.dumps(envelope, separators=(",", ":")).encode()
    signature, timestamp = ex.sign_payload(secret, payload)

    return {
        "secret": secret,
        "headers": {
            ex.WEBHOOK_SIGNATURE_HEADER: signature,
            ex.WEBHOOK_TIMESTAMP_HEADER: str(timestamp),
        },
        "body": envelope,
        "verification": {
            "algorithm": "HMAC-SHA256 over `{timestamp}.{raw_body}`",
            "tolerance_seconds": ex.WEBHOOK_TOLERANCE_SECONDS,
            "retry_schedule_seconds": list(ex.RETRY_SCHEDULE),
        },
        "events": [e.value for e in ex.WebhookEvent],
    }


class TokenRequest(BaseModel):
    scopes: list[ex.Scope]


@router.post("/export/tokens", status_code=201)
async def create_token(req: TokenRequest, principal: OwnerUser, session: Session) -> dict:
    """Export tokens are read-only by design — a leaked read token is a far
    smaller incident than a leaked write token. Persisted (hash only) so a
    presented token actually authenticates something (PRD §15.3)."""
    from envelock.models import ExportToken

    try:
        plaintext, record = ex.issue_api_token(frozenset(req.scopes))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    session.add(
        ExportToken(
            tenant_id=principal.tenant_id,
            prefix=record.prefix,
            hashed=record.hashed,
            scopes=sorted(s.value for s in record.scopes),
            created_by=principal.user_id,
        )
    )
    await session.commit()
    return {
        "token": plaintext,
        "prefix": record.prefix,
        "scopes": sorted(s.value for s in record.scopes),
        "note": "Shown once. Only a hash is stored.",
    }


@router.get("/export/tokens")
async def list_tokens(principal: OwnerUser, session: Session) -> dict:
    from envelock.models import ExportToken

    rows = (
        await session.execute(
            select(ExportToken)
            .where(ExportToken.tenant_id == principal.tenant_id, ExportToken.revoked_at.is_(None))
            .order_by(ExportToken.created_at.desc())
        )
    ).scalars().all()
    return {
        "tokens": [
            {
                "prefix": t.prefix,
                "scopes": t.scopes,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
            }
            for t in rows
        ]
    }


@router.delete("/export/tokens/{prefix}", status_code=204)
async def revoke_token(prefix: str, principal: OwnerUser, session: Session) -> Response:
    from envelock.models import ExportToken

    row = (
        await session.execute(
            select(ExportToken).where(
                ExportToken.tenant_id == principal.tenant_id, ExportToken.prefix == prefix
            )
        )
    ).scalar_one_or_none()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        await session.commit()
    return Response(status_code=204)


async def _authenticate_export_token(session: AsyncSession, authorization: str | None):
    """Resolve an `Authorization: Bearer envk_...` read-only export token to its
    tenant and scopes, or raise 401. Records last_used_at."""
    from envelock.models import ExportToken

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing export token")
    plaintext = authorization.split(" ", 1)[1].strip()
    if not plaintext.startswith("envk_"):
        raise HTTPException(401, "not an export token")
    prefix = plaintext[len("envk_"):][:8]
    rows = (
        await session.execute(
            select(ExportToken).where(
                ExportToken.prefix == prefix, ExportToken.revoked_at.is_(None)
            )
        )
    ).scalars().all()
    for row in rows:
        stored = ex.ApiToken(
            prefix=row.prefix,
            hashed=row.hashed,
            scopes=frozenset(ex.Scope(s) for s in row.scopes),
        )
        if ex.verify_api_token(plaintext, stored):
            row.last_used_at = datetime.now(UTC)
            await session.commit()
            return row.tenant_id, stored.scopes
    raise HTTPException(401, "invalid export token")


@router.get("/export/api/alerts")
async def export_api_alerts(
    session: Session,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Read-only alert feed for a SIEM, authenticated by an export token (not a
    user session). This is what a customer points Splunk/Sentinel at."""
    tenant_id, scopes = await _authenticate_export_token(session, authorization)
    if ex.Scope.ALERTS_READ not in scopes:
        raise HTTPException(403, "token lacks alerts:read scope")
    records = await _tenant_alerts(session, tenant_id)
    return {
        "alerts": [
            {
                "id": r.id, "tier": r.tier.value, "service": r.service, "title": r.title,
                "mailbox": r.mailbox, "state": r.state,
                "raised_at": r.raised_at.isoformat() if r.raised_at else None,
            }
            for r in records
        ]
    }


@router.get("/export/scopes")
async def export_scopes(principal: CurrentUser) -> dict:
    return {"scopes": sorted(s.value for s in ex.ALL_SCOPES)}
