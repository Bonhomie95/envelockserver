"""Retention, export and detection-quality endpoints (PRD §15.2–§15.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
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
def _demo_alerts() -> list[ex.AlertRecord]:
    """Stand-in until alerts are persisted; the formatters are the real thing."""
    now = datetime.now(UTC)
    return [
        ex.AlertRecord(
            id="alt_01H9",
            tier=AlertTier.CRITICAL,
            service="A1",
            title="Payment details do not match the account on file",
            mailbox="pay@acme.com.ng",
            detail="Invoice 4471 | new IBAN GB33BUKB…5555 | 47 prior messages",
            raised_at=now,
            state="open",
        ),
        ex.AlertRecord(
            id="alt_01H8",
            tier=AlertTier.HIGH,
            service="D4",
            title="acrne.com.ng registered and configured to send mail",
            mailbox="domain-monitoring",
            detail="rn/m substitution | MX live",
            raised_at=now,
            state="acknowledged",
            acknowledged_at=now,
            acknowledged_by="it@acme.com.ng",
        ),
    ]


@router.get("/export/alerts.csv")
async def export_csv(principal: AdminUser) -> Response:
    """What auditors actually ask for."""
    return Response(
        content=ex.to_csv(_demo_alerts()),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="envelock-alerts.csv"'},
    )


@router.get("/export/alerts.jsonl")
async def export_jsonl(principal: AdminUser) -> Response:
    body = "\n".join(ex.to_json_line(a) for a in _demo_alerts())
    return Response(content=body, media_type="application/x-ndjson")


@router.get("/export/alerts.cef")
async def export_cef(principal: AdminUser, syslog: bool = False) -> Response:
    """CEF for ArcSight, Splunk, QRadar and Sentinel; RFC 5424 framing optional."""
    fmt = ex.to_syslog if syslog else ex.to_cef
    return Response(
        content="\n".join(fmt(a) for a in _demo_alerts()),
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
async def create_token(req: TokenRequest, principal: OwnerUser) -> dict:
    """Export tokens are read-only by design — a leaked read token is a far
    smaller incident than a leaked write token."""
    try:
        plaintext, record = ex.issue_api_token(frozenset(req.scopes))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {
        "token": plaintext,
        "prefix": record.prefix,
        "scopes": sorted(s.value for s in record.scopes),
        "note": "Shown once. Only a hash is stored.",
    }


@router.get("/export/scopes")
async def export_scopes(principal: CurrentUser) -> dict:
    return {"scopes": sorted(s.value for s in ex.ALL_SCOPES)}
