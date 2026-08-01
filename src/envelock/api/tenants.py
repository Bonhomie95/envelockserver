"""Tenant, mailbox, alert and counterparty endpoints — the dashboard's data.

Everything here is persisted, tenant-scoped, and checked against the caller's
tenant on every access. Tenant isolation is verified, never assumed.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import ActiveUser, AdminUser, CurrentUser, OwnerUser
from envelock.auth.email_policy import is_disposable_email
from envelock.auth.security import (
    Role,
    dummy_hash,
    hash_password,
    verify_password,
    verify_totp,
)
from envelock.billing.pricing import Plan, included_mailbox_seats
from envelock.channels.mail.ingest import ingest_address, new_ingest_token, onboarding_instructions
from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import IntegrationTier, MailboxClass, SourceMechanism
from envelock.db import get_session
from envelock.detections.base import inactive_for
from envelock.models import (
    Alert,
    AuditEvent,
    BankRecord,
    Counterparty,
    Domain,
    Finding,
    Invoice,
    LookalikeDomain,
    Mailbox,
    MailboxCredential,
    Message,
    NotificationDelivery,
    PushSubscription,
    SenderProfile,
    SensorSession,
    Tenant,
    UsageMeter,
    User,
)
from envelock.platform import alerts as alert_svc
from envelock.platform import graph_store
from envelock.platform.graph import GRAPH, RiskProfile, Verdict
from envelock.platform.remediation import (
    RemediationAction,
    plan_remediation,
)
from envelock.security.crypto import seal
from envelock.security.limits import valid_domain
from envelock.util.domains import registrable_domain

router = APIRouter(prefix="/api/v1", tags=["tenant"])

Session = Annotated[AsyncSession, Depends(get_session)]

#: Sources that mean a mailbox's MAIL is actually being ingested (vs identity-only
#: signals). Used to tell "connected" from "unconnected".
_MAIL_SOURCES = frozenset(
    {"graph_api", "gmail_api", "admin_api", "imap_idle", "imap_poll", "forward_ingest", "journal"}
)


async def _tenant_or_404(session: AsyncSession, tenant_id: UUID) -> Tenant:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    return tenant


def _mailbox_entitled(tenant: Tenant) -> bool:
    """Content mailboxes (Channel 1/2) need a paid plan or an active trial. Guard
    is Channel-3-only and free — it protects domains, not mailboxes (PRD §12.3),
    so a lapsed-trial tenant on Guard cannot keep adding protected seats."""
    ends = tenant.trial_ends_at
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_active = bool(ends and ends > datetime.now(UTC))
    return trial_active or tenant.payment_method_ok


def _require_mailbox_entitlement(tenant: Tenant) -> None:
    if not _mailbox_entitled(tenant):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "add a payment method or upgrade to Essential or Complete to protect "
            "mailboxes — domain and brand monitoring stay free on Guard",
        )


def _effective_plan(tenant: Tenant) -> str:
    """Guard once the trial has lapsed unpaid, else the subscribed plan (matches
    what `current_tenant` reports to the dashboard)."""
    return tenant.plan if _mailbox_entitled(tenant) else Plan.GUARD.value


def _mailbox_capacity(tenant: Tenant) -> int:
    """How many mailboxes this tenant may protect right now: the plan's included
    seats plus any purchased, or 0 on Guard (no mailboxes without a paid plan/trial).

    During the trial the tenant sits on the top plan, so the allowance is COMPLETE's
    (7). A paid Essential tenant gets 5. Extra purchased seats add on top."""
    plan = _effective_plan(tenant)
    if plan == Plan.GUARD.value:
        return 0
    return included_mailbox_seats(plan) + max(0, tenant.extra_mailbox_seats or 0)


async def _mailbox_count(session: AsyncSession, tenant_id: UUID) -> int:
    return int(
        (
            await session.execute(
                select(func.count()).select_from(Mailbox).where(Mailbox.tenant_id == tenant_id)
            )
        ).scalar_one()
    )


async def _require_mailbox_capacity(
    session: AsyncSession, tenant: Tenant, *, adding: int = 1
) -> None:
    """Enforce the plan's mailbox seat cap so a trial or paid tenant can't protect
    more mailboxes than they're entitled to. Over the cap → 402, and the client
    routes the admin to upgrade or buy more seats before anything connects."""
    _require_mailbox_entitlement(tenant)  # Guard / lapsed-unpaid can't add at all.
    cap = _mailbox_capacity(tenant)
    used = await _mailbox_count(session, tenant.id)
    if used + adding > cap:
        plan = _effective_plan(tenant)
        need = used + adding - cap
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"your {plan.capitalize()} plan covers {cap} mailbox"
            f"{'' if cap == 1 else 'es'} and {used} are in use. "
            f"Buy {need} more seat{'' if need == 1 else 's'} (or upgrade) before "
            "adding another mailbox.",
        )


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

    # Validate the shape *before* deriving the registrable domain: a company
    # name like "Acme Corp" reduces to "acme corp", which is truthy but not a
    # domain. Storing it would silently break every domain-based lookup (MX,
    # DMARC, Certificate Transparency, lookalikes) and the ingest token for the
    # whole tenant, with no error anywhere.
    if not valid_domain(req.domain):
        raise HTTPException(422, "enter a valid domain, e.g. yourcompany.com")
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


@router.get("/tenant")
async def current_tenant(principal: CurrentUser, session: Session) -> dict:
    """The signed-in user's tenant — its name, plan and registered domains.

    The dashboard shows this instead of guessing the domain from a mailbox, so a
    tenant with no mailbox connected yet still displays who they are."""
    tenant = await session.get(Tenant, principal.tenant_id)
    domains = (
        (
            await session.execute(
                select(Domain)
                .where(Domain.tenant_id == principal.tenant_id)
                .order_by(Domain.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    ends = tenant.trial_ends_at if tenant else None
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_days_left = (
        max(0, (ends - now).days + (1 if (ends - now).seconds else 0))
        if ends
        else None
    )
    trial_active = bool(ends and ends > now)
    paid = tenant.payment_method_ok if tenant else False
    subscribed_plan = tenant.plan if tenant else "guard"
    # Entitlement is the trial plan while the trial runs (or once a card is on
    # file); when the trial lapses unpaid, the tenant is relegated to Guard (free)
    # rather than losing access entirely (PRD §12.3 — Guard is free forever).
    effective_plan = subscribed_plan if (trial_active or paid) else "guard"
    mailbox_used = await _mailbox_count(session, principal.tenant_id) if tenant else 0
    mailbox_capacity = _mailbox_capacity(tenant) if tenant else 0
    return {
        "tenant_id": str(principal.tenant_id),
        "name": tenant.name if tenant else None,
        "plan": effective_plan,
        "subscribed_plan": subscribed_plan,
        "trial_ended": bool(ends and not trial_active and not paid),
        "mailboxes": {
            "used": mailbox_used,
            "capacity": mailbox_capacity,
            "included": included_mailbox_seats(effective_plan),
            "extra_seats": tenant.extra_mailbox_seats if tenant else 0,
            "can_add": mailbox_used < mailbox_capacity,
        },
        "trial": {
            "started_at": tenant.trial_started_at.isoformat()
            if tenant and tenant.trial_started_at
            else None,
            "ends_at": ends.isoformat() if ends else None,
            "days_left": trial_days_left,
            "active": bool(ends and ends > now),
            "payment_method_ok": tenant.payment_method_ok if tenant else False,
        },
        "domains": [
            {
                "name": d.name,
                "registrable_domain": d.registrable_domain,
                "verified": d.verified_at is not None,
                "is_defensive": d.is_defensive,
            }
            for d in domains
        ],
        "primary_domain": domains[0].registrable_domain if domains else None,
    }


_SELECTABLE_PLANS = {"guard", "essential", "complete", "solo"}


class ChangePlanRequest(BaseModel):
    plan: str = Field(description="Target subscribed plan")


@router.post("/tenant/plan")
async def change_plan(
    req: ChangePlanRequest, principal: OwnerUser, session: Session
) -> dict:
    """Change the tenant's subscribed plan (upgrade/downgrade).

    Only the owner can change what the company pays for. Moving to any paid tier
    requires either an active trial or a payment method on file — otherwise we'd
    be handing out paid protection for free. Downgrading to Guard (free) is always
    allowed. Real card capture happens in the billing/confirm flow; this records
    the *chosen* plan, which `current_tenant` then resolves into the effective
    entitlement (Guard once a trial lapses unpaid).
    """
    target = req.plan.strip().lower()
    if target not in _SELECTABLE_PLANS:
        raise HTTPException(422, f"unknown plan: {req.plan}")

    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    now = datetime.now(UTC)
    ends = tenant.trial_ends_at
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_active = bool(ends and ends > now)

    is_paid_target = target not in ("guard",)
    if is_paid_target and not (trial_active or tenant.payment_method_ok):
        raise HTTPException(
            402,
            "add a payment method to move to a paid plan — your trial has ended",
        )

    tenant.plan = target
    await session.commit()

    subscribed_plan = tenant.plan
    effective_plan = subscribed_plan if (trial_active or tenant.payment_method_ok) else "guard"
    return {
        "subscribed_plan": subscribed_plan,
        "plan": effective_plan,
        "payment_method_ok": tenant.payment_method_ok,
        "trial_active": trial_active,
    }


class DeleteTenantRequest(BaseModel):
    password: str = Field(max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


@router.delete("/tenant")
async def delete_tenant(
    req: DeleteTenantRequest, principal: OwnerUser, session: Session
) -> dict:
    """Full account deletion (PRD §15.2). Confirmed with the current password (and
    a TOTP code when MFA is on), then removes the tenant and every row scoped to
    it — mailboxes, credentials, messages, alerts, the audit trail, users.

    The **domain trial ledger is deliberately kept** (PRD §12.7): its permanence is
    the anti-abuse mechanism. So an owner who deletes their account after using the
    trial and later returns gets no fresh trial — they subscribe from the start.
    """
    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not verify_password(req.password, user.password_hash or dummy_hash()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "password is incorrect")
    if user.mfa_enabled and (
        not req.mfa_code or not verify_totp(user.totp_secret or "", req.mfa_code)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authenticator code is incorrect")

    tid = principal.tenant_id
    # Children before parents. DomainTrialLedger is intentionally NOT in this list.
    for stmt in (
        delete(Finding).where(Finding.tenant_id == tid),
        delete(NotificationDelivery).where(NotificationDelivery.tenant_id == tid),
        delete(BankRecord).where(BankRecord.tenant_id == tid),
        delete(SenderProfile).where(SenderProfile.tenant_id == tid),
        delete(Message).where(Message.tenant_id == tid),
        delete(SensorSession).where(SensorSession.tenant_id == tid),
        delete(MailboxCredential).where(MailboxCredential.tenant_id == tid),
        delete(Alert).where(Alert.tenant_id == tid),
        delete(Counterparty).where(Counterparty.tenant_id == tid),
        delete(Mailbox).where(Mailbox.tenant_id == tid),
        delete(LookalikeDomain).where(LookalikeDomain.tenant_id == tid),
        delete(PushSubscription).where(PushSubscription.tenant_id == tid),
        delete(UsageMeter).where(UsageMeter.tenant_id == tid),
        delete(Invoice).where(Invoice.tenant_id == tid),
        delete(Domain).where(Domain.tenant_id == tid),
        delete(AuditEvent).where(AuditEvent.tenant_id == tid),
        delete(User).where(User.tenant_id == tid),
        delete(Tenant).where(Tenant.id == tid),
    ):
        await session.execute(stmt)
    await session.commit()
    return {"deleted": True, "domain_ledger_retained": True}


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
    tenant = await _tenant_or_404(session, principal.tenant_id)
    # Don't charge a seat for a mailbox we already have (idempotent re-add).
    existing = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                func.lower(Mailbox.address) == req.address.lower(),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _mailbox_payload(existing)  # idempotent — no new seat charged
    await _require_mailbox_capacity(session, tenant, adding=1)
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
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address, "event": "added"},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


class BulkMailboxRequest(BaseModel):
    #: Paste a whole team at once — one call instead of adding 50 people by hand.
    addresses: list[str] = Field(min_length=1, max_length=1000)
    mailbox_class: MailboxClass = MailboxClass.MONITORED


@router.post("/mailboxes/bulk", status_code=201)
async def add_mailboxes_bulk(
    req: BulkMailboxRequest, principal: AdminUser, session: Session
) -> dict:
    """Add many mailboxes in one request — the path for a whole finance team or a
    50-seat domain, instead of adding each address by hand. Idempotent: addresses
    that already exist (or repeat within the paste) are skipped, not duplicated."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    _require_mailbox_entitlement(tenant)

    existing = {
        addr.lower()
        for (addr,) in (
            await session.execute(
                select(Mailbox.address).where(Mailbox.tenant_id == principal.tenant_id)
            )
        ).all()
    }
    caps = capabilities_for(frozenset())  # no source yet — added, then connected
    level = protection_level(caps).value
    inactive = inactive_for(caps)

    # Only add up to the plan's remaining seats; the rest are reported so the admin
    # can buy more seats rather than silently getting free protection.
    remaining = max(0, _mailbox_capacity(tenant) - len(existing))

    created: list[Mailbox] = []
    skipped: list[dict] = []
    over_limit = 0
    seen: set[str] = set()
    for raw in req.addresses:
        addr = raw.strip().lower()
        if not addr:
            continue
        if "@" not in addr or "." not in addr.split("@")[-1]:
            skipped.append({"address": raw.strip(), "reason": "not a valid email address"})
            continue
        if addr in existing or addr in seen:
            skipped.append({"address": addr, "reason": "already added"})
            continue
        if remaining <= 0:
            over_limit += 1
            skipped.append({"address": addr, "reason": "no seat available — buy more seats"})
            continue
        remaining -= 1
        seen.add(addr)
        mailbox = Mailbox(
            tenant_id=principal.tenant_id,
            address=addr,
            mailbox_class=req.mailbox_class.value,
            sources=[],
            protection_level=level,
            inactive_detections=inactive,
        )
        session.add(mailbox)
        created.append(mailbox)

    if created:
        await alert_svc.record_audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=alert_svc.AuditAction.MAILBOX_CONNECTED,
            target_type="mailbox",
            detail={"bulk_added": len(created), "class": req.mailbox_class.value},
        )
    await session.commit()
    return {
        "created": [_mailbox_payload(m) for m in created],
        "skipped": skipped,
        "created_count": len(created),
        "skipped_count": len(skipped),
        # >0 means the paste exceeded the plan's seats — the client prompts to buy.
        "over_limit_count": over_limit,
        "capacity": _mailbox_capacity(tenant),
    }


async def _member_mailbox_ids(session: AsyncSession, actor) -> list[UUID]:  # noqa: ANN001
    """The mailbox ids a member may see — the ones addressed to them. Empty if
    they own none. Admins/owners are never restricted (caller checks is_member)."""
    rows = await session.execute(
        select(Mailbox.id).where(
            Mailbox.tenant_id == actor.tenant_id, Mailbox.address == actor.email
        )
    )
    return [mid for (mid,) in rows.all()]


@router.get("/mailboxes")
async def list_mailboxes(actor: ActiveUser, session: Session) -> dict:
    query = select(Mailbox).where(Mailbox.tenant_id == actor.tenant_id)
    # A member sees only their own mailbox (PRD §15.1); admins see the domain.
    if actor.is_member:
        query = query.where(Mailbox.address == actor.email)
    rows = (await session.execute(query)).scalars().all()
    return {"mailboxes": [_mailbox_payload(m) for m in rows]}


async def _mailbox_or_404(session: AsyncSession, mailbox_id: UUID, tenant_id: UUID) -> Mailbox:
    mailbox = await session.get(Mailbox, mailbox_id)
    if mailbox is None or mailbox.tenant_id != tenant_id:
        raise HTTPException(404, "mailbox not found")
    return mailbox


class ImapConnectRequest(BaseModel):
    imap_host: str = Field(min_length=3, max_length=253)
    imap_port: int = Field(default=993, ge=1, le=65535)
    #: Transport security — we don't assume 993/implicit-TLS, since many ISP servers
    #: use STARTTLS on 143. "ssl" | "starttls" | "none".
    security: Literal["ssl", "starttls", "none"] = "ssl"
    #: Login username, when it isn't the mailbox address (some providers).
    username: str | None = Field(default=None, max_length=320)
    #: The mailbox password, or (preferred) an app-specific password. Sealed with
    #: envelope encryption and never returned or logged (PRD §5.2).
    password: str = Field(min_length=1, max_length=1024)


@router.post("/mailboxes/{mailbox_id}/connect/imap")
async def connect_imap(
    mailbox_id: UUID, req: ImapConnectRequest, principal: AdminUser, session: Session
) -> dict:
    """Connect a mailbox over IMAP by storing its credentials, envelope-encrypted.

    This is the path for any provider without OAuth — most ISP and custom-domain
    mail. Protected mailboxes hold an IDLE connection (quarantine latency is the
    product); Monitored mailboxes poll (PRD §12.11D)."""
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)

    # Prove the credentials work before storing them. Reporting "connected" on a
    # wrong password (then silently ingesting nothing) is worse than an error.
    from envelock.channels.mail import broker

    host = req.imap_host.strip().lower()
    login_user = (req.username or mailbox.address).strip()
    check = await broker.verify_imap_credentials(
        host=host,
        port=req.imap_port,
        username=login_user,
        password=req.password,
        security=req.security,
    )
    if not check.ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"could not connect — {check.reason}")

    sealed = seal(req.password.encode(), aad=str(mailbox.id).encode())
    existing = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=principal.tenant_id,
                kind="imap_password",
                imap_host=host,
                imap_port=req.imap_port,
                imap_security=req.security,
                imap_username=req.username.strip() if req.username else None,
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
    else:
        existing.kind = "imap_password"
        existing.imap_host = host
        existing.imap_port = req.imap_port
        existing.imap_security = req.security
        existing.imap_username = req.username.strip() if req.username else None
        existing.ciphertext = sealed.ciphertext
        existing.wrapped_dek = sealed.wrapped_dek
        existing.key_id = sealed.key_id

    # Protected → IDLE (real-time, can quarantine); Monitored → poll.
    source = (
        SourceMechanism.IMAP_IDLE
        if mailbox.mailbox_class == MailboxClass.PROTECTED.value
        else SourceMechanism.IMAP_POLL
    )
    mailbox.sources = sorted(set(mailbox.sources or []) | {source.value})
    mailbox.integration_tier = int(IntegrationTier.IMAP)
    caps = capabilities_for(frozenset(SourceMechanism(s) for s in mailbox.sources))
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)

    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address, "method": "imap", "host": req.imap_host},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


@router.post("/mailboxes/{mailbox_id}/connect/forward")
async def connect_forward(
    mailbox_id: UUID, principal: AdminUser, session: Session
) -> dict:
    """Mark a mailbox as connected by mail forwarding.

    The customer has set a forwarding rule to their ingest address; this records
    it so the mailbox reads as covered. Forwarding arrives *post-delivery*, so it
    is alert-only — it can never quarantine (PRD §4 fn.3) — which is why the
    protection level lands at Limited. That is the honest ceiling of this path,
    not a bug.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    mailbox.sources = sorted(
        set(mailbox.sources or []) | {SourceMechanism.FORWARD_INGEST.value}
    )
    mailbox.integration_tier = int(IntegrationTier.FORWARDING)
    mailbox.last_sync_at = datetime.now(UTC)
    caps = capabilities_for(frozenset(SourceMechanism(s) for s in mailbox.sources))
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)

    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address, "method": "forwarding"},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


@router.get("/mailboxes/{mailbox_id}/activity")
async def mailbox_activity(
    mailbox_id: UUID, actor: ActiveUser, session: Session
) -> dict:
    """What has actually happened on this mailbox — so IT can see it is protected,
    not just wait for an alert. Connection events, coverage, and running counts of
    messages scanned and alerts raised."""
    mailbox = await _mailbox_or_404(session, mailbox_id, actor.tenant_id)
    if actor.is_member and mailbox.address != actor.email:
        raise HTTPException(404, "mailbox not found")

    events = (
        (
            await session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == actor.tenant_id,
                    AuditEvent.target_id == mailbox.id,
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    messages_scanned = (
        await session.execute(
            select(func.count()).select_from(Message).where(Message.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    alerts_raised = (
        await session.execute(
            select(func.count()).select_from(Alert).where(Alert.mailbox_id == mailbox.id)
        )
    ).scalar_one()

    caps = capabilities_for(
        frozenset(SourceMechanism(s) for s in (mailbox.sources or []) if s)
    )
    connected = any(s in _MAIL_SOURCES for s in (mailbox.sources or []))
    return {
        "address": mailbox.address,
        "connected": connected,
        "protection_level": protection_level(caps).value,
        "sources": mailbox.sources or [],
        "inactive_detections": inactive_for(caps),
        "last_sync_at": mailbox.last_sync_at.isoformat() if mailbox.last_sync_at else None,
        "messages_scanned": messages_scanned,
        "alerts_raised": alerts_raised,
        "events": [
            {"action": e.action, "at": e.created_at.isoformat(), "detail": e.detail}
            for e in events
        ],
    }


@router.delete("/mailboxes/{mailbox_id}")
async def remove_mailbox(
    mailbox_id: UUID, principal: AdminUser, session: Session
) -> dict:
    """Disconnect and remove a mailbox and everything that hangs off it.

    A mailbox is the parent of messages, findings, sensor sessions and its stored
    credential; deleting it while those rows exist violates their foreign keys and
    500s (the reported bug). We remove them in FK-safe order — children first —
    and deliberately *keep* alerts as the customer's incident record, detaching
    them from the mailbox rather than deleting the history.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    address = mailbox.address
    mid = mailbox.id

    # Findings reference messages and alerts, so they go first. Catch both the
    # ones tagged with this mailbox and any tied to its messages.
    msg_ids = select(Message.id).where(Message.mailbox_id == mid)
    await session.execute(
        delete(Finding).where(
            or_(Finding.mailbox_id == mid, Finding.message_id.in_(msg_ids))
        )
    )
    await session.execute(delete(Message).where(Message.mailbox_id == mid))
    await session.execute(delete(SensorSession).where(SensorSession.mailbox_id == mid))
    await session.execute(delete(MailboxCredential).where(MailboxCredential.mailbox_id == mid))
    # Preserve the incident record — detach alerts instead of deleting them.
    await session.execute(
        update(Alert).where(Alert.mailbox_id == mid).values(mailbox_id=None)
    )
    await session.delete(mailbox)
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="mailbox.removed",
        target_type="mailbox",
        detail={"address": address},
    )
    await session.commit()
    return {"removed": True, "address": address}


# ── Team / membership (PRD §15.1) ────────────────────────────────────────────
async def _seat_usage(session: AsyncSession, tenant: Tenant) -> dict:
    """Guard (free) is owner-only. On a trial or paid plan, team logins (everyone
    except the owner) are capped at the number of protected mailboxes — one login
    per protected seat."""
    protected = (
        await session.execute(
            select(func.count())
            .select_from(Mailbox)
            .where(
                Mailbox.tenant_id == tenant.id,
                Mailbox.mailbox_class == MailboxClass.PROTECTED.value,
            )
        )
    ).scalar_one()
    # A seat is consumed by an ACTIVE login. Pending join-requests don't burn a
    # paid seat — the seat is spent only when an admin actually grants access.
    team_used = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.tenant_id == tenant.id,
                User.role != Role.OWNER.value,
                User.status == "active",
            )
        )
    ).scalar_one()
    entitled = _mailbox_entitled(tenant)
    cap = protected if entitled else 0
    return {"used": team_used, "cap": cap, "entitled": entitled, "protected_mailboxes": protected}


async def _is_protected_mailbox(session: AsyncSession, tenant_id: UUID, email: str) -> bool:
    """Is this address one of the tenant's protected mailboxes — i.e. someone they
    are actually paying to protect?"""
    return bool(
        (
            await session.execute(
                select(func.count())
                .select_from(Mailbox)
                .where(
                    Mailbox.tenant_id == tenant_id,
                    func.lower(Mailbox.address) == email.lower(),
                    Mailbox.mailbox_class == MailboxClass.PROTECTED.value,
                )
            )
        ).scalar_one()
    )


async def _assert_can_grant_login(
    session: AsyncSession, tenant: Tenant, *, email: str, role: str
) -> None:
    """Gate for granting a team login — used on both create and approve.

    Three independent limits, so an admin can only give access to their own
    company's people, and only those the company is paying for:
      0. **Company domain** — the email must be on one of the tenant's registered
         domains. An admin can never create a login for an outside address.
      1. **Seats** — active logins can't exceed the number of protected mailboxes.
      2. **Protection pool** — a *member* login must be one of those protected
         mailboxes. (Admins are the company's own overseers and only the owner can
         mint them, so they're exempt from the pool check but still cost a seat.)
    """
    # 0. Must be on one of the company's own domains.
    reg = registrable_domain(email.rsplit("@", 1)[-1] if "@" in email else "")
    domains = {
        d
        for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(Domain.tenant_id == tenant.id)
            )
        ).all()
    }
    if domains and reg not in domains:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{email} isn't on your company's domain "
            f"({', '.join(sorted(domains))}). Team logins must use a company address.",
        )

    seats = await _seat_usage(session, tenant)
    if not seats["entitled"]:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "team logins need an active trial or paid plan — Guard is owner-only",
        )
    if seats["used"] >= seats["cap"]:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"all {seats['cap']} paid seat{'' if seats['cap'] == 1 else 's'} are in "
            "use — add a protected mailbox to open another login",
        )
    if role == Role.MEMBER.value and not await _is_protected_mailbox(
        session, tenant.id, email
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{email} isn't a protected mailbox in your account. Add it as a "
            "protected mailbox first — team logins are only for people you are "
            "paying to protect.",
        )


class CreateMemberRequest(BaseModel):
    email: EmailStr
    role: Literal["member", "admin"] = "member"


@router.post("/members", status_code=201)
async def create_member(
    req: CreateMemberRequest, principal: AdminUser, session: Session
) -> dict:
    """Owner-provisioned access (PRD §15.1). The owner (or an admin) creates a
    teammate and hands them a one-time temporary password; they must set their own
    on first sign-in. Seat-limited by plan — see `_seat_usage`."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    if req.role == "admin" and principal.role is not Role.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the owner can create admins")

    email = req.email.lower().strip()
    if is_disposable_email(email):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "disposable email addresses are not allowed",
        )
    if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "a user with this email already exists")

    await _assert_can_grant_login(session, tenant, email=email, role=req.role)

    temp_password = secrets.token_urlsafe(12)
    user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password(temp_password),
        role=req.role,
        is_admin=req.role == "admin",
        status="active",
        must_change_password=True,
    )
    session.add(user)
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=tenant.id,
        actor_id=principal.user_id,
        action="member.created",
        target_type="user",
        target_id=user.id,
        detail={"email": email, "role": req.role},
    )
    await session.commit()
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "temporary_password": temp_password,
        "note": "Share this once, in person or over a trusted channel. They must "
        "change it at first sign-in.",
    }


@router.get("/members")
async def list_members(principal: AdminUser, session: Session) -> dict:
    """Admins see everyone in the tenant, including colleagues awaiting approval,
    plus how many team seats the plan allows."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    rows = (
        (
            await session.execute(
                select(User).where(User.tenant_id == principal.tenant_id).order_by(
                    User.created_at.asc()
                )
            )
        )
        .scalars()
        .all()
    )
    return {
        "members": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "pending_password": u.must_change_password,
                "is_self": u.id == principal.user_id,
            }
            for u in rows
        ],
        "seats": await _seat_usage(session, tenant),
    }


async def _member_or_404(session: AsyncSession, user_id: UUID, tenant_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise HTTPException(404, "member not found")
    return user


@router.post("/members/{user_id}/approve")
async def approve_member(user_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Grant a pending colleague access to the workspace.

    Approval is the moment a seat is actually spent, so the same limits as
    creating a login apply here — otherwise self-registration would be a way
    around the seat cap and the protection pool."""
    user = await _member_or_404(session, user_id, principal.tenant_id)
    tenant = await _tenant_or_404(session, principal.tenant_id)
    await _assert_can_grant_login(session, tenant, email=user.email, role=user.role)
    user.status = "active"
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="member.approved",
        target_type="user",
        target_id=user.id,
        detail={"email": user.email},
    )
    await session.commit()
    return {"id": str(user.id), "email": user.email, "status": user.status}


@router.post("/members/{user_id}/reject")
async def reject_member(user_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Remove a member (or decline a pending request). The owner cannot be removed
    and an admin cannot remove themselves."""
    user = await _member_or_404(session, user_id, principal.tenant_id)
    if user.id == principal.user_id:
        raise HTTPException(400, "you cannot remove yourself")
    if user.role == "owner":
        raise HTTPException(400, "the owner cannot be removed")
    email = user.email
    await session.delete(user)
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="member.removed",
        target_type="user",
        detail={"email": email},
    )
    await session.commit()
    return {"removed": True, "email": email}


# ── Alerts ───────────────────────────────────────────────────────────────────
def _alert_payload(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "tier": a.tier,
        "title": a.title,
        "body": a.body,
        "state": a.state,
        "mailbox_id": str(a.mailbox_id) if a.mailbox_id else None,
        "counterparty_domain": a.counterparty_domain,
        "requires_callback": a.requires_callback,
        "callback_phone": a.callback_phone,
        "created_at": a.created_at.isoformat(),
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "escalated_at": a.escalated_at.isoformat() if a.escalated_at else None,
    }


async def _assert_alert_access(session: AsyncSession, actor, alert: Alert) -> None:
    """A member may only touch alerts on their own mailbox (PRD §15.1). Return a
    404 (not 403) for out-of-scope alerts so membership isn't an oracle."""
    if not actor.is_member:
        return
    own = await _member_mailbox_ids(session, actor)
    if alert.mailbox_id not in own:
        raise HTTPException(404, "alert not found")


@router.get("/alerts")
async def list_alerts(
    actor: ActiveUser, session: Session, state: str | None = None, limit: int = 100
) -> dict:
    query = select(Alert).where(Alert.tenant_id == actor.tenant_id)
    if actor.is_member:
        own = await _member_mailbox_ids(session, actor)
        if not own:
            return {"alerts": [], "count": 0}
        query = query.where(Alert.mailbox_id.in_(own))
    if state:
        query = query.where(Alert.state == state)
    rows = (
        (await session.execute(query.order_by(Alert.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return {"alerts": [_alert_payload(a) for a in rows], "count": len(rows)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    existing = await session.get(Alert, alert_id)
    if existing is None or existing.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, existing)
    alert = await alert_svc.acknowledge(
        session, alert_id=alert_id, tenant_id=actor.tenant_id, actor_id=actor.user_id
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: UUID, actor: ActiveUser, session: Session, dismiss: bool = False
) -> dict:
    existing = await session.get(Alert, alert_id)
    if existing is None or existing.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, existing)
    alert = await alert_svc.resolve(
        session,
        alert_id=alert_id,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        dismissed=dismiss,
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/quarantine")
async def quarantine(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    """E2. Refuses honestly on forwarding-connected mailboxes."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, alert)

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
            tenant_id=actor.tenant_id,
            actor_id=actor.user_id,
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
    steps = await alert_svc.due_escalations(session, tenant_id=principal.tenant_id)
    return {
        "due": [
            {
                "alert_id": str(step.alert_id),
                "to": step.to,
                "minutes_open": step.minutes_open,
                "tier": step.tier.value,
            }
            for step in steps
        ],
        "count": len(steps),
    }


@router.post("/escalations/run")
async def run_escalations(principal: AdminUser, session: Session) -> dict:
    """Run the E6 escalation cycle for this tenant now: mark unacknowledged
    Criticals escalated to IT, and fire the paid SMS rung only where the ladder
    allows. An ops scheduler calls the same code path tenant-wide."""
    from envelock.notify.dispatch import run_escalation_cycle

    done = await run_escalation_cycle(session, tenant_id=principal.tenant_id)
    await session.commit()
    return {"escalated": done, "count": len(done)}


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
