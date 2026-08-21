"""Is this deployment actually secure? — answered from the running system.

A security product has to be able to answer that about itself, and not from a
document. Every check here reads live configuration or live data, names what is
wrong in a sentence, and says what to do about it. It is the page a security
operator opens first, and the evidence a compliance reviewer asks for.

Nothing here returns a secret: checks report *whether* a key is configured and
what custody it has, never the material.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.api.staff_auth import requires
from envelock.auth.staff import Operator, Permission
from envelock.db import get_session
from envelock.models import Domain, Mailbox, StaffAccount, User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
Session = Annotated[AsyncSession, Depends(get_session)]
SecurityReader = Annotated[Operator, Depends(requires(Permission.SECURITY_READ))]


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    title: str
    #: pass | warn | fail
    state: str
    detail: str
    remedy: str = ""
    #: Ordering weight for the console — the things that would hurt most, first.
    severity: str = "medium"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "state": self.state,
            "detail": self.detail,
            "remedy": self.remedy,
            "severity": self.severity,
        }


def _config_checks() -> list[Check]:
    from envelock.config import get_settings
    from envelock.security.keys import custody_summary

    settings = get_settings()
    checks: list[Check] = []

    # 1. Credential key custody — the single highest-consequence control we have.
    custody = custody_summary()
    if not custody.get("ok"):
        checks.append(
            Check(
                "key_custody",
                "Credential key custody",
                "fail",
                f"No usable credential key provider: {custody.get('error')}. "
                "Mailbox passwords cannot be sealed.",
                "Generate a key pair with `python -m envelock.security.keygen` "
                "and set it on both deployments.",
                "critical",
            )
        )
    elif custody["mode"] == "local":
        checks.append(
            Check(
                "key_custody",
                "Credential key custody",
                "fail" if settings.is_production else "warn",
                "Mailbox passwords are wrapped with a key held in an environment "
                "variable, readable by every process that has it — including the "
                "web process. This is the development mode.",
                "Move to `x25519` (public key on the API, private key on the "
                "worker) or a cloud KMS, then run "
                "`python -m envelock.security.rotate_credentials --migrate`.",
                "critical",
            )
        )
    elif custody.get("separated"):
        checks.append(
            Check(
                "key_custody",
                "Credential key custody",
                "pass",
                f"{custody['mode']} — this process can seal a credential and "
                "cannot read one. Decryption happens only in the worker.",
                severity="critical",
            )
        )
    else:
        checks.append(
            Check(
                "key_custody",
                "Credential key custody",
                "warn",
                f"{custody['mode']} — this process holds a key that can decrypt "
                "stored credentials. Correct for the worker; a risk if this is "
                "the internet-facing API.",
                "Deploy the API with the public key only "
                "(ENVELOCK_CREDENTIAL_PRIVATE_KEY unset).",
                "critical",
            )
        )

    # 2. Database-level tenant isolation.
    checks.append(
        Check(
            "rls",
            "Database row-level security",
            "pass" if settings.rls_enabled else "warn",
            "Postgres enforces tenant isolation on every query."
            if settings.rls_enabled
            else "Tenant isolation rests entirely on application code remembering "
            "a WHERE tenant_id on every query. One missed filter leaks another "
            "company's data.",
            "" if settings.rls_enabled else "Apply the RLS migration, provision "
            "the envelock_app role, then set ENVELOCK_RLS_ENABLED=true.",
            "high",
        )
    )

    # 3. Mailbox domain-ownership gate.
    checks.append(
        Check(
            "domain_verification",
            "Domain-control verification",
            "pass" if settings.require_domain_verification else "fail",
            "A tenant must prove DNS control of a domain before connecting a "
            "mailbox on it."
            if settings.require_domain_verification
            else "Anyone can add a mailbox on a domain they do not own and "
            "receive that company's mail alerts.",
            "" if settings.require_domain_verification
            else "Set ENVELOCK_REQUIRE_DOMAIN_VERIFICATION=true.",
            "high",
        )
    )

    # 4. Provider push authentication.
    checks.append(
        Check(
            "webhook_secret",
            "Provider webhook authentication",
            "pass",
            "Graph notifications carry a signed clientState and Gmail push "
            "carries our token; forged pushes are rejected."
            + (
                ""
                if settings.webhook_shared_secret
                else " (Derived from ENVELOCK_SECRET_KEY — rotating that secret "
                "invalidates existing Graph subscriptions.)"
            ),
            ""
            if settings.webhook_shared_secret
            else "Set ENVELOCK_WEBHOOK_SHARED_SECRET so provider subscriptions "
            "survive an app-secret rotation.",
            "medium",
        )
    )

    # 5. Forwarded-mail ingest pinning.
    checks.append(
        Check(
            "ingest_allowlist",
            "Forwarded-mail ingest source pinning",
            "pass" if settings.ingest_allowed_ips.strip() else "warn",
            "Only allow-listed forwarders may submit mail."
            if settings.ingest_allowed_ips.strip()
            else "Any source that learns a tenant's ingest token can inject mail "
            "into that tenant's pipeline.",
            "" if settings.ingest_allowed_ips.strip()
            else "Set ENVELOCK_INGEST_ALLOWED_IPS to your gateway's egress ranges.",
            "medium",
        )
    )

    # 6. Proxy header trust.
    checks.append(
        Check(
            "forwarded_for",
            "Client-IP trust",
            "pass",
            "X-Forwarded-For is trusted — correct only behind a proxy you control."
            if settings.trust_forwarded_for
            else "X-Forwarded-For is not trusted, so rate limits cannot be "
            "bypassed with a spoofed header.",
            "Behind a load balancer, enable ENVELOCK_TRUST_FORWARDED_FOR — "
            "otherwise every client shares the proxy's IP and limits apply "
            "globally." if not settings.trust_forwarded_for else "",
            "low",
        )
    )

    # 7. Transport security in production.
    checks.append(
        Check(
            "production_mode",
            "Production hardening",
            "pass" if settings.is_production else "warn",
            "HSTS is set, API docs are disabled, and startup refuses missing "
            "secrets."
            if settings.is_production
            else f"Running as env={settings.env}: HSTS is off and /docs is "
            "exposed. Correct for development, never for a live deployment.",
            "" if settings.is_production else "Set ENVELOCK_ENV=production.",
            "high",
        )
    )

    # 8. Outbound alert delivery — a security control that fails silently.
    smtp_ok = bool(settings.smtp_host and settings.smtp_host != "localhost")
    checks.append(
        Check(
            "alert_delivery",
            "Outbound alert delivery",
            "pass" if smtp_ok else "fail",
            "Email alerts have a configured relay."
            if smtp_ok
            else "No SMTP relay is configured, so Critical alerts — and password "
            "reset links — never leave the system.",
            "" if smtp_ok else "Set ENVELOCK_SMTP_HOST and the DKIM key.",
            "high",
        )
    )

    return checks


async def _data_checks(session: AsyncSession) -> list[Check]:
    checks: list[Check] = []

    async def _count(stmt) -> int:  # noqa: ANN001
        return int((await session.execute(stmt)).scalar_one())

    # Staff MFA coverage — these credentials reach every tenant's metadata.
    staff_total = await _count(
        select(func.count()).select_from(StaffAccount).where(StaffAccount.status == "active")
    )
    staff_no_mfa = await _count(
        select(func.count())
        .select_from(StaffAccount)
        .where(StaffAccount.status == "active", StaffAccount.mfa_enabled.is_(False))
    )
    checks.append(
        Check(
            "staff_mfa",
            "Operator two-factor coverage",
            "pass" if staff_no_mfa == 0 else "fail",
            f"{staff_total - staff_no_mfa}/{staff_total} active operators have an "
            "authenticator enrolled."
            if staff_total
            else "No staff accounts exist yet — the console is running on "
            "break-glass access only.",
            "" if staff_no_mfa == 0 else "An operator without MFA cannot hold a "
            "session, but the account should be completed or removed.",
            "high",
        )
    )

    # Stale operator accounts — the classic audit finding.
    cutoff = datetime.now(UTC) - timedelta(days=90)
    dormant = await _count(
        select(func.count())
        .select_from(StaffAccount)
        .where(
            StaffAccount.status == "active",
            StaffAccount.last_login_at.is_not(None),
            StaffAccount.last_login_at < cutoff,
        )
    )
    checks.append(
        Check(
            "staff_dormant",
            "Dormant operator accounts",
            "pass" if dormant == 0 else "warn",
            "No active operator has been idle for 90 days."
            if dormant == 0
            else f"{dormant} active operator account(s) have not signed in for 90 days.",
            "" if dormant == 0 else "Suspend the accounts of people who have "
            "changed role or left.",
            "medium",
        )
    )

    # Customer admins without MFA — the account an attacker actually wants.
    admins_total = await _count(
        select(func.count())
        .select_from(User)
        .where(User.role.in_(["owner", "admin"]), User.status == "active")
    )
    admins_no_mfa = await _count(
        select(func.count())
        .select_from(User)
        .where(
            User.role.in_(["owner", "admin"]),
            User.status == "active",
            User.mfa_enabled.is_(False),
        )
    )
    checks.append(
        Check(
            "customer_admin_mfa",
            "Customer admin two-factor coverage",
            "pass" if admins_no_mfa == 0 else "warn",
            f"{admins_no_mfa} of {admins_total} customer owners/admins have not "
            "enrolled an authenticator.",
            "" if admins_no_mfa == 0 else "MFA is deferrable by design for "
            "customers; the dashboard nags them. Consider outreach for the "
            "largest accounts.",
            "medium",
        )
    )

    # Mailboxes that look protected and are not.
    broken = await _count(
        select(func.count()).select_from(Mailbox).where(Mailbox.needs_reconnect.is_(True))
    )
    checks.append(
        Check(
            "mailboxes_needing_reconnect",
            "Mailboxes silently unprotected",
            "pass" if broken == 0 else "warn",
            "Every connected mailbox is being read."
            if broken == 0
            else f"{broken} mailbox(es) hold a credential we can no longer use. "
            "They read as connected to the customer but are not being scanned.",
            "" if broken == 0 else "The customer is prompted in their dashboard; "
            "chase the ones that stay broken.",
            "high",
        )
    )

    # Domains claimed but never proven.
    unverified = await _count(
        select(func.count()).select_from(Domain).where(Domain.verified_at.is_(None))
    )
    checks.append(
        Check(
            "unverified_domains",
            "Unverified domains",
            "pass" if unverified == 0 else "warn",
            "Every domain on file has proven DNS control."
            if unverified == 0
            else f"{unverified} domain(s) are claimed but unproven. Mailboxes on "
            "them cannot be connected, which is the gate working.",
            "",
            "low",
        )
    )

    return checks


_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATE_ORDER = {"fail": 0, "warn": 1, "pass": 2}


@router.get("/security")
async def security_posture(operator: SecurityReader, session: Session) -> dict:
    """The live security posture of this deployment."""
    checks = _config_checks() + await _data_checks(session)
    checks.sort(key=lambda c: (_STATE_ORDER[c.state], _ORDER[c.severity], c.id))

    failing = [c for c in checks if c.state == "fail"]
    warning = [c for c in checks if c.state == "warn"]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total": len(checks),
            "passing": len(checks) - len(failing) - len(warning),
            "warning": len(warning),
            "failing": len(failing),
            # One word for the console header. "Attention" rather than a score:
            # a number invites arguing with the number.
            "state": "action_required"
            if failing
            else ("attention" if warning else "healthy"),
        },
        "checks": [c.as_dict() for c in checks],
    }


__all__ = ["router"]
