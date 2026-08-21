"""Platform staff: who at Envelock can operate the product, and how much.

Super-admin used to be a single environment allowlist — every listed email could
do everything, and the only way to onboard a colleague was a redeploy. That does
not survive a second hire: a support agent who can suspend any tenant, a billing
clerk who can read every customer's alert queue, and no record of who was granted
what. This module is the replacement.

Three ideas, deliberately small:

* **A department** is what someone was hired to do (support, billing, security,
  engineering, compliance, leadership). It carries a sensible default set of
  permissions, so onboarding is "add Ada to Support", not a checklist.
* **A permission** is one verb over one surface (`tenant:suspend`,
  `staff:manage`). Every admin endpoint names the permission it needs, so the
  question "can this person do that?" has exactly one answer in one place.
* **A grant/revoke overlay** handles the exceptions a real team always has —
  the support lead who also needs billing, the engineer temporarily off keys —
  without inventing a new department for each of them.

The env allowlist survives as **break-glass**: an email in
`ENVELOCK_SUPERADMIN_EMAILS` always has every permission, cannot be locked out by
a bad grant, and is how the very first staff account gets created. It is
deployment-level and can never be granted through the product.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Permission(StrEnum):
    """One verb over one surface. Endpoints name these; nothing infers them."""

    # Read
    PLATFORM_READ = "platform:read"  # overview counts, the console home
    TENANT_READ = "tenant:read"  # tenant list and detail (metadata, never mail)
    USER_READ = "user:read"  # customer users across tenants
    AUDIT_READ = "audit:read"  # the cross-tenant audit trail
    SECURITY_READ = "security:read"  # security posture / key custody / config

    # Customer lifecycle
    TENANT_BILLING = "tenant:billing"  # change plan, extend a trial
    TENANT_SUSPEND = "tenant:suspend"  # suspend or reactivate a whole tenant
    USER_MANAGE = "user:manage"  # approve, suspend, reactivate a customer user
    USER_ROLE = "user:role"  # change a customer user's role

    # Platform
    STAFF_READ = "staff:read"
    STAFF_MANAGE = "staff:manage"  # create colleagues, set departments, revoke


ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)


class Department(StrEnum):
    """What someone was hired to do. Drives the default permission set."""

    LEADERSHIP = "leadership"
    SECURITY = "security"
    ENGINEERING = "engineering"
    SUPPORT = "support"
    BILLING = "billing"
    COMPLIANCE = "compliance"


#: Least privilege by default: a department gets what its job needs and no more.
#: Notably — support cannot change plans or roles, billing cannot read the audit
#: trail, and only leadership and security can create staff.
DEPARTMENT_PERMISSIONS: dict[Department, frozenset[Permission]] = {
    Department.LEADERSHIP: ALL_PERMISSIONS,
    Department.SECURITY: frozenset(
        {
            Permission.PLATFORM_READ,
            Permission.TENANT_READ,
            Permission.USER_READ,
            Permission.AUDIT_READ,
            Permission.SECURITY_READ,
            Permission.TENANT_SUSPEND,
            Permission.USER_MANAGE,
            Permission.STAFF_READ,
            Permission.STAFF_MANAGE,
        }
    ),
    Department.ENGINEERING: frozenset(
        {
            Permission.PLATFORM_READ,
            Permission.TENANT_READ,
            Permission.USER_READ,
            Permission.SECURITY_READ,
            Permission.AUDIT_READ,
            Permission.STAFF_READ,
        }
    ),
    Department.SUPPORT: frozenset(
        {
            Permission.PLATFORM_READ,
            Permission.TENANT_READ,
            Permission.USER_READ,
            Permission.USER_MANAGE,
            Permission.STAFF_READ,
        }
    ),
    Department.BILLING: frozenset(
        {
            Permission.PLATFORM_READ,
            Permission.TENANT_READ,
            Permission.TENANT_BILLING,
            Permission.STAFF_READ,
        }
    ),
    Department.COMPLIANCE: frozenset(
        {
            Permission.PLATFORM_READ,
            Permission.TENANT_READ,
            Permission.USER_READ,
            Permission.AUDIT_READ,
            Permission.SECURITY_READ,
            Permission.STAFF_READ,
        }
    ),
}

#: Shown in the console so an admin picks a department knowing what it grants.
DEPARTMENT_DESCRIPTIONS: dict[Department, str] = {
    Department.LEADERSHIP: "Everything, including creating and removing staff.",
    Department.SECURITY: (
        "Full read, the security posture page, and the ability to suspend a "
        "tenant or a user during an incident. Can onboard staff."
    ),
    Department.ENGINEERING: (
        "Read-only across the platform plus the security posture page. No "
        "customer lifecycle actions."
    ),
    Department.SUPPORT: (
        "Read tenants and users, and approve, suspend or reactivate a customer "
        "user. Cannot change plans, roles or billing."
    ),
    Department.BILLING: (
        "Read tenants, change plans and extend trials. No access to customer "
        "users or the audit trail."
    ),
    Department.COMPLIANCE: (
        "Read-only across the platform, plus the audit trail and security "
        "posture for evidence gathering. Changes nothing."
    ),
}


def default_permissions(department: Department | str) -> frozenset[Permission]:
    try:
        return DEPARTMENT_PERMISSIONS[Department(department)]
    except (ValueError, KeyError):
        return frozenset()


def resolve_permissions(
    *,
    department: Department | str,
    granted: list[str] | None = None,
    revoked: list[str] | None = None,
) -> frozenset[Permission]:
    """Department defaults, plus explicit grants, minus explicit revocations.

    Revocation wins over a grant: taking access away must never be defeated by an
    older, forgotten grant sitting in the same record.
    """

    def _parse(values: list[str] | None) -> set[Permission]:
        out: set[Permission] = set()
        for value in values or []:
            try:
                out.add(Permission(value))
            except ValueError:
                continue  # a permission removed in a later release — ignore, don't crash
        return out

    return frozenset(
        (set(default_permissions(department)) | _parse(granted)) - _parse(revoked)
    )


@dataclass(frozen=True, slots=True)
class Operator:
    """The authenticated platform operator behind an admin request."""

    id: str
    email: str
    name: str | None
    department: str
    permissions: frozenset[Permission]
    #: True for an email on the deployment allowlist — break-glass access that no
    #: in-product change can remove, and the only way to bootstrap the first
    #: staff account.
    break_glass: bool = False

    def can(self, permission: Permission) -> bool:
        return self.break_glass or permission in self.permissions

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "department": self.department,
            "permissions": sorted(p.value for p in self.permissions),
            "break_glass": self.break_glass,
        }


def department_catalogue() -> list[dict]:
    """What the console renders on the "add a colleague" form."""
    return [
        {
            "id": d.value,
            "name": d.value.replace("_", " ").title(),
            "description": DEPARTMENT_DESCRIPTIONS[d],
            "permissions": sorted(p.value for p in DEPARTMENT_PERMISSIONS[d]),
        }
        for d in Department
    ]


def permission_catalogue() -> list[dict]:
    labels = {
        Permission.PLATFORM_READ: "See the platform overview",
        Permission.TENANT_READ: "See tenants and their detail",
        Permission.USER_READ: "See customer users",
        Permission.AUDIT_READ: "Read the audit trail",
        Permission.SECURITY_READ: "See the security posture",
        Permission.TENANT_BILLING: "Change a plan or extend a trial",
        Permission.TENANT_SUSPEND: "Suspend or reactivate a tenant",
        Permission.USER_MANAGE: "Approve, suspend or reactivate a customer user",
        Permission.USER_ROLE: "Change a customer user's role",
        Permission.STAFF_READ: "See the staff list",
        Permission.STAFF_MANAGE: "Create, change and remove staff",
    }
    return [{"id": p.value, "label": labels[p]} for p in Permission]


__all__ = [
    "ALL_PERMISSIONS",
    "DEPARTMENT_DESCRIPTIONS",
    "DEPARTMENT_PERMISSIONS",
    "Department",
    "Operator",
    "Permission",
    "default_permissions",
    "department_catalogue",
    "permission_catalogue",
    "resolve_permissions",
]
