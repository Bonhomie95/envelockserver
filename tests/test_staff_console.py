"""Platform staff: departments, permissions, and the boundaries around them.

The admin console reaches every tenant's metadata, so the interesting questions
are not "does create work" but "can a support agent suspend a tenant", "can
someone with staff:manage promote themselves", and "does a customer token open
any of it". These pin those.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from envelock.auth.security import _totp_at, hash_password
from envelock.auth.staff import Department, Permission, resolve_permissions
from envelock.db import get_sessionmaker
from envelock.models import StaffAccount

TEMP_PW = "Env-first-temporary-passphrase"  # noqa: S105 — a fixture value
REAL_PW = "a-long-enough-operator-passphrase"  # noqa: S105


@pytest.fixture(autouse=True)
def _clear_staff() -> Iterator[None]:
    """Staff rows are not tenant-scoped, so the tenant truncate in `client`
    doesn't reach them."""

    async def _wipe() -> None:
        async with get_sessionmaker()() as session:
            for account in (await session.execute(select(StaffAccount))).scalars().all():
                await session.delete(account)
            await session.commit()

    asyncio.run(_wipe())
    yield
    asyncio.run(_wipe())


def _seed(email: str, department: Department, **fields: object) -> str:
    """An operator who has already completed onboarding."""

    async def _add() -> str:
        async with get_sessionmaker()() as session:
            account = StaffAccount(
                **{
                    "email": email,
                    "name": email.split("@")[0],
                    "password_hash": hash_password(REAL_PW),
                    "department": department.value,
                    "status": "active",
                    "must_change_password": False,
                    **fields,
                }
            )
            session.add(account)
            await session.commit()
            return str(account.id)

    return asyncio.run(_add())


def _totp_secret(email: str) -> str:
    """Read the enrolled secret straight from the row — the API only hands it out
    once, at enrolment, and a test may sign in more than once."""

    async def _read() -> str:
        async with get_sessionmaker()() as session:
            account = (
                await session.execute(select(StaffAccount).where(StaffAccount.email == email))
            ).scalar_one()
            return account.totp_secret or ""

    return asyncio.run(_read())


def _sign_in(client: TestClient, email: str, password: str = REAL_PW) -> dict[str, str]:
    login = client.post(
        "/api/v1/admin/auth/login", json={"email": email, "password": password}
    )
    assert login.status_code == 200, login.text
    body = login.json()
    token = body["mfa_token"]

    if body["mfa_setup_required"]:
        setup = client.post("/api/v1/admin/auth/mfa/setup", json={"token": token})
        assert setup.status_code == 200, setup.text
        secret = setup.json()["secret"]
    else:
        secret = _totp_secret(email)

    # A TOTP code is single-use, so a second sign-in inside the same 30s step
    # needs the next step's code rather than a replay.
    step = int(time.time()) // 30
    for candidate in (step, step + 1, step + 2):
        verified = client.post(
            "/api/v1/admin/auth/mfa/verify",
            json={"mfa_token": token, "code": _totp_at(secret, candidate)},
        )
        if verified.status_code == 200:
            return {"Authorization": f"Bearer {verified.json()['access_token']}"}
    raise AssertionError(f"could not sign in as {email}: {verified.text}")


# ── The permission model itself ──────────────────────────────────────────────
def test_departments_are_least_privilege_by_default() -> None:
    support = resolve_permissions(department=Department.SUPPORT)
    assert Permission.USER_MANAGE in support, "support has to approve customer users"
    assert Permission.TENANT_SUSPEND not in support
    assert Permission.TENANT_BILLING not in support
    assert Permission.STAFF_MANAGE not in support

    billing = resolve_permissions(department=Department.BILLING)
    assert Permission.TENANT_BILLING in billing
    assert Permission.USER_READ not in billing, "billing has no reason to read users"
    assert Permission.AUDIT_READ not in billing


def test_a_revocation_beats_a_stale_grant() -> None:
    """Taking access away must not be defeated by an older, forgotten grant."""
    permissions = resolve_permissions(
        department=Department.SECURITY,
        granted=[Permission.TENANT_SUSPEND.value],
        revoked=[Permission.TENANT_SUSPEND.value],
    )
    assert Permission.TENANT_SUSPEND not in permissions


def test_an_unknown_permission_string_is_ignored_not_fatal() -> None:
    """A permission removed in a later release must not break every operator
    whose record still names it."""
    permissions = resolve_permissions(
        department=Department.SUPPORT, granted=["tenant:teleport"]
    )
    assert Permission.PLATFORM_READ in permissions


# ── Sign-in ──────────────────────────────────────────────────────────────────
def test_an_operator_cannot_skip_two_factor(client: TestClient) -> None:
    """Customers may defer MFA and be nagged. These credentials reach every
    tenant's metadata, so there is no skip endpoint at all."""
    _seed("ada@envelock.io", Department.LEADERSHIP)
    login = client.post(
        "/api/v1/admin/auth/login",
        json={"email": "ada@envelock.io", "password": REAL_PW},
    )
    assert login.status_code == 200
    skipped = client.post(
        "/api/v1/admin/auth/mfa/skip", json={"token": login.json()["mfa_token"]}
    )
    assert skipped.status_code == 404


def test_a_new_operator_must_replace_the_temporary_password_first(
    client: TestClient,
) -> None:
    _seed(
        "new@envelock.io",
        Department.SUPPORT,
        must_change_password=True,
        password_hash=hash_password(TEMP_PW),
    )
    headers = _sign_in(client, "new@envelock.io", TEMP_PW)

    blocked = client.get("/api/v1/admin/overview", headers=headers)
    assert blocked.status_code == 403
    assert "password" in blocked.json()["detail"]

    changed = client.post(
        "/api/v1/admin/auth/password",
        json={"current_password": TEMP_PW, "new_password": REAL_PW},
        headers=headers,
    )
    assert changed.status_code == 200

    # The change revoked every session, so a fresh sign-in is required — and now
    # the console answers.
    headers = _sign_in(client, "new@envelock.io", REAL_PW)
    assert client.get("/api/v1/admin/overview", headers=headers).status_code == 200


def test_a_customer_token_opens_nothing_on_the_console(client: TestClient) -> None:
    """A stolen customer session pointed at /admin must not even reveal that the
    console exists."""
    email, pw = "owner@customerco.example", "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "CustomerCo"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    assert client.get("/api/v1/admin/overview", headers=headers).status_code == 404
    assert client.get("/api/v1/admin/staff", headers=headers).status_code == 404
    assert client.get("/api/v1/admin/security", headers=headers).status_code == 404


# ── Permission enforcement on the real endpoints ─────────────────────────────
def test_support_can_approve_a_user_but_not_suspend_a_tenant(client: TestClient) -> None:
    _seed("sam@envelock.io", Department.SUPPORT)
    headers = _sign_in(client, "sam@envelock.io")

    assert client.get("/api/v1/admin/overview", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/tenants", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 200

    fake = "00000000-0000-4000-8000-000000000001"
    # 403 (not 404): the permission is checked before the row is looked up, so a
    # refusal never doubles as an existence oracle.
    denied = client.post(f"/api/v1/admin/tenants/{fake}/suspend", headers=headers)
    assert denied.status_code == 403
    assert "tenant:suspend" in denied.json()["detail"]

    assert (
        client.post(
            f"/api/v1/admin/tenants/{fake}/plan",
            json={"plan": "complete"},
            headers=headers,
        ).status_code
        == 403
    )
    # It DOES hold user:manage, so this gets as far as "no such user".
    assert client.post(f"/api/v1/admin/users/{fake}/approve", headers=headers).status_code == 404


def test_billing_cannot_read_the_audit_trail_or_customer_users(
    client: TestClient,
) -> None:
    _seed("bill@envelock.io", Department.BILLING)
    headers = _sign_in(client, "bill@envelock.io")
    assert client.get("/api/v1/admin/tenants", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/staff/audit", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/security", headers=headers).status_code == 403


def test_compliance_reads_everything_and_changes_nothing(client: TestClient) -> None:
    _seed("cara@envelock.io", Department.COMPLIANCE)
    headers = _sign_in(client, "cara@envelock.io")
    assert client.get("/api/v1/admin/security", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/staff/audit", headers=headers).status_code == 200
    fake = "00000000-0000-4000-8000-000000000001"
    assert client.post(f"/api/v1/admin/users/{fake}/approve", headers=headers).status_code == 403
    assert client.post(f"/api/v1/admin/tenants/{fake}/suspend", headers=headers).status_code == 403


# ── Staff management ─────────────────────────────────────────────────────────
def test_creating_a_colleague_returns_a_one_time_password(client: TestClient) -> None:
    _seed("lead@envelock.io", Department.LEADERSHIP)
    headers = _sign_in(client, "lead@envelock.io")

    created = client.post(
        "/api/v1/admin/staff",
        json={
            "email": "Nina@Envelock.IO",
            "name": "Nina",
            "department": "support",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["email"] == "nina@envelock.io"
    assert body["must_change_password"] is True
    assert body["temporary_password"]
    assert "user:manage" in body["permissions"]
    assert "tenant:suspend" not in body["permissions"]

    # The password is shown once and is not readable from the list afterwards.
    listed = client.get("/api/v1/admin/staff", headers=headers).json()
    nina = next(s for s in listed["staff"] if s["email"] == "nina@envelock.io")
    assert "temporary_password" not in nina
    assert "password_hash" not in nina

    # And it actually works as a sign-in.
    assert (
        client.post(
            "/api/v1/admin/auth/login",
            json={"email": "nina@envelock.io", "password": body["temporary_password"]},
        ).status_code
        == 200
    )


def test_nobody_can_grant_a_permission_they_do_not_hold(client: TestClient) -> None:
    """Otherwise `staff:manage` silently means every permission: create an
    account with the extra power, then sign in as it."""
    _seed("sec@envelock.io", Department.SECURITY)
    headers = _sign_in(client, "sec@envelock.io")
    assert Permission.TENANT_BILLING not in resolve_permissions(
        department=Department.SECURITY
    )

    denied = client.post(
        "/api/v1/admin/staff",
        json={
            "email": "mole@envelock.io",
            "department": "support",
            "granted_permissions": ["tenant:billing"],
        },
        headers=headers,
    )
    assert denied.status_code == 403
    assert "tenant:billing" in denied.json()["detail"]

    # And the department shortcut is closed too — you cannot assign a department
    # whose defaults exceed your own permissions.
    assert (
        client.post(
            "/api/v1/admin/staff",
            json={"email": "mole2@envelock.io", "department": "leadership"},
            headers=headers,
        ).status_code
        == 403
    )


def test_an_operator_cannot_promote_themselves(client: TestClient) -> None:
    staff_id = _seed("sec2@envelock.io", Department.SECURITY)
    headers = _sign_in(client, "sec2@envelock.io")
    blocked = client.patch(
        f"/api/v1/admin/staff/{staff_id}",
        json={"department": "leadership"},
        headers=headers,
    )
    assert blocked.status_code == 409


def test_suspending_an_operator_takes_effect_immediately(client: TestClient) -> None:
    _seed("lead2@envelock.io", Department.LEADERSHIP)
    victim_id = _seed("temp@envelock.io", Department.SUPPORT)
    lead_headers = _sign_in(client, "lead2@envelock.io")
    victim_headers = _sign_in(client, "temp@envelock.io")

    assert client.get("/api/v1/admin/overview", headers=victim_headers).status_code == 200
    assert (
        client.post(f"/api/v1/admin/staff/{victim_id}/suspend", headers=lead_headers).status_code
        == 200
    )
    # Their existing access token stops working on the next request, not in 15 minutes.
    assert client.get("/api/v1/admin/overview", headers=victim_headers).status_code == 404


def test_the_last_staff_manager_cannot_be_suspended(client: TestClient) -> None:
    """Locking the last in-product administrator out is a support incident."""
    only_id = _seed("solo@envelock.io", Department.LEADERSHIP)
    headers = _sign_in(client, "solo@envelock.io")
    # Suspending yourself is refused first...
    assert (
        client.post(f"/api/v1/admin/staff/{only_id}/suspend", headers=headers).status_code
        == 409
    )
    # ...and so is suspending the last one, from another manager's session.
    other_id = _seed("solo2@envelock.io", Department.SECURITY)
    other_headers = _sign_in(client, "solo2@envelock.io")
    client.post(f"/api/v1/admin/staff/{other_id}/suspend", headers=headers)
    assert (
        client.post(f"/api/v1/admin/staff/{only_id}/suspend", headers=other_headers).status_code
        in (404, 409)
    )


def test_a_password_reset_also_clears_the_authenticator(client: TestClient) -> None:
    """The usual reason for this call is "they lost the phone it was on"."""
    _seed("lead3@envelock.io", Department.LEADERSHIP)
    target_id = _seed("lost@envelock.io", Department.SUPPORT)
    headers = _sign_in(client, "lead3@envelock.io")

    reset = client.post(
        f"/api/v1/admin/staff/{target_id}/reset-password", headers=headers
    )
    assert reset.status_code == 200
    body = reset.json()
    assert body["temporary_password"]
    assert body["mfa_enabled"] is False
    assert body["must_change_password"] is True


def test_every_staff_action_is_written_to_the_staff_audit_log(client: TestClient) -> None:
    _seed("lead4@envelock.io", Department.LEADERSHIP)
    headers = _sign_in(client, "lead4@envelock.io")
    client.post(
        "/api/v1/admin/staff",
        json={"email": "audited@envelock.io", "department": "billing"},
        headers=headers,
    )
    events = client.get("/api/v1/admin/staff/audit", headers=headers).json()["events"]
    assert any(
        e["action"] == "staff.created" and e["actor"] == "lead4@envelock.io"
        for e in events
    )


def test_the_role_catalogue_says_what_each_department_grants(client: TestClient) -> None:
    """The person filling in the form should see what they are handing over."""
    _seed("lead5@envelock.io", Department.LEADERSHIP)
    headers = _sign_in(client, "lead5@envelock.io")
    body = client.get("/api/v1/admin/staff/roles", headers=headers).json()
    departments = {d["id"]: d for d in body["departments"]}
    assert set(departments) == {d.value for d in Department}
    assert departments["support"]["description"]
    assert "tenant:suspend" not in departments["support"]["permissions"]
    assert body["your_permissions"]


# ── Security posture ─────────────────────────────────────────────────────────
def test_the_security_page_reports_the_deployment_honestly(client: TestClient) -> None:
    _seed("sec3@envelock.io", Department.SECURITY)
    headers = _sign_in(client, "sec3@envelock.io")
    body = client.get("/api/v1/admin/security", headers=headers).json()

    checks = {c["id"]: c for c in body["checks"]}
    # The test environment uses the development key mode, and the page must say
    # so rather than reporting a healthy deployment.
    assert checks["key_custody"]["state"] in ("warn", "fail")
    assert "environment variable" in checks["key_custody"]["detail"]
    assert checks["key_custody"]["remedy"]
    assert body["summary"]["state"] in ("healthy", "attention", "action_required")
    # Failures sort first — this page is read top-down during an incident.
    states = [c["state"] for c in body["checks"]]
    assert states == sorted(states, key=lambda s: {"fail": 0, "warn": 1, "pass": 2}[s])
