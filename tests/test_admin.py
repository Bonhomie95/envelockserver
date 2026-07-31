"""Super-admin (platform) console API.

Access is an email allowlist set at deployment, so the tests configure it and
prove both the gate (non-admins are invisible) and the cross-tenant operations.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app

SUPERADMIN = "root@envelock.com"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


@pytest.fixture
def superadmin_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_SUPERADMIN_EMAILS", SUPERADMIN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _session(client: TestClient, email: str) -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Co"},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    # Register the email's domain so the tenant is searchable by domain.
    domain = email.split("@", 1)[1]
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": "Co", "domain": domain}, headers=h
    )
    return h


def test_non_superadmin_cannot_see_the_console(client: TestClient, superadmin_env: None) -> None:
    """A normal signed-in user gets 404 — the surface isn't even advertised."""
    h = _session(client, "someone@normalco-uniq.com")
    assert client.get("/api/v1/admin/overview", headers=h).status_code == 404
    assert client.get("/api/v1/admin/tenants", headers=h).status_code == 404


def test_superadmin_sees_overview_and_lists(client: TestClient, superadmin_env: None) -> None:
    _session(client, "owner@customerco-uniq.com")  # some tenant to see
    h = _session(client, SUPERADMIN)

    ov = client.get("/api/v1/admin/overview", headers=h)
    assert ov.status_code == 200
    body = ov.json()
    assert body["tenants"] >= 2 and body["users"] >= 2
    assert "plan_distribution" in body

    tenants = client.get("/api/v1/admin/tenants", headers=h).json()
    assert tenants["total"] >= 2
    assert all("primary_domain" in t and "effective_plan" in t for t in tenants["tenants"])

    users = client.get(
        "/api/v1/admin/users", params={"query": "customerco-uniq"}, headers=h
    ).json()
    assert any(u["email"] == "owner@customerco-uniq.com" for u in users["users"])


def test_superadmin_can_extend_trial_and_change_plan(
    client: TestClient, superadmin_env: None
) -> None:
    _session(client, "owner@acty-uniq.com")
    h = _session(client, SUPERADMIN)
    tid = next(
        t["id"]
        for t in client.get(
            "/api/v1/admin/tenants", params={"query": "acty-uniq"}, headers=h
        ).json()["tenants"]
    )

    plan = client.post(f"/api/v1/admin/tenants/{tid}/plan", json={"plan": "essential"}, headers=h)
    assert plan.status_code == 200 and plan.json()["subscribed_plan"] == "essential"

    ext = client.post(
        f"/api/v1/admin/tenants/{tid}/extend-trial", json={"days": 30}, headers=h
    )
    assert ext.status_code == 200 and ext.json()["trial_days_left"] >= 29


def test_superadmin_user_actions_and_last_owner_guard(
    client: TestClient, superadmin_env: None
) -> None:
    # A tenant with an owner and a joined (pending) colleague.
    _session(client, "owner@teamx-uniq.com")
    _session(client, "colleague@teamx-uniq.com")
    h = _session(client, SUPERADMIN)

    users = client.get(
        "/api/v1/admin/users", params={"query": "teamx-uniq"}, headers=h
    ).json()["users"]
    owner = next(u for u in users if u["role"] == "owner")
    colleague = next(u for u in users if u["email"] == "colleague@teamx-uniq.com")

    # Approve the pending colleague.
    assert colleague["status"] == "pending"
    r = client.post(f"/api/v1/admin/users/{colleague['id']}/approve", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "active"

    # Suspend then reactivate them.
    assert client.post(f"/api/v1/admin/users/{colleague['id']}/suspend", headers=h).json()[
        "status"
    ] == "suspended"
    assert client.post(f"/api/v1/admin/users/{colleague['id']}/activate", headers=h).json()[
        "status"
    ] == "active"

    # The sole owner cannot be demoted away — a tenant must keep an owner.
    demote = client.post(
        f"/api/v1/admin/users/{owner['id']}/role", json={"role": "member"}, headers=h
    )
    assert demote.status_code == 409
