"""Owner-provisioned team members: temp password, forced first change, and the
per-plan seat limit (Guard = owner only; paid/trial = one login per protected seat).
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app

PW = "a-long-enough-passphrase"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _owner(client: TestClient, domain: str) -> dict:
    email = f"owner@{domain}"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _add_protected(client: TestClient, h: dict, address: str) -> None:
    client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected", "sources": []},
        headers=h,
    )


def test_guard_is_owner_only(client: TestClient) -> None:
    """On Guard (no trial), no team logins can be created."""
    h = _owner(client, "guardonly.example")
    # Lapse the trial so the tenant is on Guard.
    import asyncio
    from datetime import UTC, datetime, timedelta
    from uuid import UUID

    from envelock.db import get_sessionmaker
    from envelock.models import Tenant

    tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]

    async def _lapse() -> None:
        async with get_sessionmaker()() as s:
            t = await s.get(Tenant, UUID(tid))
            t.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
            await s.commit()

    asyncio.run(_lapse())

    r = client.post(
        "/api/v1/members", json={"email": "staff@guardonly.example", "role": "member"}, headers=h
    )
    assert r.status_code == 402


def test_seat_cap_tracks_protected_mailboxes(client: TestClient) -> None:
    h = _owner(client, "seatco.example")  # entitled (trial active), 0 protected → 0 seats

    # No protected mailboxes yet → no seats.
    blocked = client.post(
        "/api/v1/members", json={"email": "a@seatco.example", "role": "member"}, headers=h
    )
    assert blocked.status_code == 402

    _add_protected(client, h, "cfo@seatco.example")  # 1 protected → 1 seat
    ok = client.post(
        "/api/v1/members", json={"email": "a@seatco.example", "role": "member"}, headers=h
    )
    assert ok.status_code == 201
    assert ok.json()["temporary_password"]

    # Second member exceeds the single seat.
    full = client.post(
        "/api/v1/members", json={"email": "b@seatco.example", "role": "member"}, headers=h
    )
    assert full.status_code == 402

    seats = client.get("/api/v1/members", headers=h).json()["seats"]
    assert seats == {"used": 1, "cap": 1, "entitled": True, "protected_mailboxes": 1}


def test_provisioned_member_must_change_password_then_signs_in(client: TestClient) -> None:
    h = _owner(client, "provco.example")
    _add_protected(client, h, "cfo@provco.example")
    created = client.post(
        "/api/v1/members",
        json={"email": "member@provco.example", "role": "member"},
        headers=h,
    ).json()
    temp = created["temporary_password"]

    # The member signs in with the temp password and lands with must_change flagged.
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "member@provco.example", "password": temp},
    ).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    mh = {"Authorization": f"Bearer {skip['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=mh).json()
    assert me["must_change_password"] is True
    assert me["role"] == "member"

    # Setting the initial password needs no MFA and clears the flag.
    r = client.post(
        "/api/v1/auth/password/initial",
        json={"new_password": "a-fresh-member-passphrase-1"},
        headers=mh,
    )
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers=mh).json()["must_change_password"] is False

    # And the new password works at login; the temp one no longer does.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "member@provco.example", "password": "a-fresh-member-passphrase-1"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "member@provco.example", "password": temp},
        ).status_code
        == 401
    )


def test_only_owner_can_create_admins(client: TestClient) -> None:
    h = _owner(client, "adminco.example")
    _add_protected(client, h, "cfo@adminco.example")
    _add_protected(client, h, "ceo@adminco.example")
    # Owner creates an admin.
    admin = client.post(
        "/api/v1/members", json={"email": "admin@adminco.example", "role": "admin"}, headers=h
    )
    assert admin.status_code == 201

    # That admin signs in and cannot mint another admin.
    temp = admin.json()["temporary_password"]
    login = client.post(
        "/api/v1/auth/login", json={"email": "admin@adminco.example", "password": temp}
    ).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    ah = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post(
        "/api/v1/auth/password/initial",
        json={"new_password": "an-admin-passphrase-2"},
        headers=ah,
    )
    r = client.post(
        "/api/v1/members", json={"email": "admin2@adminco.example", "role": "admin"}, headers=ah
    )
    assert r.status_code == 403  # only the owner mints admins

    # But the admin CAN create a plain member (a seat remains).
    ok = client.post(
        "/api/v1/members", json={"email": "m@adminco.example", "role": "member"}, headers=ah
    )
    assert ok.status_code == 201


def _mfa_owner(client: TestClient, domain: str) -> tuple[dict, str]:
    email = f"owner@{domain}"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h, setup["secret"]


def test_initial_password_endpoint_only_works_when_pending(client: TestClient) -> None:
    # A normal owner (not provisioned) has no pending change.
    h, _ = _mfa_owner(client, "normalco.example")
    r = client.post(
        "/api/v1/auth/password/initial",
        json={"new_password": "some-other-passphrase-9"},
        headers=h,
    )
    assert r.status_code == 409
