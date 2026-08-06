"""Unknown-IP / new-country / new-device login alerts via the sensor heartbeat.

The session detections (C7 impossible travel, C8 new country, C9 anonymising
network, C10 new device) existed but nothing ran them: `/sensor/heartbeat` stored
a session and returned. This proves the wired path — a second sign-in from a new
country on a new device now raises an alert.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.asyncio


def _totp_at(secret: str, counter: int) -> str:
    import hashlib
    import hmac
    import struct

    key = _b32decode(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def _b32decode(secret: str) -> bytes:
    import base64

    pad = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + pad)


@pytest.fixture
def client() -> Iterator[TestClient]:
    from envelock.api.auth import _reset_store
    from envelock.main import app

    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _auth_header(client: TestClient, email: str) -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
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
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def test_new_country_new_device_login_raises_alert(client: TestClient):
    h = _auth_header(client, email="admin@loginco.dev")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "LoginCo", "domain": "loginco.dev"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "ceo@loginco.dev", "mailbox_class": "protected", "sources": []},
        headers=h,
    )
    addr = "ceo@loginco.dev"

    # First sign-in: device A from the US. Enrolment — must NOT alert.
    first = client.post(
        "/api/v1/sensor/heartbeat",
        json={
            "mailbox_address": addr,
            "device_fingerprint": "device-A-known-1234",
            "ip": "8.8.8.8",
            "country": "US",
            "browser": "Chrome",
        },
        headers=h,
    ).json()
    assert first["alerted"] is False

    # Second sign-in: a NEW device from a NEW country. This is the unknown-IP
    # login the user asked about — it must alert.
    second = client.post(
        "/api/v1/sensor/heartbeat",
        json={
            "mailbox_address": addr,
            "device_fingerprint": "device-B-unknown-9999",
            "ip": "197.210.0.1",
            "country": "NG",
            "browser": "Firefox",
        },
        headers=h,
    ).json()
    assert second["alerted"] is True
    services = {f["service"] for f in second["findings"]}
    # C8 = sign-in from a new country; C10 = a new device.
    assert "C8" in services


async def test_same_device_heartbeat_does_not_realert(client: TestClient):
    h = _auth_header(client, email="admin@steadyco.dev")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "SteadyCo", "domain": "steadyco.dev"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "ops@steadyco.dev", "mailbox_class": "protected", "sources": []},
        headers=h,
    )
    body = {
        "mailbox_address": "ops@steadyco.dev",
        "device_fingerprint": "device-steady-0001",
        "ip": "8.8.4.4",
        "country": "US",
    }
    client.post("/api/v1/sensor/heartbeat", json=body, headers=h)
    again = client.post("/api/v1/sensor/heartbeat", json=body, headers=h).json()
    # A liveness heartbeat from the same open session is not a new sign-in.
    assert again["alerted"] is False
