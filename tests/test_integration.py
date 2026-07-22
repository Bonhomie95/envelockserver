"""Full HTTP surface: signup → MFA → tenant → ingest → alert → acknowledge.

This is the test that proves the parts are actually connected, rather than each
working in isolation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.db import Base, get_engine
from envelock.main import app

pytestmark = pytest.mark.asyncio


def totp(secret: str) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


@pytest.fixture
async def client():
    _reset_store()
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    with TestClient(app) as c:
        yield c


def sign_in(client: TestClient, email="it@acme.com.ng") -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "a-long-enough-pw", "tenant_name": "Acme"},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "a-long-enough-pw"}
    ).json()
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": totp(setup["secret"])},
    ).json()
    return tokens["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


LEGIT = (
    "From: <billing@gemini.com>\nTo: pay@acme.com.ng\nSubject: Invoice 9001\n"
    "Content-Type: text/plain\n\n"
    "Invoice for March. Our bank account IBAN GB94BARC10201530093459 is unchanged."
)
FRAUD = (
    "From: <billing@gemini.com>\nTo: pay@acme.com.ng\nSubject: Re: Invoice 9001\n"
    "In-Reply-To: <old@gemini.com>\nContent-Type: text/plain\n\n"
    "Our bank account has changed. Remit to IBAN GB33BUKB20201555555555. "
    "Urgent, today please."
)


async def test_whole_journey_signup_to_acknowledged_alert(client: TestClient) -> None:
    token = sign_in(client)
    h = auth(token)

    # Tenant and mailbox
    boot = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme Freight", "domain": "acme.com.ng"},
        headers=h,
    ).json()
    assert boot["domain"] == "acme.com.ng"
    assert boot["ingest_address"].endswith("in.envelock.io")

    mailbox = client.post(
        "/api/v1/mailboxes",
        json={
            "address": "pay@acme.com.ng",
            "mailbox_class": "protected",
            "sources": ["imap_idle", "client_sensor"],
        },
        headers=h,
    ).json()
    assert mailbox["protection_level"] == "standard"
    # IMAP cannot read server-side rules, and we say which detections that costs.
    assert {"C1", "C2", "C4"} <= set(mailbox["inactive_detections"])

    # Learn the vendor from ordinary correspondence
    for i in range(3):
        client.post(
            "/api/v1/ingest",
            json={
                "raw_message": LEGIT.replace("9001", f"900{i}"),
                "mailbox_address": "pay@acme.com.ng",
            },
            headers=h,
        )

    client.post(
        "/api/v1/counterparties/gemini.com/phone",
        params={"phone": "+234 803 000 0000"},
        headers=h,
    )

    # The fraud
    result = client.post(
        "/api/v1/ingest",
        json={"raw_message": FRAUD, "mailbox_address": "pay@acme.com.ng"},
        headers=h,
    ).json()
    assert result["alerted"]
    assert result["tier"] == "critical"
    assert "A1" in [f["service"] for f in result["findings"]]

    # It is persisted, with the callback number from our records
    alerts = client.get("/api/v1/alerts", headers=h).json()
    critical = [a for a in alerts["alerts"] if a["tier"] == "critical"]
    assert len(critical) == 1
    assert critical[0]["requires_callback"]
    assert critical[0]["callback_phone"] == "+234 803 000 0000"
    # The headline is not repeated inside the body.
    assert critical[0]["title"] not in critical[0]["body"]

    # Acknowledge, and the audit trail records who did it
    acked = client.post(
        f"/api/v1/alerts/{critical[0]['id']}/acknowledge", headers=h
    ).json()
    assert acked["state"] == "acked"

    audit = client.get("/api/v1/audit", headers=h).json()
    actions = [e["action"] for e in audit["events"]]
    assert "alert.acknowledged" in actions
    assert "alert.raised" in actions

    oversight = client.get("/api/v1/oversight", headers=h).json()
    assert oversight["acknowledged"] >= 1


async def test_simulation_detects_every_scenario(client: TestClient) -> None:
    """A simulation that cannot fire the detection it claims to test is worse
    than no simulation — it would report a working detection as broken."""
    h = auth(sign_in(client))
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme", "domain": "acme.com.ng"},
        headers=h,
    )
    result = client.post(
        "/api/v1/simulate", json={"protected_domain": "acme.com.ng"}, headers=h
    ).json()
    assert result["passed"] == result["total"], result["runs"]


async def test_quarantine_refuses_on_forwarding_connected_mailbox(
    client: TestClient,
) -> None:
    h = auth(sign_in(client))
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Acme", "domain": "acme.com.ng"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={
            "address": "warehouse@acme.com.ng",
            "mailbox_class": "monitored",
            "sources": ["forward_ingest"],
        },
        headers=h,
    )
    for i in range(3):
        client.post(
            "/api/v1/ingest",
            json={
                "raw_message": LEGIT.replace("9001", f"800{i}").replace(
                    "pay@", "warehouse@"
                ),
                "mailbox_address": "warehouse@acme.com.ng",
            },
            headers=h,
        )
    client.post(
        "/api/v1/ingest",
        json={
            "raw_message": FRAUD.replace("pay@", "warehouse@"),
            "mailbox_address": "warehouse@acme.com.ng",
        },
        headers=h,
    )

    alerts = client.get("/api/v1/alerts", headers=h).json()["alerts"]
    assert alerts
    result = client.post(
        f"/api/v1/alerts/{alerts[0]['id']}/quarantine", headers=h
    ).json()
    assert not result["succeeded"]
    assert result["alert_only"]
    assert "post-delivery" in result["reason"]


async def test_tenants_cannot_see_each_others_alerts(client: TestClient) -> None:
    first = auth(sign_in(client, "a@one.com"))
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": "One", "domain": "one.com"}, headers=first
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "pay@one.com", "mailbox_class": "protected", "sources": ["imap_idle"]},
        headers=first,
    )
    for i in range(3):
        client.post(
            "/api/v1/ingest",
            json={
                "raw_message": LEGIT.replace("9001", f"700{i}").replace("acme.com.ng", "one.com"),
                "mailbox_address": "pay@one.com",
            },
            headers=first,
        )
    client.post(
        "/api/v1/ingest",
        json={
            "raw_message": FRAUD.replace("acme.com.ng", "one.com"),
            "mailbox_address": "pay@one.com",
        },
        headers=first,
    )
    assert client.get("/api/v1/alerts", headers=first).json()["count"] > 0

    second = auth(sign_in(client, "b@two.com"))
    assert client.get("/api/v1/alerts", headers=second).json()["count"] == 0


async def test_ingest_requires_a_known_mailbox(client: TestClient) -> None:
    h = auth(sign_in(client))
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": "Acme", "domain": "acme.com.ng"}, headers=h
    )
    response = client.post(
        "/api/v1/ingest",
        json={"raw_message": FRAUD, "mailbox_address": "nobody@acme.com.ng"},
        headers=h,
    )
    assert response.status_code == 404


async def test_public_endpoints_need_no_session(client: TestClient) -> None:
    """Channel 3 works before signup — that is why Guard can be free."""
    assert client.get("/api/v1/retention/schedule").status_code == 200
    assert client.get("/api/v1/quality/targets").status_code == 200
    assert client.post("/api/v1/domains/scan", json={"domain": "gemini.com"}).status_code == 200
    assert client.get("/api/v1/providers").status_code == 200


async def test_status_reports_unconfigured_providers_honestly(client: TestClient) -> None:
    h = auth(sign_in(client))
    status = client.get("/api/v1/status/channels", headers=h).json()
    sources = {p["source"]: p for p in status["mail_providers"]}
    # Forwarding needs no credentials at all, so it is always available.
    assert sources["forward_ingest"]["configured"] is True
    for provider in status["mail_providers"]:
        if not provider["configured"]:
            assert provider["reason"]
