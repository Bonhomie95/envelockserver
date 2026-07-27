"""Signup-time trial, IMAP credential verification, and bulk mailbox add."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.channels.mail import broker
from envelock.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _session(client: TestClient, email: str, domain: str = "acme.co") -> dict:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


# ── Signup trial (issue 1) ────────────────────────────────────────────────────
def test_signup_starts_a_trial_on_the_top_plan(client: TestClient) -> None:
    h = _session(client, "owner@acme.co")
    tenant = client.get("/api/v1/tenant", headers=h).json()
    assert tenant["plan"] == "complete"  # highest plan during trial
    assert tenant["trial"]["active"] is True
    assert tenant["trial"]["days_left"] is not None and tenant["trial"]["days_left"] > 0


def test_trial_domain_cannot_re_trial_after_deletion(client: TestClient) -> None:
    """The permanent ledger means a second signup on the same domain gets no trial."""
    _session(client, "first@ledger-test.co", domain="ledger-test.co")
    _reset_store()  # wipe users/tenants — the ledger row survives by design

    # A brand-new signup on the same registrable domain: no fresh trial.
    h = _session(client, "second@ledger-test.co", domain="ledger-test.co")
    tenant = client.get("/api/v1/tenant", headers=h).json()
    assert tenant["trial"]["active"] is False
    assert tenant["plan"] == "guard"


# ── IMAP verification (issue 2) ───────────────────────────────────────────────
def _add_mailbox(client: TestClient, h: dict, address: str) -> str:
    return client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()["id"]


def test_imap_connect_rejects_a_bad_password(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Unique domain per test — the trial ledger is permanent, and only a
    # first-trial tenant is entitled to add content mailboxes.
    h = _session(client, "it@imaprej.example", domain="imaprej.example")
    mb_id = _add_mailbox(client, h, "ceo@imaprej.example")

    async def _reject(**_: object) -> broker.ImapVerifyResult:
        return broker.ImapVerifyResult(False, "the server rejected the address or password")

    monkeypatch.setattr(broker, "verify_imap_credentials", _reject)

    out = client.post(
        f"/api/v1/mailboxes/{mb_id}/connect/imap",
        json={"imap_host": "imap.acme.co", "imap_port": 993, "password": "wrong"},
        headers=h,
    )
    assert out.status_code == 400
    # And the mailbox stays unconnected — no IMAP source was attached.
    boxes = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
    assert all("imap_idle" not in b["sources"] for b in boxes)


def test_imap_connect_succeeds_when_credentials_verify(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _session(client, "it2@imapok.example", domain="imapok.example")
    mb_id = _add_mailbox(client, h, "cfo@imapok.example")

    async def _ok(**_: object) -> broker.ImapVerifyResult:
        return broker.ImapVerifyResult(True, "signed in")

    monkeypatch.setattr(broker, "verify_imap_credentials", _ok)

    out = client.post(
        f"/api/v1/mailboxes/{mb_id}/connect/imap",
        json={"imap_host": "imap.acme.co", "imap_port": 993, "password": "app-pw"},
        headers=h,
    )
    assert out.status_code == 200
    assert "imap_idle" in out.json()["sources"]


# ── Bulk add (issue 3) ────────────────────────────────────────────────────────
def test_bulk_add_creates_many_and_skips_dupes(client: TestClient) -> None:
    h = _session(client, "admin@bulkco.example", domain="bulkco.example")
    out = client.post(
        "/api/v1/mailboxes/bulk",
        json={
            "addresses": [
                "finance@bulkco.example",
                "payroll@bulkco.example",
                "finance@bulkco.example",  # duplicate within the paste
                "not-an-email",  # invalid
                "  execs@bulkco.example  ",  # whitespace tolerated
            ],
            "mailbox_class": "protected",
        },
        headers=h,
    )
    assert out.status_code == 201
    body = out.json()
    assert body["created_count"] == 3
    assert body["skipped_count"] == 2
    listed = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
    addresses = {m["address"] for m in listed}
    assert {"finance@bulkco.example", "payroll@bulkco.example", "execs@bulkco.example"} <= addresses
