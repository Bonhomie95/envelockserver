"""API surface, exercised the way the frontend uses it."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Enter the lifespan so the schema is bootstrapped — the authenticated paths
    # below need the persisted users table (PRD §17.1).
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _auth_header(client: TestClient, email: str = "analyst@acme.com") -> dict[str, str]:
    """Register → login → enrol MFA, returning an Authorization header. Signed-in
    callers see the full detection taxonomy that §16 redacts from anonymous ones."""
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": pw}
    ).json()
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


BEC = """From: "Gemini Accounts" <billing@gemini.com>
To: pay@acme.com
Subject: Re: Invoice 4471
In-Reply-To: <old@gemini.com>
Content-Type: text/plain

Our bank account has changed. Remit to IBAN GB33BUKB20201555555555.
This is urgent, we need it today. Please keep this confidential.
"""


def test_health(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


_BANK_CHANGE = {
    "raw_message": BEC,
    "owned_domains": ["acme.com"],
    "known_counterparties": ["gemini.com"],
    "counterparty_known_bank_ids": ["GB94BARC10201530093459"],
    "counterparty_message_count": 47,
    "counterparty_phone": "+1 803 000 0000",
    "source": "imap_idle",
}


def test_analyse_flags_bank_change_critical_for_authenticated_caller(
    client: TestClient,
) -> None:
    body = client.post(
        "/api/v1/analyse", json=_BANK_CHANGE, headers=_auth_header(client)
    ).json()

    assert body["assessment"]["tier"] == "critical"
    assert "A1" in body["assessment"]["services"]
    assert body["assessment"]["requires_callback"] is True
    assert body["assessment"]["callback_phone"] == "+1 803 000 0000"
    assert body["findings"][0]["service"] is not None


def test_analyse_redacts_detection_taxonomy_for_anonymous_caller(
    client: TestClient,
) -> None:
    """PRD §16 — the public sandbox shows the outcome and severity, never the
    internal detection code, score, evidence or the service list."""
    body = client.post("/api/v1/analyse", json=_BANK_CHANGE).json()

    assert body["assessment"]["tier"] == "critical"  # outcome still visible
    assert body["assessment"]["requires_callback"] is True
    assert body["assessment"]["services"] is None  # taxonomy withheld
    for finding in body["findings"]:
        assert finding["service"] is None
        assert "evidence" not in finding
        assert "score" not in finding
        assert finding["category"]  # plain-English category is fine
        assert finding["summary"]


def test_remediable_is_derived_from_source(client: TestClient) -> None:
    """Regression: the endpoint must derive remediability from capabilities.

    IMAP can quarantine (MOVE works on any server); forwarding arrives
    post-delivery and never can (PRD §4 fn.3).
    """

    def remediable(source: str) -> bool:
        return client.post(
            "/api/v1/analyse", json={"raw_message": BEC, "source": source}
        ).json()["message"]["remediable"]

    assert remediable("imap_idle") is True
    assert remediable("graph_api") is True
    assert remediable("forward_ingest") is False
    assert remediable("journal") is False


def test_coverage_names_inactive_detections_for_authenticated_caller(
    client: TestClient,
) -> None:
    """PRD E7/P4 — inactive detections are named to the customer, never silently
    dropped. §16 keeps those names behind a session."""
    body = client.get(
        "/api/v1/coverage",
        params={"sources": "imap_idle,client_sensor"},
        headers=_auth_header(client),
    ).json()

    assert body["protection_level"] == "standard"
    # Server-side rules are unavailable over IMAP.
    assert {"C1", "C2", "C4"} <= set(body["inactive_detections"])
    assert "A1" in body["active_detections"]


def test_coverage_redacts_detection_codes_for_anonymous_caller(
    client: TestClient,
) -> None:
    """PRD §16 — anonymous callers get the protection level and counts, never the
    per-detection codes."""
    body = client.get(
        "/api/v1/coverage", params={"sources": "imap_idle,client_sensor"}
    ).json()

    assert body["protection_level"] == "standard"
    assert body["active_count"] > 0
    assert body["inactive_count"] > 0
    assert "active_detections" not in body
    assert "inactive_detections" not in body


def test_coverage_rejects_unknown_source(client: TestClient) -> None:
    assert client.get("/api/v1/coverage", params={"sources": "nonsense"}).status_code == 422


def test_domain_scan_needs_no_integration(client: TestClient) -> None:
    body = client.post("/api/v1/domains/scan", json={"domain": "gemini.com"}).json()
    assert body["protected_domain"] == "gemini.com"
    assert len(body["hits"]) > 0
    # Every hit carries a registration-date field (null here — dates are disabled
    # in the suite to stay hermetic; populated live via RDAP).
    assert all("registered_at" in h for h in body["hits"])


def test_domain_scan_sorts_registered_newest_first(client: TestClient, monkeypatch) -> None:
    """With registration dates present, hits are ordered newest-registered first,
    and undated candidates fall to the bottom."""
    from envelock.api import v1

    async def _fake_dates(domains: list[str]) -> dict[str, str | None]:
        # Give two of them dates, one older, one newer; leave the rest undated.
        out: dict[str, str | None] = dict.fromkeys(domains)
        if domains:
            out[domains[0]] = "2020-01-01T00:00:00Z"  # old
        if len(domains) > 1:
            out[domains[1]] = "2024-06-01T00:00:00Z"  # new
        return out

    from envelock.config import get_settings

    monkeypatch.setattr(v1, "_registration_dates", _fake_dates)
    monkeypatch.setattr(get_settings(), "scan_registration_dates", True)

    body = client.post("/api/v1/domains/scan", json={"domain": "gemini.com"}).json()
    dated = [h for h in body["hits"] if h["registered_at"]]
    assert len(dated) >= 2
    # Newest first among dated, and dated appear before undated.
    assert dated[0]["registered_at"] >= dated[1]["registered_at"]
    first_undated = next(
        (i for i, h in enumerate(body["hits"]) if not h["registered_at"]), len(body["hits"])
    )
    last_dated = max(
        (i for i, h in enumerate(body["hits"]) if h["registered_at"]), default=-1
    )
    assert last_dated < first_undated


def test_pricing_matches_prd_worked_examples(client: TestClient) -> None:
    five = client.post(
        "/api/v1/pricing/quote",
        json={"plan": "essential", "term": "monthly", "mail_domains": 1,
              "protected": 5, "monitored": 0},
    ).json()
    assert five["total_usd"] == 25.00

    thousand = client.post(
        "/api/v1/pricing/quote",
        json={"plan": "complete", "term": "monthly", "mail_domains": 1,
              "protected": 30, "monitored": 970},
    ).json()
    assert 430 <= thousand["total_usd"] <= 450


def test_ordinary_email_produces_no_alert(client: TestClient) -> None:
    body = client.post(
        "/api/v1/analyse",
        json={
            "raw_message": "From: <sara@gemini.com>\nTo: pay@acme.com\n"
            "Subject: Lunch\nContent-Type: text/plain\n\nThursday at 1?\n",
            "owned_domains": ["acme.com"],
            "known_counterparties": ["gemini.com"],
            "counterparty_message_count": 47,
        },
    ).json()
    assert body["assessment"] is None or not body["assessment"]["alertable"]


def test_connection_advisor_returns_a_path_for_every_domain(client: TestClient) -> None:
    """Every provider is supported. An unrecognised MX record changes the
    method, never whether we can protect the mailbox (PRD §5)."""
    body = client.get("/api/v1/domains/example.com/connect").json()

    assert body["recommended"]["steps"]
    assert body["recommended"]["protection_level"] in {"full", "standard", "limited"}
    # Forwarding is the universal fallback, so there is always a path.
    all_methods = [body["recommended"], *body["alternatives"]]
    assert any(m["id"] in {"imap", "forward"} for m in all_methods)


def test_advisor_marks_forwarding_as_alert_only(client: TestClient) -> None:
    body = client.get("/api/v1/domains/example.com/connect").json()
    for method in [body["recommended"], *body["alternatives"]]:
        if method["id"] == "forward":
            assert method["remediation"] is False


def test_provider_registry_is_exposed(client: TestClient) -> None:
    body = client.get("/api/v1/providers").json()
    names = {p["name"] for p in body["providers"]}
    assert {"Microsoft 365", "Google Workspace", "HiNet hiBox"} <= names
    assert body["count"] >= 20


def test_tenant_endpoint_returns_the_registered_domain(client: TestClient) -> None:
    """The dashboard shows the tenant's real domain, so /tenant must return it
    after bootstrap — not leave the UI guessing from a mailbox."""
    h = _auth_header(client, email="owner@globex.com")
    # Before bootstrap there is a tenant but no domain.
    empty = client.get("/api/v1/tenant", headers=h).json()
    assert empty["name"] is not None
    assert empty["primary_domain"] is None

    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Globex Inc", "domain": "globex.com"},
        headers=h,
    )
    body = client.get("/api/v1/tenant", headers=h).json()
    assert body["primary_domain"] == "globex.com"
    assert any(d["registrable_domain"] == "globex.com" for d in body["domains"])


def test_owner_can_change_plan_during_trial(client: TestClient) -> None:
    """During the signup trial an owner can pick any plan — no card required yet."""
    h = _auth_header(client, email="owner@planco-uniq.com")
    r = client.post("/api/v1/tenant/plan", json={"plan": "essential"}, headers=h)
    assert r.status_code == 200
    assert r.json()["subscribed_plan"] == "essential"
    assert client.get("/api/v1/tenant", headers=h).json()["subscribed_plan"] == "essential"


def test_change_plan_rejects_unknown_plan(client: TestClient) -> None:
    h = _auth_header(client, email="owner@planco2-uniq.com")
    r = client.post("/api/v1/tenant/plan", json={"plan": "platinum"}, headers=h)
    assert r.status_code == 422


def test_paid_upgrade_needs_trial_or_card(client: TestClient) -> None:
    """Once the trial lapses with no card, a paid plan is refused (402); Guard is
    always allowed."""
    import asyncio
    from datetime import UTC, datetime, timedelta

    from envelock.db import get_sessionmaker
    from envelock.models import Tenant

    email = "owner@planexpired-uniq.com"
    h = _auth_header(client, email=email)
    tid = client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]

    async def _expire() -> None:
        async with get_sessionmaker()() as s:
            from uuid import UUID

            t = await s.get(Tenant, UUID(tid))
            t.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
            t.payment_method_ok = False
            await s.commit()

    asyncio.run(_expire())

    refused = client.post("/api/v1/tenant/plan", json={"plan": "complete"}, headers=h)
    assert refused.status_code == 402
    # Guard (free) is always allowed.
    assert client.post("/api/v1/tenant/plan", json={"plan": "guard"}, headers=h).status_code == 200


def test_bootstrap_rejects_a_company_name_as_domain(client: TestClient) -> None:
    """A company name typed into the domain field ("Acme Corp") reduces to a
    truthy-but-bogus registrable domain. Storing it would silently break every
    domain-based lookup and the ingest token, so bootstrap must reject it."""
    h = _auth_header(client, email="owner@validco.dev")
    bad = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Valid Co", "domain": "Valid Co"},
        headers=h,
    )
    assert bad.status_code == 422

    # No garbage domain was persisted.
    assert client.get("/api/v1/tenant", headers=h).json()["primary_domain"] is None

    # The real domain still works.
    ok = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Valid Co", "domain": "validco.dev"},
        headers=h,
    )
    assert ok.status_code == 201
    assert ok.json()["domain"] == "validco.dev"


def test_imap_connect_seals_credentials_and_marks_connected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-OAuth mailbox connects over IMAP; the password is envelope-encrypted
    and the mailbox flips to connected with a real protection level."""
    import asyncio

    from sqlalchemy import select

    from envelock.channels.mail import broker
    from envelock.db import get_sessionmaker
    from envelock.models import MailboxCredential

    # No live IMAP server in the suite — stub the credential check as passing so
    # this test covers storage/connect, not the network (see test_imap_verify).
    async def _ok(**_: object) -> broker.ImapVerifyResult:
        return broker.ImapVerifyResult(True, "signed in")

    monkeypatch.setattr(broker, "verify_imap_credentials", _ok)

    h = _auth_header(client, email="admin@custommail.dev")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Custom", "domain": "custommail.dev"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ceo@custommail.dev", "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()

    out = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap",
        json={"imap_host": "imap.custommail.dev", "imap_port": 993, "password": "s3cret-app-pw"},
        headers=h,
    )
    assert out.status_code == 200
    body = out.json()
    assert "imap_idle" in body["sources"]  # Protected -> IDLE
    assert body["protection_level"] in {"full", "standard"}

    async def _read() -> MailboxCredential | None:
        async with get_sessionmaker()() as s:
            return (
                await s.execute(
                    select(MailboxCredential).order_by(MailboxCredential.created_at.desc())
                )
            ).scalars().first()

    cred = asyncio.run(_read())
    assert cred is not None and cred.kind == "imap_password"
    assert b"s3cret-app-pw" not in cred.ciphertext  # sealed, not plaintext


def test_imap_connect_honours_security_mode_and_username(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The connect form's SSL/TLS choice, custom port and login username reach the
    verifier and are stored — we don't assume 993/implicit-TLS/address-as-username."""
    import asyncio

    from sqlalchemy import select

    from envelock.channels.mail import broker
    from envelock.db import get_sessionmaker
    from envelock.models import MailboxCredential

    seen: dict = {}

    async def _capture(**kw: object) -> broker.ImapVerifyResult:
        seen.update(kw)
        return broker.ImapVerifyResult(True, "signed in")

    monkeypatch.setattr(broker, "verify_imap_credentials", _capture)

    h = _auth_header(client, email="admin@ispmail.dev")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "ISP", "domain": "ispmail.dev"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ap@ispmail.dev", "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()

    out = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap",
        json={
            "imap_host": "mail.ispmail.dev",
            "imap_port": 143,
            "security": "starttls",
            "username": "ap.login",
            "password": "app-pw",
        },
        headers=h,
    )
    assert out.status_code == 200
    # The verifier saw the chosen transport + explicit username, not defaults.
    assert seen["security"] == "starttls" and seen["port"] == 143
    assert seen["username"] == "ap.login"

    async def _read() -> MailboxCredential | None:
        async with get_sessionmaker()() as s:
            return (
                await s.execute(
                    select(MailboxCredential).order_by(MailboxCredential.created_at.desc())
                )
            ).scalars().first()

    cred = asyncio.run(_read())
    assert cred is not None
    assert cred.imap_security == "starttls" and cred.imap_port == 143
    assert cred.imap_username == "ap.login"


def test_imap_test_endpoint_verifies_without_storing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 'Test connection' button verifies the settings but stores nothing."""
    import asyncio

    from sqlalchemy import func, select

    from envelock.channels.mail import broker
    from envelock.db import get_sessionmaker
    from envelock.models import MailboxCredential

    async def _reject(**_: object) -> broker.ImapVerifyResult:
        return broker.ImapVerifyResult(False, "the server rejected the password")

    monkeypatch.setattr(broker, "verify_imap_credentials", _reject)

    h = _auth_header(client, email="admin@testconn.dev")
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": "TC", "domain": "testconn.dev"}, headers=h
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "cfo@testconn.dev", "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()

    r = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap/test",
        json={"imap_host": "imap.testconn.dev", "imap_port": 993, "password": "x"},
        headers=h,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False and "rejected" in r.json()["reason"]

    async def _cred_count() -> int:
        async with get_sessionmaker()() as s:
            return int(
                (await s.execute(select(func.count()).select_from(MailboxCredential))).scalar_one()
            )

    assert asyncio.run(_cred_count()) == 0  # nothing persisted by a test


def test_remove_mailbox(client: TestClient) -> None:
    h = _auth_header(client, email="admin@removeco.dev")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "RemoveCo", "domain": "removeco.dev"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "x@removeco.dev", "mailbox_class": "monitored", "sources": []},
        headers=h,
    ).json()
    assert client.delete(f"/api/v1/mailboxes/{mb['id']}", headers=h).status_code == 200
    remaining = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
    assert all(m["id"] != mb["id"] for m in remaining)


def test_tenant_reports_trial_state(client: TestClient) -> None:
    h = _auth_header(client, email="owner@trialco.dev")
    body = client.get("/api/v1/tenant", headers=h).json()
    # Signup now starts a trial on the top plan from minute one (issue 1).
    assert body["plan"] == "complete"
    assert body["trial"]["active"] is True
    assert body["trial"]["days_left"] is not None and body["trial"]["days_left"] > 0
