"""API surface, exercised the way the frontend uses it."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from envelock.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


BEC = """From: "Gemini Accounts" <billing@gemini.com>
To: pay@acme.com.ng
Subject: Re: Invoice 4471
In-Reply-To: <old@gemini.com>
Content-Type: text/plain

Our bank account has changed. Remit to IBAN GB33BUKB20201555555555.
This is urgent, we need it today. Please keep this confidential.
"""


def test_health(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


def test_analyse_flags_bank_change_critical(client: TestClient) -> None:
    body = client.post(
        "/api/v1/analyse",
        json={
            "raw_message": BEC,
            "owned_domains": ["acme.com.ng"],
            "known_counterparties": ["gemini.com"],
            "counterparty_known_bank_ids": ["GB94BARC10201530093459"],
            "counterparty_message_count": 47,
            "counterparty_phone": "+234 803 000 0000",
            "source": "imap_idle",
        },
    ).json()

    assert body["assessment"]["tier"] == "critical"
    assert "A1" in body["assessment"]["services"]
    assert body["assessment"]["requires_callback"] is True
    assert body["assessment"]["callback_phone"] == "+234 803 000 0000"


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


def test_coverage_names_inactive_detections(client: TestClient) -> None:
    """PRD E7/P4 — inactive detections are named, never silently dropped."""
    body = client.get(
        "/api/v1/coverage", params={"sources": "imap_idle,client_sensor"}
    ).json()

    assert body["protection_level"] == "standard"
    # Server-side rules are unavailable over IMAP.
    assert {"C1", "C2", "C4"} <= set(body["inactive_detections"])
    assert "A1" in body["active_detections"]


def test_coverage_rejects_unknown_source(client: TestClient) -> None:
    assert client.get("/api/v1/coverage", params={"sources": "nonsense"}).status_code == 422


def test_domain_scan_needs_no_integration(client: TestClient) -> None:
    body = client.post("/api/v1/domains/scan", json={"domain": "gemini.com"}).json()
    assert body["protected_domain"] == "gemini.com"
    assert len(body["hits"]) > 0


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
            "raw_message": "From: <sara@gemini.com>\nTo: pay@acme.com.ng\n"
            "Subject: Lunch\nContent-Type: text/plain\n\nThursday at 1?\n",
            "owned_domains": ["acme.com.ng"],
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
