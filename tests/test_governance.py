"""PRD §15 — auth, retention, export and detection quality."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import (
    Role,
    TokenError,
    _totp_at,
    decode_token,
    hash_password,
    issue_token,
    role_at_least,
    verify_password,
    verify_totp,
)
from envelock.core.enums import AlertTier
from envelock.governance import export as ex
from envelock.governance import quality, retention
from envelock.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Enter the app lifespan so the SQLite schema is bootstrapped — accounts are
    # now persisted, so the users table must exist before any auth call.
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


# ── §15.1 Auth ───────────────────────────────────────────────────────────────
def test_password_hash_roundtrip() -> None:
    stored = hash_password("correct horse battery")
    assert verify_password("correct horse battery", stored)
    assert not verify_password("wrong horse battery", stored)


def test_short_passwords_rejected() -> None:
    with pytest.raises(ValueError):
        hash_password("short")


def test_password_hashes_are_salted() -> None:
    assert hash_password("same password 12") != hash_password("same password 12")


def test_totp_accepts_drift_but_not_wrong_codes() -> None:
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # noqa: S105 — TOTP seed, not a password
    now = int(time.time())
    counter = now // 30
    assert verify_totp(secret, _totp_at(secret, counter), now=now)
    # ±1 step for clock drift
    assert verify_totp(secret, _totp_at(secret, counter - 1), now=now)
    # but not further
    assert not verify_totp(secret, _totp_at(secret, counter - 5), now=now)
    assert not verify_totp(secret, "000000", now=now)


def test_token_tamper_is_rejected() -> None:
    from uuid import uuid4

    token = issue_token(
        user_id=uuid4(),
        tenant_id=uuid4(),
        role=Role.MEMBER,
        typ="access",
        ttl=__import__("datetime").timedelta(minutes=5),
    )
    payload, sig = token.split(".")
    with pytest.raises(TokenError):
        decode_token(f"{payload}x.{sig}", expect="access")


def test_role_hierarchy() -> None:
    assert role_at_least(Role.OWNER, Role.ADMIN)
    assert role_at_least(Role.ADMIN, Role.MEMBER)
    assert not role_at_least(Role.MEMBER, Role.ADMIN)


def test_mfa_is_mandatory_before_a_session_exists(client: TestClient) -> None:
    """A security product cannot hand out sessions without MFA."""
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "owner@acme.com",
            "password": "a-long-enough-passphrase",
            "tenant_name": "Acme",
        },
    )
    body = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@acme.com", "password": "a-long-enough-passphrase"},
    ).json()

    assert body["mfa_setup_required"] is True
    # No access token is issued at this stage.
    assert "access_token" not in body


def test_full_login_flow_issues_tokens_and_recovery_codes(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "owner@acme.com",
            "password": "a-long-enough-passphrase",
            "tenant_name": "Acme",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@acme.com", "password": "a-long-enough-passphrase"},
    ).json()

    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    code = _totp_at(setup["secret"], int(time.time()) // 30)

    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": code},
    ).json()

    assert tokens["access_token"]
    assert tokens["role"] == "owner"
    assert len(tokens["recovery_codes"]) == 10

    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    ).json()
    assert me["email"] == "owner@acme.com"
    assert me["mfa_enabled"] is True


def test_registered_account_is_persisted_to_the_database(client: TestClient) -> None:
    """The account store is the database, not process memory — a registered user
    and its owning tenant must be durable rows (PRD §15.1, §17.1)."""
    import asyncio

    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.models import Tenant, User

    client.post(
        "/api/v1/auth/register",
        json={
            "email": "durable@acme.com",
            "password": "a-long-enough-passphrase",
            "tenant_name": "Durable Co",
        },
    )

    async def _read() -> tuple[User | None, Tenant | None]:
        async with get_sessionmaker()() as s:
            user = (
                await s.execute(select(User).where(User.email == "durable@acme.com"))
            ).scalar_one_or_none()
            tenant = (
                await s.execute(select(Tenant).where(Tenant.name == "Durable Co"))
            ).scalar_one_or_none()
            return user, tenant

    user, tenant = asyncio.run(_read())
    assert user is not None, "the account must be a persisted row"
    assert user.role == "owner"
    assert user.password_hash and user.password_hash.startswith("scrypt$")
    assert tenant is not None and user.tenant_id == tenant.id


def test_protected_routes_reject_anonymous(client: TestClient) -> None:
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/export/alerts.csv").status_code == 401


def test_member_cannot_reach_admin_routes(client: TestClient) -> None:
    from uuid import uuid4

    member = issue_token(
        user_id=uuid4(),
        tenant_id=uuid4(),
        role=Role.MEMBER,
        typ="access",
        ttl=__import__("datetime").timedelta(minutes=5),
    )
    r = client.get(
        "/api/v1/export/alerts.csv", headers={"Authorization": f"Bearer {member}"}
    )
    assert r.status_code == 403


def test_refresh_token_cannot_be_used_as_access(client: TestClient) -> None:
    from uuid import uuid4

    refresh = issue_token(
        user_id=uuid4(),
        tenant_id=uuid4(),
        role=Role.OWNER,
        typ="refresh",
        ttl=__import__("datetime").timedelta(days=1),
    )
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401


# ── §15.2 Retention ──────────────────────────────────────────────────────────
def test_every_data_class_has_a_policy() -> None:
    for data_class in retention.DataClass:
        assert retention.policy_for(data_class).rationale


def test_bodies_expire_before_metadata() -> None:
    body = retention.policy_for(retention.DataClass.MESSAGE_BODY).days
    meta = retention.policy_for(retention.DataClass.MESSAGE_METADATA).days
    assert body is not None and meta is not None and body < meta


def test_trial_ledger_survives_tenant_deletion() -> None:
    """Permanence IS the anti-abuse mechanism (§12.7)."""
    policy = retention.policy_for(retention.DataClass.TRIAL_LEDGER)
    assert policy.days is None
    assert policy.survives_tenant_deletion


def test_metadata_only_mode_skips_content_classes() -> None:
    purge = retention.classes_to_purge(metadata_only=True)
    assert retention.DataClass.MESSAGE_BODY not in purge
    assert retention.DataClass.MESSAGE_METADATA in purge


def test_deletion_plan_separates_deleted_from_retained() -> None:
    from datetime import UTC, datetime

    plan = retention.deletion_plan(closed_at=datetime(2026, 1, 1, tzinfo=UTC))
    retained = {r["data_class"] for r in plan["retained"]}
    deleted = {d["data_class"] for d in plan["deleted"]}
    assert "trial_ledger" in retained
    assert "message_body" in deleted
    assert not retained & deleted


def test_retention_schedule_is_public(client: TestClient) -> None:
    body = client.get("/api/v1/retention/schedule").json()
    assert len(body["schedule"]) == len(retention.DataClass)
    assert body["churn"]["deletion_deadline_days"] == 60


# ── §15.3 Export ─────────────────────────────────────────────────────────────
def _alert() -> ex.AlertRecord:
    from datetime import UTC, datetime

    return ex.AlertRecord(
        id="alt_1",
        tier=AlertTier.CRITICAL,
        service="A1",
        title="Payment details changed",
        mailbox="pay@acme.com",
        detail="Invoice 4471 | new IBAN",
        raised_at=datetime(2026, 7, 18, 9, 42, tzinfo=UTC),
        state="open",
    )


def test_webhook_signature_verifies() -> None:
    secret = ex.generate_webhook_secret()
    payload = json.dumps({"hello": "world"}).encode()
    sig, ts = ex.sign_payload(secret, payload)
    assert ex.verify_signature(secret, payload, sig, ts)


def test_webhook_signature_rejects_tampering_and_replay() -> None:
    secret = ex.generate_webhook_secret()
    payload = json.dumps({"amount": 100}).encode()
    sig, ts = ex.sign_payload(secret, payload)

    assert not ex.verify_signature(secret, b'{"amount": 999}', sig, ts)
    assert not ex.verify_signature("whsec_other", payload, sig, ts)
    # Replayed an hour later, outside tolerance
    assert not ex.verify_signature(secret, payload, sig, ts, now=ts + 3600)


def test_retry_schedule_terminates() -> None:
    assert ex.next_retry_delay(0) == 0
    assert ex.next_retry_delay(len(ex.RETRY_SCHEDULE)) is None


def test_cef_escapes_pipes_and_maps_severity() -> None:
    line = ex.to_cef(_alert())
    assert line.startswith("CEF:0|Envelock|Envelock|")
    assert "|10|" in line  # critical
    assert "cs2=critical" in line


def test_syslog_priority_reflects_tier() -> None:
    assert ex.to_syslog(_alert()).startswith("<106>1 ")  # facility 13, severity 2


def test_csv_has_header_and_row() -> None:
    out = ex.to_csv([_alert()])
    lines = out.strip().splitlines()
    assert lines[0].startswith("id,raised_at,tier,detection")
    assert "alt_1" in lines[1]


def test_export_tokens_are_read_only() -> None:
    plaintext, record = ex.issue_api_token(frozenset({ex.Scope.ALERTS_READ}))
    assert plaintext.startswith("envk_")
    assert ex.verify_api_token(plaintext, record)
    assert not ex.verify_api_token("envk_wrong", record)


# ── §15.4 Detection quality ──────────────────────────────────────────────────
def test_targets_are_defined_for_every_metric() -> None:
    for t in quality.TARGETS:
        assert t.rationale
        assert t.target > 0


def test_critical_fp_target_is_one_percent() -> None:
    t = quality.target("critical_fp_rate")
    assert t.target == 0.01
    assert t.meets(0.005)
    assert not t.meets(0.02)


def test_evaluate_flags_a_noisy_critical_detection() -> None:
    noisy = quality.evaluate(
        [quality.Confusion(service="A1", true_positive=80, false_positive=20)]
    )
    assert not noisy["all_targets_met"]

    clean = quality.evaluate(
        [quality.Confusion(service="A1", true_positive=1000, false_positive=5)]
    )
    assert clean["all_targets_met"]


def test_recall_counts_misses_not_just_alerts() -> None:
    c = quality.Confusion(service="A1", true_positive=90, false_negative=10)
    assert c.recall == 0.9
    assert not quality.target("a1_recall").meets(c.recall)


def test_critical_false_positive_requires_postmortem() -> None:
    assert quality.requires_postmortem("A1", "critical", was_false_positive=True)
    assert not quality.requires_postmortem("A7", "medium", was_false_positive=True)
    assert not quality.requires_postmortem("A1", "critical", was_false_positive=False)


def test_quality_targets_endpoint(client: TestClient) -> None:
    body = client.get("/api/v1/quality/targets").json()
    ids = {t["id"] for t in body["targets"]}
    assert {"critical_fp_rate", "a1_recall", "detonation_fallthrough"} <= ids
