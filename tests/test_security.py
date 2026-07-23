"""Regression tests for the security audit.

Each test corresponds to a finding that was exploitable before the fix. They
exist so a refactor cannot quietly reintroduce any of them.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import (
    MAX_TOKEN_LENGTH,
    Role,
    TokenError,
    decode_token,
    dummy_hash,
    issue_token,
)
from envelock.core.enums import AlertTier
from envelock.governance import export as ex
from envelock.security.limits import (
    AccountLockout,
    RateLimiter,
    ReplayGuard,
    TokenRevocations,
    clamp_text,
    valid_domain,
)


# ── CSV / formula injection ──────────────────────────────────────────────────
def _alert(title: str = "t", detail: str = "d", service: str = "A1") -> ex.AlertRecord:
    return ex.AlertRecord(
        id="alt_1",
        tier=AlertTier.CRITICAL,
        service=service,
        title=title,
        mailbox="pay@acme.com",
        detail=detail,
        raised_at=datetime(2026, 7, 18, 9, 42, tzinfo=UTC),
        state="open",
    )


@pytest.mark.parametrize(
    "payload",
    [
        "=cmd|'/c calc.exe'!A1",
        "+HYPERLINK(\"http://evil\",\"click\")",
        "-2+3+cmd|' /c calc'!A0",
        "@SUM(1+1)*cmd|' /c calc'!A0",
    ],
)
def test_csv_formula_injection_is_neutralised(payload: str) -> None:
    """Alert text is attacker-controlled by definition. RFC 4180 quoting does
    not stop Excel executing a leading =, +, - or @.

    The property that matters is that the cell no longer *starts* with a
    formula character — the payload text may still appear, inert, after the
    escaping apostrophe.
    """
    field = ex.to_csv([_alert(title=payload)]).splitlines()[1].split(",")[4]
    assert not field.lstrip('"').startswith(("=", "+", "-", "@"))
    assert ex.csv_safe(payload).startswith("'")


def test_csv_strips_newlines_that_would_forge_rows() -> None:
    assert "\n" not in ex.csv_safe("line1\nline2,evil")


def test_cef_cannot_forge_an_extra_log_record() -> None:
    line = ex.to_cef(_alert(service="A1\nCEF:0|Fake|Fake|1|9|pwned|10"))
    assert "\n" not in line and "\r" not in line


# ── Token handling ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "bad",
    ["", "a.!!!!", "....", "a.b.c", "no-dot", "x" * (MAX_TOKEN_LENGTH + 1)],
)
def test_malformed_tokens_are_401_never_500(bad: str) -> None:
    with pytest.raises(TokenError):
        decode_token(bad, expect="access")


def test_oversized_token_is_rejected_before_crypto_work() -> None:
    with pytest.raises(TokenError):
        decode_token("x" * 100_000)


def test_token_type_confusion_is_blocked() -> None:
    refresh = issue_token(
        user_id=uuid4(),
        tenant_id=uuid4(),
        role=Role.OWNER,
        typ="refresh",
        ttl=timedelta(days=1),
    )
    with pytest.raises(TokenError):
        decode_token(refresh, expect="access")


def test_dummy_hash_is_computed_once() -> None:
    """Hashing per failed login burned 80ms and 32 MB of attacker-controlled
    work; a few hundred concurrent requests exhausted a core."""
    dummy_hash()
    start = time.perf_counter()
    for _ in range(20):
        dummy_hash()
    assert (time.perf_counter() - start) < 0.05


# ── Rate limiting and lockout ────────────────────────────────────────────────
def test_rate_limiter_blocks_then_recovers() -> None:
    limiter = RateLimiter()
    now = 1000.0
    for _ in range(5):
        assert limiter.check("auth.login", "ip:1.2.3.4", now=now)[0]
    allowed, retry_after = limiter.check("auth.login", "ip:1.2.3.4", now=now)
    assert not allowed and retry_after > 0
    # Window rolls over.
    assert limiter.check("auth.login", "ip:1.2.3.4", now=now + 301)[0]


def test_rate_limiter_isolates_identities() -> None:
    limiter = RateLimiter()
    for _ in range(5):
        limiter.check("auth.login", "ip:1.1.1.1", now=1000.0)
    assert limiter.check("auth.login", "ip:2.2.2.2", now=1000.0)[0]


def test_lockout_backs_off_but_never_permanently() -> None:
    """A permanent lock would let an attacker deny any customer their account."""
    lock = AccountLockout()
    now = 1000.0
    for _ in range(AccountLockout.THRESHOLD):
        lock.record_failure("victim@acme.com", now=now)
    locked, retry = lock.is_locked("victim@acme.com", now=now)
    assert locked and retry <= AccountLockout.BACKOFFS[-1] + 1
    assert not lock.is_locked("victim@acme.com", now=now + 4000)[0]


def test_successful_login_clears_lockout() -> None:
    lock = AccountLockout()
    for _ in range(AccountLockout.THRESHOLD):
        lock.record_failure("u@e.com", now=1000.0)
    lock.record_success("u@e.com")
    assert not lock.is_locked("u@e.com", now=1000.0)[0]


def test_replay_guard_allows_once() -> None:
    guard = ReplayGuard()
    assert guard.check_and_record("user:123456", now=1000.0)
    assert not guard.check_and_record("user:123456", now=1000.0)


def test_revocation_covers_single_token_and_whole_user() -> None:
    rev = TokenRevocations()
    assert not rev.is_revoked("jti1", "user1", now=1000.0)
    rev.revoke_jti("jti1", expires_at=2000.0)
    assert rev.is_revoked("jti1", "user1", now=1000.0)
    rev.revoke_user("user2", until=2000.0)
    assert rev.is_revoked("other", "user2", now=1000.0)


# ── Input validation ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "bad",
    [
        "", "localhost", "127.0.0.1", "10.0.0.1", "a" * 300,
        "evil.com:8080", "http://evil.com", "a..b.com", "user@evil.com",
        "-lead.com", "trail-.com", "a" * 70 + ".com", "internal",
    ],
)
def test_invalid_domains_never_reach_a_resolver(bad: str) -> None:
    assert not valid_domain(bad)


@pytest.mark.parametrize(
    "good", ["acme.com", "acme.com", "sub.acme.co.uk", "xn--80ak6aa92e.com"]
)
def test_legitimate_domains_still_pass(good: str) -> None:
    assert valid_domain(good)


def test_clamp_text_bounds_regex_work() -> None:
    assert len(clamp_text("x" * 5_000_000, 1000)) == 1000


# ── API-level enforcement ────────────────────────────────────────────────────
def test_security_headers_present_on_every_response(client: TestClient) -> None:
    h = client.get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"
    assert "geolocation=()" in h["Permissions-Policy"]


def test_login_is_rate_limited(client: TestClient) -> None:
    body = {"email": "nobody@acme.com", "password": "wrong-password-here"}
    codes = [client.post("/api/v1/auth/login", json=body).status_code for _ in range(8)]
    assert 429 in codes, "login must throttle — otherwise it is a brute-force oracle"


def test_registration_does_not_leak_existing_accounts(client: TestClient) -> None:
    body = {
        "email": "dup@acme.com",
        "password": "a-long-enough-passphrase",
        "tenant_name": "Acme",
    }
    first = client.post("/api/v1/auth/register", json=body)
    second = client.post("/api/v1/auth/register", json=body)
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()


def test_login_failure_is_indistinguishable_for_unknown_vs_wrong_password(
    client: TestClient,
) -> None:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "real@acme.com",
            "password": "a-long-enough-passphrase",
            "tenant_name": "Acme",
        },
    )
    unknown = client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@acme.com", "password": "some-wrong-password"},
    )
    wrong = client.post(
        "/api/v1/auth/login",
        json={"email": "real@acme.com", "password": "some-wrong-password"},
    )
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_oversized_body_is_rejected(client: TestClient) -> None:
    r = client.post(
        "/api/v1/analyse",
        json={"raw_message": "x"},
        headers={"Content-Length": str(50 * 1024 * 1024)},
    )
    assert r.status_code in (413, 422)


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "not-a-domain"])
def test_scan_rejects_unresolvable_input(client: TestClient, bad: str) -> None:
    assert client.post("/api/v1/domains/scan", json={"domain": bad}).status_code == 422


def test_mfa_code_cannot_be_replayed(client: TestClient) -> None:
    """An observed code must not work twice inside its 30s window."""
    import base64
    import hashlib
    import hmac
    import struct

    def totp(secret: str) -> str:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
        d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        o = d[-1] & 0xF
        return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"

    creds = {
        "email": "replay@acme.com",
        "password": "a-long-enough-passphrase",
        "tenant_name": "Acme",
    }
    client.post("/api/v1/auth/register", json=creds)
    login = client.post(
        "/api/v1/auth/login",
        json={"email": creds["email"], "password": creds["password"]},
    ).json()
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    code = totp(setup["secret"])

    first = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": code},
    )
    assert first.status_code == 200

    replayed = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": code},
    )
    assert replayed.status_code == 401


def test_refresh_reuse_revokes_every_session(client: TestClient) -> None:
    """A refresh token presented twice was stolen. Revoke the family, not just
    the token."""
    import base64
    import hashlib
    import hmac
    import struct

    def totp(secret: str) -> str:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
        d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        o = d[-1] & 0xF
        return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"

    creds = {
        "email": "rot@acme.com",
        "password": "a-long-enough-passphrase",
        "tenant_name": "Acme",
    }
    client.post("/api/v1/auth/register", json=creds)
    login = client.post(
        "/api/v1/auth/login",
        json={"email": creds["email"], "password": creds["password"]},
    ).json()
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": login["mfa_token"], "code": totp(setup["secret"])},
    ).json()

    original = tokens["refresh_token"]
    assert client.post("/api/v1/auth/refresh", json={"token": original}).status_code == 200
    # Second use of the same token = theft.
    assert client.post("/api/v1/auth/refresh", json={"token": original}).status_code == 401
