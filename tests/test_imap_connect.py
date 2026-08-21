"""The IMAP connection path: discovery, the fallback ladder, error classification
and the SSRF guard.

These cover the failure modes that actually stop a customer connecting — a
hostname that is nearly right, a TLS mode that does not match the port, a
provider that has switched password auth off — rather than only the happy path.
"""

from __future__ import annotations

import socket
import ssl
import time

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import _totp_at
from envelock.channels.mail import imap_probe
from envelock.channels.mail.imap_discovery import (
    Candidate,
    conventional_candidates,
    parse_autoconfig,
)
from envelock.channels.mail.imap_errors import (
    ImapErrorCode,
    classify_connect_failure,
    classify_login_failure,
)


# ── Error classification ─────────────────────────────────────────────────────
def test_a_typo_in_the_hostname_is_named_as_such() -> None:
    failure = classify_connect_failure(
        socket.gaierror(8, "nodename nor servname provided"),
        host="imap.acme-typo.example",
        port=993,
        security="ssl",
    )
    assert failure.code is ImapErrorCode.DNS_NOT_FOUND
    assert "imap.acme-typo.example" in failure.message
    assert not failure.terminal  # keep trying other candidates


def test_a_tls_mismatch_suggests_the_other_port() -> None:
    failure = classify_connect_failure(
        ssl.SSLError("WRONG_VERSION_NUMBER"), host="mail.acme.test", port=993, security="ssl"
    )
    assert failure.code is ImapErrorCode.TLS_ERROR
    assert "143" in failure.hint  # "try STARTTLS on port 143"


def test_a_blocked_port_reads_as_a_firewall_not_a_bad_password() -> None:
    failure = classify_connect_failure(
        TimeoutError(), host="mail.acme.test", port=993, security="ssl"
    )
    assert failure.code is ImapErrorCode.TIMEOUT
    assert "firewall" in failure.hint


def test_gmail_auth_failure_asks_for_an_app_password() -> None:
    failure = classify_login_failure(
        "[AUTHENTICATIONFAILED] Invalid credentials", host="imap.gmail.com"
    )
    assert failure.code is ImapErrorCode.APP_PASSWORD_REQUIRED
    assert "App password" in failure.hint
    assert failure.terminal  # the host is right; more hosts cannot help


def test_microsoft_auth_failure_points_at_oauth() -> None:
    """Microsoft has switched basic auth off for IMAP, so "check your password"
    is actively misleading — the fix is the OAuth button."""
    failure = classify_login_failure("AUTHENTICATE failed.", host="outlook.office365.com")
    assert failure.code is ImapErrorCode.OAUTH_REQUIRED
    assert "OAuth" in failure.hint


def test_imap_switched_off_is_distinguished_from_a_wrong_password() -> None:
    failure = classify_login_failure(
        "NO IMAP access is disabled for this user", host="mail.acme.test"
    )
    assert failure.code is ImapErrorCode.IMAP_DISABLED


def test_the_imaplib_bytes_repr_is_not_shown_to_the_customer() -> None:
    failure = classify_login_failure("b'LOGIN failed'", host="mail.acme.test")
    assert failure.detail == "LOGIN failed"


# ── Discovery ────────────────────────────────────────────────────────────────
AUTOCONFIG_XML = """<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="acme.test">
    <incomingServer type="pop3"><hostname>pop.acme.test</hostname><port>995</port>
      <socketType>SSL</socketType></incomingServer>
    <incomingServer type="imap">
      <hostname>mailbox.acme.test</hostname><port>993</port><socketType>SSL</socketType>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mailbox.acme.test</hostname><port>143</port><socketType>STARTTLS</socketType>
    </incomingServer>
  </emailProvider>
</clientConfig>"""


def test_autoconfig_yields_imap_servers_only() -> None:
    found = parse_autoconfig(AUTOCONFIG_XML)
    assert [(c.host, c.port, c.security) for c in found] == [
        ("mailbox.acme.test", 993, "ssl"),
        ("mailbox.acme.test", 143, "starttls"),
    ]


def test_conventional_candidates_cover_both_tls_modes() -> None:
    found = conventional_candidates("acme.test", ["mx1.acme.test"])
    pairs = {(c.host, c.port, c.security) for c in found}
    assert ("imap.acme.test", 993, "ssl") in pairs
    assert ("mail.acme.test", 993, "ssl") in pairs
    # The 993/143 mismatch is the commonest misconfiguration, so both are tried.
    assert ("imap.acme.test", 143, "starttls") in pairs


def test_discovery_never_proposes_a_non_imap_port() -> None:
    found = conventional_candidates("acme.test", ["mx1.acme.test"])
    assert all(c.port in (143, 993) for c in found)


# ── SSRF guard ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1", "192.168.1.1"],
)
def test_internal_targets_are_refused(host: str) -> None:
    """The host comes from a customer form; without this the connect test is a
    port scanner pointed at our own network and the cloud metadata service."""
    failure = imap_probe.check_host_allowed(host, 993)
    assert failure is not None
    assert failure.code in (ImapErrorCode.BLOCKED_HOST, ImapErrorCode.DNS_NOT_FOUND)


def test_a_non_imap_port_is_refused_before_any_socket_is_opened() -> None:
    failure = imap_probe.check_host_allowed("example.com", 5432)
    assert failure is not None and failure.code is ImapErrorCode.BLOCKED_HOST


# ── The fallback ladder ──────────────────────────────────────────────────────
#: Any non-empty string; the socket layer is stubbed in these tests.
PW = "not-a-real-password"  # noqa: S105


def _cand(host: str, port: int = 993, security: str = "ssl") -> Candidate:
    return Candidate(host, port, security, "test", 10)


def test_the_ladder_falls_through_transport_failures_to_a_working_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tried: list[str] = []

    def _login(candidate, *, username, **_):  # noqa: ANN001, ANN202
        tried.append(f"{candidate.host}:{candidate.port}")
        if candidate.host != "mail.acme.test":
            return imap_probe.Attempt(
                candidate,
                username,
                ok=False,
                failure=classify_connect_failure(
                    socket.gaierror(8, "not found"),
                    host=candidate.host,
                    port=candidate.port,
                    security=candidate.security,
                ),
            )
        return imap_probe.Attempt(candidate, username, ok=True)

    monkeypatch.setattr(imap_probe, "try_login", _login)
    result = imap_probe.probe_sync(
        [_cand("imap.acme.test"), _cand("mail.acme.test")],
        email="cfo@acme.test",
        password=PW,
    )
    assert result.ok
    assert result.candidate is not None and result.candidate.host == "mail.acme.test"
    assert tried == ["imap.acme.test:993", "mail.acme.test:993"]


def test_the_ladder_stops_at_a_credential_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once a server says the app password is wrong, dialling four more hosts
    with it only risks the provider's lockout."""
    tried: list[str] = []

    def _login(candidate, *, username, **_):  # noqa: ANN001, ANN202
        tried.append(candidate.host)
        return imap_probe.Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_login_failure("Invalid credentials", host="imap.gmail.com"),
        )

    monkeypatch.setattr(imap_probe, "try_login", _login)
    result = imap_probe.probe_sync(
        [_cand("imap.gmail.com"), _cand("mail.gmail.com")],
        email="cfo@acme.test",
        password=PW,
    )
    assert not result.ok
    assert result.failure is not None and result.failure.terminal
    assert tried == ["imap.gmail.com"]


def test_a_plain_auth_failure_retries_the_local_part_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some servers want `cfo`, not `cfo@acme.test` — indistinguishable from a
    wrong password unless we try both."""
    seen: list[str] = []

    def _login(candidate, *, username, **_):  # noqa: ANN001, ANN202
        seen.append(username)
        if username == "cfo":
            return imap_probe.Attempt(candidate, username, ok=True)
        return imap_probe.Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_login_failure("LOGIN failed", host=candidate.host),
        )

    monkeypatch.setattr(imap_probe, "try_login", _login)
    result = imap_probe.probe_sync(
        [_cand("mail.acme.test")], email="cfo@acme.test", password=PW
    )
    assert result.ok and result.username == "cfo"
    assert seen == ["cfo@acme.test", "cfo"]


def test_xoauth2_initial_response_is_the_documented_sasl_shape() -> None:
    import base64

    raw = base64.b64decode(imap_probe.xoauth2_string("a@b.test", "tok")).decode()
    assert raw == "user=a@b.test\x01auth=Bearer tok\x01\x01"


# ── End to end through the API ───────────────────────────────────────────────
def _session(client: TestClient, email: str, domain: str) -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": domain},
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


def test_connect_stores_the_settings_that_actually_worked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The customer typed 993/SSL; the server only answers STARTTLS on 143. We
    connect anyway and persist what worked, rather than failing on their typo."""
    import asyncio

    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.models import MailboxCredential

    def _login(candidate, *, username, **_):  # noqa: ANN001, ANN202
        if candidate.port == 143 and candidate.security == "starttls":
            return imap_probe.Attempt(candidate, username, ok=True)
        return imap_probe.Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_connect_failure(
                ConnectionRefusedError(),
                host=candidate.host,
                port=candidate.port,
                security=candidate.security,
            ),
        )

    monkeypatch.setattr(imap_probe, "try_login", _login)

    h = _session(client, "it@ladder.example", "ladder.example")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Ladder", "domain": "ladder.example"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "cfo@ladder.example", "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()

    out = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap",
        json={"imap_host": "mail.ladder.example", "imap_port": 993, "password": "app-pw"},
        headers=h,
    )
    assert out.status_code == 200, out.text
    assert out.json()["imap"]["port"] == 143
    assert out.json()["imap"]["security"] == "starttls"

    async def _stored() -> MailboxCredential:
        async with get_sessionmaker()() as s:
            return (
                await s.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mb["id"])
                )
            ).scalar_one()

    cred = asyncio.run(_stored())
    assert (cred.imap_port, cred.imap_security) == (143, "starttls")


def test_connect_refuses_an_internal_host(client: TestClient) -> None:
    h = _session(client, "it@ssrf.example", "ssrf.example")
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": "S", "domain": "ssrf.example"}, headers=h
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "cfo@ssrf.example", "mailbox_class": "monitored", "sources": []},
        headers=h,
    ).json()
    r = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap/test",
        json={
            "imap_host": "127.0.0.1",
            "imap_port": 993,
            "password": "x",
            "autodiscover": False,
        },
        headers=h,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["error"]["code"] == "blocked_host"
