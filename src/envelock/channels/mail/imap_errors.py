"""Turn a raw IMAP/socket/TLS failure into something a customer can act on.

"Could not reach the IMAP server" was the single biggest source of stuck
connections: it is the same message for a typo'd hostname, a blocked port, a
TLS-mode mismatch, a provider that has switched basic auth off, and a password
that is simply wrong — four completely different fixes. This module classifies
the failure and returns the fix, not just the symptom.

Pure functions over exception/`str` input so the whole table is unit-testable
without a live server.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from enum import StrEnum


class ImapErrorCode(StrEnum):
    """Machine-readable failure reason. The client keys its remediation UI off
    this, so it must stay stable."""

    OK = "ok"
    DNS_NOT_FOUND = "dns_not_found"
    CONNECTION_REFUSED = "connection_refused"
    TIMEOUT = "timeout"
    NETWORK_UNREACHABLE = "network_unreachable"
    TLS_ERROR = "tls_error"
    CERTIFICATE_ERROR = "certificate_error"
    STARTTLS_UNSUPPORTED = "starttls_unsupported"
    NOT_AN_IMAP_SERVER = "not_an_imap_server"
    AUTH_FAILED = "auth_failed"
    APP_PASSWORD_REQUIRED = "app_password_required"  # noqa: S105 — an error code, not a secret
    OAUTH_REQUIRED = "oauth_required"
    IMAP_DISABLED = "imap_disabled"
    RATE_LIMITED = "rate_limited"
    BLOCKED_HOST = "blocked_host"
    MAILBOX_MISSING = "mailbox_missing"
    UNKNOWN = "unknown"


#: Failures where the server answered and told us the credential is wrong. There
#: is no point trying the next candidate host with the same password — we have
#: found the right server, so stop probing and report the real problem.
TERMINAL_CODES = frozenset(
    {
        ImapErrorCode.AUTH_FAILED,
        ImapErrorCode.APP_PASSWORD_REQUIRED,
        ImapErrorCode.OAUTH_REQUIRED,
        ImapErrorCode.IMAP_DISABLED,
        ImapErrorCode.RATE_LIMITED,
        ImapErrorCode.BLOCKED_HOST,
    }
)


@dataclass(frozen=True, slots=True)
class ImapFailure:
    code: ImapErrorCode
    #: One sentence naming what went wrong, in the customer's language.
    message: str
    #: What to do about it. Empty when the message is already the action.
    hint: str = ""
    #: The raw provider text, kept for support/debugging. Never contains the
    #: password (IMAP servers echo the tag and status, not the credential).
    detail: str = ""

    @property
    def terminal(self) -> bool:
        return self.code in TERMINAL_CODES

    def as_dict(self) -> dict:
        return {
            "code": self.code.value,
            "message": self.message,
            "hint": self.hint,
            "detail": self.detail[:400],
        }

    @property
    def reason(self) -> str:
        """Single-line form for logs and legacy callers."""
        return f"{self.message} {self.hint}".strip()


# ── Provider-specific auth remediation ───────────────────────────────────────
# Matching on the host we actually dialled is what lets us say "Gmail needs an
# app password" instead of a generic "check your password".

_APP_PASSWORD_HOSTS: tuple[tuple[str, str, str], ...] = (
    (
        "imap.gmail.com",
        "Google rejected the sign-in.",
        "Gmail does not accept your normal password over IMAP. Turn on 2-Step "
        "Verification, create an App password at "
        "myaccount.google.com/apppasswords, and paste that 16-character password "
        "here — or use the one-click Google connection instead.",
    ),
    (
        "imap.mail.yahoo.com",
        "Yahoo rejected the sign-in.",
        "Yahoo requires an app password: Account Security → Generate app password.",
    ),
    (
        "imap.aol.com",
        "AOL rejected the sign-in.",
        "AOL requires an app password generated from Account Security.",
    ),
    (
        "imap.mail.me.com",
        "iCloud rejected the sign-in.",
        "iCloud Mail requires an app-specific password from appleid.apple.com.",
    ),
    (
        "imap.zoho",
        "Zoho rejected the sign-in.",
        "Zoho needs an application-specific password (Zoho Account → Security → "
        "App Passwords), and IMAP access must be enabled in Zoho Mail settings.",
    ),
    (
        "imap.yandex",
        "Yandex rejected the sign-in.",
        "Yandex requires an app password and IMAP enabled in Mail settings.",
    ),
    (
        "imap.qq.com",
        "QQ Mail rejected the sign-in.",
        "QQ/Tencent mail uses an authorisation code, not your login password — "
        "generate one in Settings → Account → IMAP/SMTP service.",
    ),
    (
        "163.com",
        "NetEase rejected the sign-in.",
        "163/126 mail uses a client authorisation code, not your login password.",
    ),
)

_MICROSOFT_HOSTS = ("outlook.office365.com", "outlook.office.com", "imap-mail.outlook.com")

_MICROSOFT_HINT = (
    "Microsoft switched off password (basic) authentication for IMAP. Connect "
    "this mailbox with the one-click Microsoft 365 button instead — that uses "
    "OAuth, which Microsoft still supports."
)

# Server text that means "your credential is fine, but IMAP itself is off".
_DISABLED_PATTERNS = (
    "imap access is disabled",
    "imap is disabled",
    "not enabled for imap",
    "imap access not enabled",
    "service not enabled",
    "web login required",
)

#: Text that means "this server will not take a password at all". Deliberately
#: narrow: RFC 5530's `[AUTHENTICATIONFAILED]` and a bare "AUTHENTICATE failed"
#: are what every server says for a simply-wrong password, so matching those
#: would send people chasing OAuth when they just mistyped an app password.
#: Microsoft's blanket basic-auth removal is caught by host instead, above.
_OAUTH_PATTERNS = (
    "basic authentication is disabled",
    "basic auth is disabled",
    "modern auth",
    "oauth",
    "xoauth",
)

_RATE_PATTERNS = (
    "too many",
    "try again later",
    "temporarily",
    "throttl",
    "exceeded the limit",
    "unusual activity",
)


def _unbytes(text: str) -> str:
    """`imaplib` stringifies its errors as `b'...'`; show the message, not the repr."""
    stripped = (text or "").strip()
    if len(stripped) > 3 and stripped[:2] in ("b'", 'b"') and stripped[-1] == stripped[1]:
        return stripped[2:-1]
    return stripped


def classify_login_failure(text: str, *, host: str) -> ImapFailure:
    """The server was reached and rejected the LOGIN. Say why, specifically."""
    raw = _unbytes(text)
    lowered = raw.lower()
    host_l = (host or "").lower()

    if any(p in lowered for p in _DISABLED_PATTERNS):
        return ImapFailure(
            ImapErrorCode.IMAP_DISABLED,
            "The mail server says IMAP access is turned off for this mailbox.",
            "Enable IMAP in the mailbox's own settings (or ask your mail "
            "administrator to enable it), then try again.",
            raw,
        )

    if any(h in host_l for h in _MICROSOFT_HOSTS):
        return ImapFailure(
            ImapErrorCode.OAUTH_REQUIRED,
            "Microsoft rejected the password sign-in.",
            _MICROSOFT_HINT,
            raw,
        )

    for needle, message, hint in _APP_PASSWORD_HOSTS:
        if needle in host_l:
            return ImapFailure(ImapErrorCode.APP_PASSWORD_REQUIRED, message, hint, raw)

    if any(p in lowered for p in _RATE_PATTERNS):
        return ImapFailure(
            ImapErrorCode.RATE_LIMITED,
            "The mail server is temporarily refusing sign-ins from us.",
            "This is usually a rate limit after several failed attempts. Wait a "
            "few minutes and try once more.",
            raw,
        )

    if any(p in lowered for p in _OAUTH_PATTERNS):
        return ImapFailure(
            ImapErrorCode.OAUTH_REQUIRED,
            "The mail server refused password authentication.",
            "This provider requires OAuth or an app-specific password rather "
            "than the normal mailbox password.",
            raw,
        )

    return ImapFailure(
        ImapErrorCode.AUTH_FAILED,
        "The mail server rejected the username or password.",
        "Check the username (it is often the full email address) and use an "
        "app-specific password if your provider issues one.",
        raw,
    )


_HOSTNAME_MISMATCH = re.compile(r"hostname .* doesn't match|certificate verify failed", re.I)


def classify_connect_failure(
    exc: BaseException, *, host: str, port: int, security: str
) -> ImapFailure:
    """Anything that stopped us before the LOGIN got an answer."""
    raw = f"{type(exc).__name__}: {exc}".strip()

    if isinstance(exc, socket.gaierror):
        return ImapFailure(
            ImapErrorCode.DNS_NOT_FOUND,
            f"No mail server found at “{host}”.",
            "Check the server name for typos — most providers use "
            "imap.yourprovider.com or mail.yourdomain.com. Use “Find my "
            "settings” to detect it automatically.",
            raw,
        )

    if isinstance(exc, ssl.SSLCertVerificationError) or _HOSTNAME_MISMATCH.search(raw):
        return ImapFailure(
            ImapErrorCode.CERTIFICATE_ERROR,
            f"“{host}” presented a TLS certificate we could not verify.",
            "The certificate does not match this hostname. Use the exact server "
            "name your provider documents (often the provider's own host, not "
            "your domain).",
            raw,
        )

    if isinstance(exc, ssl.SSLError):
        other = "STARTTLS on port 143" if security == "ssl" else "SSL/TLS on port 993"
        return ImapFailure(
            ImapErrorCode.TLS_ERROR,
            f"The TLS handshake with “{host}:{port}” failed.",
            f"The security setting probably does not match the port. Try {other}.",
            raw,
        )

    if isinstance(exc, TimeoutError | socket.timeout):
        return ImapFailure(
            ImapErrorCode.TIMEOUT,
            f"“{host}:{port}” did not answer in time.",
            "The port is usually blocked by a firewall, or the server name is "
            "wrong. IMAP normally listens on 993 (SSL/TLS) or 143 (STARTTLS).",
            raw,
        )

    if isinstance(exc, ConnectionRefusedError):
        return ImapFailure(
            ImapErrorCode.CONNECTION_REFUSED,
            f"“{host}” refused the connection on port {port}.",
            "The server is reachable but nothing is listening on that port. Try "
            "993 with SSL/TLS, or 143 with STARTTLS.",
            raw,
        )

    if isinstance(exc, OSError) and getattr(exc, "errno", None) in {51, 101, 113, 65}:
        return ImapFailure(
            ImapErrorCode.NETWORK_UNREACHABLE,
            f"“{host}” is unreachable from our network.",
            "Check the server name, and allow our connections through any "
            "firewall or IP allowlist on the mail server.",
            raw,
        )

    lowered = raw.lower()
    if "starttls" in lowered:
        return ImapFailure(
            ImapErrorCode.STARTTLS_UNSUPPORTED,
            f"“{host}:{port}” does not support STARTTLS.",
            "Switch the security setting to SSL/TLS on port 993.",
            raw,
        )

    if "bye" in lowered or "unexpected" in lowered or "not an imap" in lowered:
        return ImapFailure(
            ImapErrorCode.NOT_AN_IMAP_SERVER,
            f"“{host}:{port}” answered, but not as an IMAP server.",
            "That port is probably running something else. IMAP is normally 993 "
            "(SSL/TLS) or 143 (STARTTLS).",
            raw,
        )

    return ImapFailure(
        ImapErrorCode.UNKNOWN,
        f"Could not connect to “{host}:{port}”.",
        "Check the server, port and the SSL/TLS setting with your mail provider.",
        raw,
    )


__all__ = [
    "ImapErrorCode",
    "ImapFailure",
    "TERMINAL_CODES",
    "classify_connect_failure",
    "classify_login_failure",
]
