"""Tier-1 OAuth connection flows for Microsoft 365 and Google Workspace.

The provider hosts and the connection advisor were already built; this is the
consent-and-token-exchange that actually completes a Tier-1 sign-up (PRD §17.1).

Two design choices keep it honest:

* **One interface, thin providers.** `OAuthProvider` defines authorization-URL
  construction and code exchange; Microsoft and Google are ~10 lines each. A new
  Tier-1 provider is a new implementation, never a branch in the flow.
* **Injectable transport.** The network call sits behind a `Transport` callable so
  the flow is unit-tested against a fake, while production passes a real httpx
  client. Nothing here needs live credentials to *build* — only to *run*.

The `state` parameter is HMAC-signed and binds the tenant, mailbox and provider
so a callback cannot be forged or replayed across contexts (CSRF).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode

from envelock.config import get_settings


class OAuthError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class OAuthTokens:
    access_token: str
    refresh_token: str | None
    expires_in: int
    scope: str | None
    raw: dict


# ── Signed state (CSRF / replay protection) ──────────────────────────────────
_STATE_TTL = 600  # 10 minutes to complete consent


def issue_state(*, tenant_id: str, mailbox: str, provider: str) -> str:
    payload = {
        "t": tenant_id,
        "m": mailbox,
        "p": provider,
        "n": secrets.token_urlsafe(8),
        "exp": int(time.time()) + _STATE_TTL,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(_secret(), raw, hashlib.sha256).digest()
    return f"{_b64(raw)}.{_b64(sig)}"


def verify_state(state: str, *, provider: str) -> dict:
    try:
        raw_b64, sig_b64 = state.split(".")
        raw = _unb64(raw_b64)
        sig = _unb64(sig_b64)
    except (ValueError, TypeError) as exc:
        raise OAuthError("malformed state") from exc
    if not hmac.compare_digest(hmac.new(_secret(), raw, hashlib.sha256).digest(), sig):
        raise OAuthError("bad state signature")
    data = json.loads(raw)
    if data.get("exp", 0) < int(time.time()):
        raise OAuthError("state expired")
    if data.get("p") != provider:
        raise OAuthError("state/provider mismatch")
    return data


def _secret() -> bytes:
    key = get_settings().secret_key.get_secret_value()
    if not key:
        raise OAuthError("no secret key configured for state signing")
    return key.encode()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ── Transport (injectable for tests) ─────────────────────────────────────────
class Transport(Protocol):
    async def post_form(self, url: str, data: dict) -> dict: ...


class HttpxTransport:
    """Default transport — a real token-endpoint POST."""

    async def post_form(self, url: str, data: dict) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                data=data,
                headers={"Accept": "application/json"},
            )
        if resp.status_code >= 400:
            raise OAuthError(
                f"token endpoint returned {resp.status_code}: {resp.text[:200]}"
            )
        return resp.json()


# ── Providers ────────────────────────────────────────────────────────────────
class OAuthProvider(Protocol):
    id: str
    authorize_endpoint: str
    token_endpoint: str
    scopes: tuple[str, ...]

    def client_id(self) -> str | None: ...
    def client_secret(self) -> str | None: ...
    def redirect_uri(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class _Microsoft:
    id: str = "microsoft"
    authorize_endpoint: str = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    token_endpoint: str = "https://login.microsoftonline.com/common/oauth2/v2.0/token"  # noqa: S105 — an OAuth endpoint URL, not a secret
    #: Graph mail read + audit, with a refresh token for background sync.
    scopes: tuple[str, ...] = (
        "offline_access",
        "https://graph.microsoft.com/Mail.Read",
        "https://graph.microsoft.com/MailboxSettings.Read",
        "https://graph.microsoft.com/AuditLog.Read.All",
    )

    def client_id(self) -> str | None:
        return get_settings().ms_client_id

    def client_secret(self) -> str | None:
        s = get_settings().ms_client_secret
        return s.get_secret_value() if s else None

    def redirect_uri(self) -> str | None:
        return get_settings().ms_redirect_uri


@dataclass(frozen=True, slots=True)
class _Google:
    id: str = "google"
    authorize_endpoint: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: str = "https://oauth2.googleapis.com/token"  # noqa: S105 — an OAuth endpoint URL, not a secret
    scopes: tuple[str, ...] = (
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    )

    def client_id(self) -> str | None:
        return get_settings().google_client_id

    def client_secret(self) -> str | None:
        s = get_settings().google_client_secret
        return s.get_secret_value() if s else None

    def redirect_uri(self) -> str | None:
        return get_settings().google_redirect_uri


_PROVIDERS: dict[str, OAuthProvider] = {p.id: p for p in (_Microsoft(), _Google())}

#: Test seam. Production leaves this None and a real httpx POST is used; tests set
#: a fake so the flow runs end to end without a live provider.
_DEFAULT_TRANSPORT: Transport | None = None


def set_default_transport(transport: Transport | None) -> None:
    global _DEFAULT_TRANSPORT
    _DEFAULT_TRANSPORT = transport


def provider_for(name: str) -> OAuthProvider | None:
    return _PROVIDERS.get(name.lower())


def is_configured(provider: OAuthProvider) -> bool:
    return bool(provider.client_id() and provider.client_secret() and provider.redirect_uri())


def configured_providers() -> list[str]:
    return [pid for pid, p in _PROVIDERS.items() if is_configured(p)]


# ── Flow ─────────────────────────────────────────────────────────────────────
def authorization_url(provider: OAuthProvider, *, state: str) -> str:
    """The URL the admin's browser is redirected to for tenant consent."""
    if not is_configured(provider):
        raise OAuthError(
            f"{provider.id} OAuth is not configured — set its client id, secret "
            "and redirect URI in the environment"
        )
    params = {
        "client_id": provider.client_id(),
        "response_type": "code",
        "redirect_uri": provider.redirect_uri(),
        "response_mode": "query",
        "scope": " ".join(provider.scopes),
        "state": state,
        # Force a refresh token on Google; Microsoft returns one with offline_access.
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{provider.authorize_endpoint}?{urlencode(params)}"


async def exchange_code(
    provider: OAuthProvider,
    *,
    code: str,
    transport: Transport | None = None,
) -> OAuthTokens:
    """Exchange the authorization code for access + refresh tokens."""
    if not is_configured(provider):
        raise OAuthError(f"{provider.id} OAuth is not configured")
    transport = transport or _DEFAULT_TRANSPORT or HttpxTransport()
    data = {
        "client_id": provider.client_id(),
        "client_secret": provider.client_secret(),
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": provider.redirect_uri(),
    }
    body = await transport.post_form(provider.token_endpoint, data)
    if "access_token" not in body:
        raise OAuthError(f"token exchange returned no access_token: {body!r}")
    return OAuthTokens(
        access_token=body["access_token"],
        refresh_token=body.get("refresh_token"),
        expires_in=int(body.get("expires_in", 3600)),
        scope=body.get("scope"),
        raw=body,
    )
