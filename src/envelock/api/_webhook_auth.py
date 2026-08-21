"""Authenticate provider push callbacks.

Graph and Gmail push endpoints cannot carry a customer's bearer token — the
caller is Microsoft or Google, not the customer's browser. Before this, that
meant they carried *nothing*: anyone could POST a mailbox address and make us
sync it, across any tenant. Two mechanisms fix that without a round-trip:

* **Graph** — the subscription we create carries a `clientState` we choose. We
  put an HMAC over `tenant|mailbox` in it, so a notification proves it belongs
  to a subscription we made, and names exactly which mailbox it may touch.
* **Gmail Pub/Sub** — the push URL is registered by us and can carry a `?token=`
  query parameter that Google echoes on every delivery. We compare it in
  constant time.

Both derive from `ENVELOCK_WEBHOOK_SHARED_SECRET` (falling back to the app
secret key), so there is nothing extra to provision for a working deployment.
"""

from __future__ import annotations

import hashlib
import hmac
from uuid import UUID

from envelock.config import get_settings


def _secret() -> bytes:
    settings = get_settings()
    raw = settings.webhook_shared_secret or settings.secret_key
    return raw.get_secret_value().encode()


def _sign(message: str) -> str:
    return hmac.new(_secret(), message.encode(), hashlib.sha256).hexdigest()[:32]


def client_state(*, tenant_id: UUID | str, mailbox: str) -> str:
    """The `clientState` to register with a Graph subscription."""
    mailbox = mailbox.strip().lower()
    body = f"{tenant_id}|{mailbox}"
    return f"{body}|{_sign(body)}"


def verify_client_state(value: str | None) -> tuple[UUID, str] | None:
    """`(tenant_id, mailbox)` if this notification came from our subscription."""
    if not value:
        return None
    parts = value.split("|")
    if len(parts) != 3:
        return None
    tenant_raw, mailbox, signature = parts
    if not hmac.compare_digest(_sign(f"{tenant_raw}|{mailbox}"), signature):
        return None
    try:
        return UUID(tenant_raw), mailbox
    except ValueError:
        return None


def push_token() -> str:
    """The `?token=` value to append to a Gmail Pub/Sub push endpoint URL."""
    return _sign("gmail-push")


def verify_push_token(value: str | None) -> bool:
    return bool(value) and hmac.compare_digest(str(value), push_token())


__all__ = [
    "client_state",
    "push_token",
    "verify_client_state",
    "verify_push_token",
]
