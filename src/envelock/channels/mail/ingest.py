"""Tier 4 forwarding ingest — an SMTP listener that accepts forwarded copies.

Every mail system supports forwarding, so this is the path that makes coverage
universal. The address is per-tenant (`t-<token>@in.envelock.io`) so a message
identifies its tenant without any credential.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from uuid import UUID

from envelock.config import get_settings

_TENANT_RE = re.compile(r"^t-([A-Za-z0-9_-]{8,})@", re.I)


def ingest_address(token: str) -> str:
    return f"t-{token}@{get_settings().ingest_domain}"


def new_ingest_token() -> str:
    return secrets.token_urlsafe(12)


def tenant_token_from(recipient: str) -> str | None:
    match = _TENANT_RE.match(recipient.strip())
    return match.group(1) if match else None


@dataclass(frozen=True, slots=True)
class IngestResult:
    accepted: bool
    reason: str
    tenant_token: str | None = None
    size_bytes: int = 0


#: Refuse anything larger than this at RCPT time rather than buffering it.
MAX_MESSAGE_BYTES = 30 * 1024 * 1024


class ForwardingIngest:
    """Transport-agnostic core so it is testable without binding a socket."""

    def __init__(self, *, resolve_tenant, on_message) -> None:  # noqa: ANN001
        self._resolve_tenant = resolve_tenant
        self._on_message = on_message

    async def handle_rcpt(self, recipient: str) -> IngestResult:
        token = tenant_token_from(recipient)
        if token is None:
            return IngestResult(False, "550 unknown recipient")
        tenant_id = await self._resolve_tenant(token)
        if tenant_id is None:
            return IngestResult(False, "550 unknown recipient")
        return IngestResult(True, "250 OK", tenant_token=token)

    async def handle_data(self, *, recipient: str, raw: bytes) -> IngestResult:
        if len(raw) > MAX_MESSAGE_BYTES:
            return IngestResult(False, "552 message too large", size_bytes=len(raw))

        token = tenant_token_from(recipient)
        if token is None:
            return IngestResult(False, "550 unknown recipient")
        tenant_id: UUID | None = await self._resolve_tenant(token)
        if tenant_id is None:
            return IngestResult(False, "550 unknown recipient")

        await self._on_message(tenant_id=tenant_id, raw=raw)
        return IngestResult(True, "250 Message accepted", tenant_token=token, size_bytes=len(raw))


def onboarding_instructions(token: str) -> dict:
    """Shown in the connect flow. The allowlist step matters: an external
    forwarding rule is exactly what C1 flags as Critical, so our own onboarding
    would otherwise trip our own detection (PRD §5.4)."""
    address = ingest_address(token)
    return {
        "ingest_address": address,
        "steps": [
            f"Create a rule that forwards a copy of inbound mail to {address}.",
            "Keep delivering to the original mailbox — this is a copy, not a redirect.",
            f"Allowlist {address} in your gateway or DLP.",
            "Install the browser extension or Outlook add-in for session monitoring.",
        ],
        "warning": (
            "We flag external forwarding rules as Critical by default. This one "
            "is allowlisted automatically so your own setup does not alert you."
        ),
        "limitation": (
            "Forwarded copies arrive after delivery, so we alert but cannot "
            "quarantine. A direct connection enables quarantine."
        ),
    }
