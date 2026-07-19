"""RFC822 → `MailEvent`.

Used by forwarding ingest (Tier 4) and the IMAP broker (Tier 3). Graph and Gmail
map their own payloads onto the same model — that is the point of the normaliser.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from uuid import UUID

from envelock.core.enums import AuthResult, MailDirection, SourceMechanism
from envelock.core.events import (
    AttachmentRef,
    AuthenticationResults,
    EmailAddress,
    MailEvent,
)
from envelock.util.domains import registrable_domain

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".cab")

_AUTH_MAP = {
    "pass": AuthResult.PASS,
    "fail": AuthResult.FAIL,
    "softfail": AuthResult.SOFTFAIL,
    "neutral": AuthResult.NEUTRAL,
    "none": AuthResult.NONE,
    "temperror": AuthResult.TEMPERROR,
    "permerror": AuthResult.PERMERROR,
}


def _address(raw: str | None) -> EmailAddress | None:
    if not raw:
        return None
    pairs = getaddresses([raw])
    if not pairs:
        return None
    display, addr = pairs[0]
    if not addr:
        return None
    return EmailAddress(address=addr.strip().lower(), display=display.strip() or None)


def _addresses(raw: str | None) -> tuple[EmailAddress, ...]:
    if not raw:
        return ()
    out = []
    for display, addr in getaddresses([raw]):
        if addr:
            out.append(
                EmailAddress(address=addr.strip().lower(), display=display.strip() or None)
            )
    return tuple(out)


def _parse_auth_results(msg: EmailMessage) -> AuthenticationResults:
    header = " ".join(msg.get_all("Authentication-Results", []))
    if not header:
        return AuthenticationResults()

    def find(mech: str) -> AuthResult:
        match = re.search(rf"\b{mech}=(\w+)", header, re.IGNORECASE)
        return _AUTH_MAP.get(match.group(1).lower(), AuthResult.NONE) if match else AuthResult.NONE

    dkim_domain: str | None = None
    domain_match = re.search(r"header\.d=([A-Za-z0-9.\-]+)", header)
    if domain_match:
        dkim_domain = domain_match.group(1).lower()

    return AuthenticationResults(
        spf=find("spf"), dkim=find("dkim"), dmarc=find("dmarc"), dkim_domain=dkim_domain
    )


def _bodies(msg: EmailMessage) -> tuple[str | None, str | None]:
    text = html = None
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text" or part.get_filename():
                continue
            try:
                content = part.get_content()
            except (LookupError, ValueError):
                continue
            if part.get_content_subtype() == "plain" and text is None:
                text = content
            elif part.get_content_subtype() == "html" and html is None:
                html = content
    else:
        try:
            content = msg.get_content()
        except (LookupError, ValueError):
            content = None
        if msg.get_content_subtype() == "html":
            html = content
        else:
            text = content
    return text, html


def _attachments(msg: EmailMessage) -> tuple[AttachmentRef, ...]:
    refs: list[AttachmentRef] = []
    if not msg.is_multipart():
        return ()
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        name = filename.lower()
        refs.append(
            AttachmentRef(
                filename=filename,
                # Layer 0 of the cascade is a consequence of the schema: hashing
                # here makes the shared cross-tenant verdict cache automatic.
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                declared_mime=part.get_content_type(),
                detected_mime=_sniff(payload),
                is_archive=name.endswith(_ARCHIVE_EXT),
            )
        )
    return tuple(refs)


def _sniff(payload: bytes) -> str | None:
    """Magic bytes. A mismatch with the declared type is itself a signal (B6)."""
    if payload.startswith(b"%PDF"):
        return "application/pdf"
    if payload.startswith(b"PK\x03\x04"):
        return "application/zip"
    if payload.startswith(b"\xd0\xcf\x11\xe0"):
        return "application/vnd.ms-office"
    if payload.startswith((b"\xff\xd8\xff", b"\x89PNG")):
        return "image"
    if payload.startswith(b"MZ"):
        return "application/x-dosexec"
    if payload[:4] == b"Rar!":
        return "application/x-rar"
    return None


def parse_message(
    raw: bytes,
    *,
    tenant_id: UUID,
    mailbox_id: UUID,
    source: SourceMechanism,
    owned_domains: frozenset[str] = frozenset(),
    remediable: bool = False,
    source_ref: str | None = None,
) -> MailEvent:
    msg: EmailMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]

    sender = _address(msg.get("From")) or EmailAddress(address="unknown@invalid")
    text, html = _bodies(msg)

    sent_at: datetime | None = None
    if date_header := msg.get("Date"):
        try:
            sent_at = parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            sent_at = None

    sender_domain = registrable_domain(sender.domain)
    direction = (
        MailDirection.OUTBOUND if sender_domain in owned_domains else MailDirection.INBOUND
    )

    references = tuple(msg.get("References", "").split()) if msg.get("References") else ()
    urls = tuple(dict.fromkeys(_URL_RE.findall(f"{text or ''} {html or ''}")))

    now = datetime.now(UTC)
    return MailEvent(
        tenant_id=tenant_id,
        mailbox_id=mailbox_id,
        occurred_at=sent_at or now,
        ingested_at=now,
        source=source,
        source_ref=source_ref or msg.get("Message-ID"),
        direction=direction,
        rfc_message_id=msg.get("Message-ID"),
        in_reply_to=msg.get("In-Reply-To"),
        references=references,
        sender=sender,
        reply_to=_address(msg.get("Reply-To")),
        return_path=_address(msg.get("Return-Path")),
        recipients_to=_addresses(msg.get("To")),
        recipients_cc=_addresses(msg.get("Cc")),
        subject=msg.get("Subject"),
        sent_at=sent_at,
        body_text=text,
        body_html=html,
        attachments=_attachments(msg),
        urls=urls,
        authentication=_parse_auth_results(msg),
        received_headers=tuple(msg.get_all("Received", [])),
        # Forwarding arrives post-delivery: nothing can be quarantined no matter
        # what we detect (PRD §4 fn.3).
        remediable=remediable
        and source not in (SourceMechanism.FORWARD_INGEST, SourceMechanism.JOURNAL),
    )
