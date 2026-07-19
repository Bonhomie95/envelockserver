"""Export and SIEM integration (PRD §15.3).

Alerts are worth more inside the tools a security team already watches. This is
also a retention feature — a customer piping us into Sentinel does not churn
casually.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from envelock.core.enums import AlertTier

# ── Webhooks ─────────────────────────────────────────────────────────────────

WEBHOOK_SIGNATURE_HEADER = "X-Envelock-Signature"
WEBHOOK_TIMESTAMP_HEADER = "X-Envelock-Timestamp"
#: Reject signatures older than this to blunt replay attacks.
WEBHOOK_TOLERANCE_SECONDS = 300

#: Exponential backoff, in seconds. Deliberately spans ~4 hours so a receiver
#: can survive a deploy without losing alerts.
RETRY_SCHEDULE: tuple[int, ...] = (0, 30, 120, 600, 1800, 7200, 14400)


def generate_webhook_secret() -> str:
    return f"whsec_{secrets.token_urlsafe(32)}"


def sign_payload(secret: str, payload: bytes, *, timestamp: int | None = None) -> tuple[str, int]:
    """Signature covers the timestamp too, so a captured body cannot be replayed
    later with a fresh header."""
    ts = timestamp if timestamp is not None else int(datetime.now(UTC).timestamp())
    signed = f"{ts}.".encode() + payload
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"v1={digest}", ts


def verify_signature(
    secret: str,
    payload: bytes,
    signature: str,
    timestamp: int,
    *,
    now: int | None = None,
    tolerance: int = WEBHOOK_TOLERANCE_SECONDS,
) -> bool:
    """Reference implementation — publish this in the docs so customers can
    verify our deliveries without guessing."""
    current = now if now is not None else int(datetime.now(UTC).timestamp())
    if abs(current - timestamp) > tolerance:
        return False
    expected, _ = sign_payload(secret, payload, timestamp=timestamp)
    return hmac.compare_digest(expected, signature)


class WebhookEvent(StrEnum):
    ALERT_RAISED = "alert.raised"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    MAILBOX_CONNECTED = "mailbox.connected"
    MAILBOX_COVERAGE_CHANGED = "mailbox.coverage_changed"
    LOOKALIKE_DETECTED = "lookalike.detected"


def webhook_envelope(event: WebhookEvent, tenant_id: str, data: dict) -> dict:
    return {
        "id": f"evt_{secrets.token_urlsafe(16)}",
        "type": event.value,
        "created_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "data": data,
    }


def next_retry_delay(attempt: int) -> int | None:
    """`None` means give up and surface a delivery failure in the dashboard."""
    return RETRY_SCHEDULE[attempt] if attempt < len(RETRY_SCHEDULE) else None


# ── Syslog / CEF ─────────────────────────────────────────────────────────────

_CEF_SEVERITY = {
    AlertTier.LOW: 3,
    AlertTier.MEDIUM: 5,
    AlertTier.HIGH: 8,
    AlertTier.CRITICAL: 10,
}

_SYSLOG_SEVERITY = {
    AlertTier.LOW: 6,  # informational
    AlertTier.MEDIUM: 4,  # warning
    AlertTier.HIGH: 3,  # error
    AlertTier.CRITICAL: 2,  # critical
}


def _cef_escape(value: str, *, extension: bool = False) -> str:
    out = value.replace("\\", "\\\\")
    out = out.replace("=", "\\=") if extension else out.replace("|", "\\|")
    return out.replace("\n", " ").replace("\r", " ")


@dataclass(frozen=True, slots=True)
class AlertRecord:
    """The shape every export path consumes."""

    id: str
    tier: AlertTier
    service: str
    title: str
    mailbox: str
    detail: str
    raised_at: datetime
    state: str
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None


def to_cef(alert: AlertRecord, *, product_version: str = "1.0.0") -> str:
    """ArcSight CEF — also accepted by Splunk, QRadar and Sentinel."""
    header = "|".join(
        [
            "CEF:0",
            "Envelock",
            "Envelock",
            product_version,
            _cef_escape(alert.service),
            _cef_escape(alert.title),
            str(_CEF_SEVERITY[alert.tier]),
        ]
    )
    extensions = {
        "externalId": alert.id,
        "rt": int(alert.raised_at.timestamp() * 1000),
        "duser": alert.mailbox,
        "cs1Label": "detection",
        "cs1": alert.service,
        "cs2Label": "tier",
        "cs2": alert.tier.value,
        "cs3Label": "state",
        "cs3": alert.state,
        "msg": alert.detail,
    }
    body = " ".join(f"{k}={_cef_escape(str(v), extension=True)}" for k, v in extensions.items())
    return f"{header}|{body}"


def to_syslog(alert: AlertRecord, *, hostname: str = "envelock", facility: int = 13) -> str:
    """RFC 5424 with the CEF message as the payload."""
    priority = facility * 8 + _SYSLOG_SEVERITY[alert.tier]
    stamp = alert.raised_at.astimezone(UTC).isoformat()
    return f"<{priority}>1 {stamp} {hostname} envelock - {alert.service} - {to_cef(alert)}"


def to_json_line(alert: AlertRecord) -> str:
    """JSONL for anything that ingests structured logs directly."""
    return json.dumps(
        {
            "id": alert.id,
            "tier": alert.tier.value,
            "detection": alert.service,
            "title": alert.title,
            "mailbox": alert.mailbox,
            "detail": alert.detail,
            "raised_at": alert.raised_at.astimezone(UTC).isoformat(),
            "state": alert.state,
            "acknowledged_at": alert.acknowledged_at.astimezone(UTC).isoformat()
            if alert.acknowledged_at
            else None,
            "acknowledged_by": alert.acknowledged_by,
        },
        separators=(",", ":"),
    )


# ── CSV ──────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = (
    "id",
    "raised_at",
    "tier",
    "detection",
    "title",
    "mailbox",
    "detail",
    "state",
    "acknowledged_at",
    "acknowledged_by",
)


def to_csv(alerts: list[AlertRecord]) -> str:
    """What auditors actually ask for."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for a in alerts:
        writer.writerow(
            [
                a.id,
                a.raised_at.astimezone(UTC).isoformat(),
                a.tier.value,
                a.service,
                a.title,
                a.mailbox,
                a.detail,
                a.state,
                a.acknowledged_at.astimezone(UTC).isoformat() if a.acknowledged_at else "",
                a.acknowledged_by or "",
            ]
        )
    return buffer.getvalue()


# ── Scoped API tokens ────────────────────────────────────────────────────────


class Scope(StrEnum):
    ALERTS_READ = "alerts:read"
    FINDINGS_READ = "findings:read"
    MAILBOXES_READ = "mailboxes:read"
    AUDIT_READ = "audit:read"


#: Export tokens are read-only by design. A SIEM integration never needs write
#: access, and a leaked read token is a far smaller incident.
ALL_SCOPES = frozenset(Scope)


@dataclass(frozen=True, slots=True)
class ApiToken:
    prefix: str
    hashed: str
    scopes: frozenset[Scope]


def issue_api_token(scopes: frozenset[Scope]) -> tuple[str, ApiToken]:
    """Returns (plaintext_shown_once, stored_record)."""
    if not scopes <= ALL_SCOPES:
        raise ValueError("export tokens are read-only")
    raw = secrets.token_urlsafe(32)
    prefix = raw[:8]
    plaintext = f"envk_{raw}"
    return plaintext, ApiToken(
        prefix=prefix,
        hashed=hashlib.sha256(plaintext.encode()).hexdigest(),
        scopes=scopes,
    )


def verify_api_token(plaintext: str, stored: ApiToken) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(plaintext.encode()).hexdigest(), stored.hashed
    )
