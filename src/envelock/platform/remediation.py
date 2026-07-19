"""E2 — quarantine and claw-back.

IMAP `MOVE` works on a 1998 server, so Tier 3 can quarantine even though Tier 4
never can — the forwarded copy arrives after delivery (PRD §4 fn.3). That
asymmetry is enforced by the capability model, not by convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from envelock.core.capabilities import Capability
from envelock.core.enums import SourceMechanism

QUARANTINE_FOLDER = "Envelock Quarantine"


class RemediationAction(StrEnum):
    QUARANTINE = "quarantine"
    RESTORE = "restore"
    REWRITE_LINKS = "rewrite_links"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class RemediationResult:
    action: RemediationAction
    succeeded: bool
    reason: str
    message_id: UUID | None = None
    performed_at: datetime | None = None

    @property
    def alert_only(self) -> bool:
        return not self.succeeded and "post-delivery" in self.reason


def can_remediate(capabilities: frozenset[Capability]) -> bool:
    return Capability.MODIFY_MESSAGE in capabilities


def plan_remediation(
    *,
    action: RemediationAction,
    capabilities: frozenset[Capability],
    source: SourceMechanism,
    message_id: UUID | None = None,
) -> RemediationResult:
    """Decide before promising anything in an alert."""
    if source in (SourceMechanism.FORWARD_INGEST, SourceMechanism.JOURNAL):
        return RemediationResult(
            action=action,
            succeeded=False,
            reason=(
                "This mailbox is connected by forwarding, so the copy reaches us "
                "post-delivery — we can alert, but not remove the message. "
                "A direct connection enables quarantine."
            ),
            message_id=message_id,
        )
    if not can_remediate(capabilities):
        return RemediationResult(
            action=action,
            succeeded=False,
            reason="This connection has no write access to the mailbox.",
            message_id=message_id,
        )
    return RemediationResult(
        action=action,
        succeeded=True,
        reason=f"Message moved to '{QUARANTINE_FOLDER}'.",
        message_id=message_id,
        performed_at=datetime.now(UTC),
    )


def imap_commands(action: RemediationAction, uid: int) -> list[str]:
    """The literal IMAP exchange, so the broker and the tests agree."""
    if action is RemediationAction.QUARANTINE:
        return [f'UID MOVE {uid} "{QUARANTINE_FOLDER}"']
    if action is RemediationAction.RESTORE:
        return [f'UID MOVE {uid} "INBOX"']
    if action is RemediationAction.DELETE:
        return [f"UID STORE {uid} +FLAGS (\\Deleted)", "EXPUNGE"]
    return []


def graph_operation(action: RemediationAction, message_id: str) -> dict:
    """Microsoft Graph equivalent."""
    if action is RemediationAction.QUARANTINE:
        return {
            "method": "POST",
            "path": f"/messages/{message_id}/move",
            "body": {"destinationId": QUARANTINE_FOLDER},
        }
    if action is RemediationAction.RESTORE:
        return {
            "method": "POST",
            "path": f"/messages/{message_id}/move",
            "body": {"destinationId": "inbox"},
        }
    return {"method": "DELETE", "path": f"/messages/{message_id}"}
