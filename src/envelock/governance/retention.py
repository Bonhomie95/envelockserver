"""Data retention and deletion (PRD §15.2).

Every regulated buyer asks this in the first call, so the schedule is code rather
than prose — the purge job and the customer-facing report both read from here,
which stops the policy and the practice from drifting apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class DataClass(StrEnum):
    MESSAGE_BODY = "message_body"
    ATTACHMENT = "attachment"
    MESSAGE_METADATA = "message_metadata"
    IDENTITY_EVENT = "identity_event"
    AUDIT_EVENT = "audit_event"
    ALERT = "alert"
    FINDING = "finding"
    VERDICT_CACHE_CLEAN = "verdict_cache_clean"
    VERDICT_CACHE_MALICIOUS = "verdict_cache_malicious"
    TRIAL_LEDGER = "trial_ledger"
    USAGE_METER = "usage_meter"


#: `None` means "kept indefinitely" and must always carry a justification.
@dataclass(frozen=True, slots=True)
class Policy:
    data_class: DataClass
    days: int | None
    rationale: str
    metadata_only_mode: bool = True
    """Whether this class still exists when a tenant runs metadata-only (E13)."""

    survives_tenant_deletion: bool = False


SCHEDULE: tuple[Policy, ...] = (
    Policy(
        DataClass.MESSAGE_BODY,
        30,
        "Long enough to investigate an incident; short enough to limit exposure.",
        metadata_only_mode=False,
    ),
    Policy(
        DataClass.ATTACHMENT,
        30,
        "Deduplicated by hash. The verdict outlives the file, so deleting the "
        "bytes costs no detection quality.",
        metadata_only_mode=False,
    ),
    Policy(
        DataClass.MESSAGE_METADATA,
        365,
        "Powers A9 stylometry and A12 reply-time baselines. Features and hashes "
        "only — no message content.",
    ),
    Policy(
        DataClass.IDENTITY_EVENT,
        365,
        "Session and access history for C-group detections.",
    ),
    Policy(
        DataClass.AUDIT_EVENT,
        365,
        "E5 oversight trail. Deliberately shorter than most SIEMs — say so in "
        "sales rather than letting a customer assume seven years.",
    ),
    Policy(
        DataClass.ALERT,
        730,
        "The customer's own incident record; they will want it at renewal and "
        "after any dispute.",
    ),
    Policy(DataClass.FINDING, 730, "Evidence behind each alert."),
    Policy(
        DataClass.VERDICT_CACHE_CLEAN,
        30,
        "Clean today can be flagged tomorrow, so clean verdicts must expire.",
    ),
    Policy(
        DataClass.VERDICT_CACHE_MALICIOUS,
        None,
        "Malicious verdicts never expire. Cross-tenant and keyed by hash only — "
        "it contains no customer data.",
        survives_tenant_deletion=True,
    ),
    Policy(
        DataClass.TRIAL_LEDGER,
        None,
        "A registrable domain is not personal data. Permanence IS the anti-abuse "
        "mechanism (§12.7) — deleting it would reopen unlimited free trials.",
        survives_tenant_deletion=True,
    ),
    Policy(
        DataClass.USAGE_METER,
        None,
        "Aggregate counters only, retained for billing history and COGS "
        "modelling. No per-message detail.",
        survives_tenant_deletion=True,
    ),
)

_BY_CLASS = {p.data_class: p for p in SCHEDULE}

#: Churn timeline.
CHURN_GRACE_DAYS = 30
CHURN_DELETION_DEADLINE_DAYS = 60


def policy_for(data_class: DataClass) -> Policy:
    return _BY_CLASS[data_class]


def cutoff(data_class: DataClass, *, now: datetime | None = None) -> datetime | None:
    """Anything older than this is purged. `None` means never."""
    policy = policy_for(data_class)
    if policy.days is None:
        return None
    return (now or datetime.now(UTC)) - timedelta(days=policy.days)


def classes_to_purge(*, metadata_only: bool = False) -> list[DataClass]:
    """Classes with a finite lifetime. Under metadata-only mode the content
    classes were never written, so they are skipped rather than purged."""
    return [
        p.data_class
        for p in SCHEDULE
        if p.days is not None and (p.metadata_only_mode or not metadata_only)
    ]


def deletion_plan(*, closed_at: datetime) -> dict:
    """What happens to a churned tenant, and by when.

    Deletion must be demonstrable — this is the shape of the report a customer
    receives, not an internal note.
    """
    return {
        "closed_at": closed_at.isoformat(),
        "grace_ends": (closed_at + timedelta(days=CHURN_GRACE_DAYS)).isoformat(),
        "deletion_deadline": (
            closed_at + timedelta(days=CHURN_DELETION_DEADLINE_DAYS)
        ).isoformat(),
        "deleted": [
            {"data_class": p.data_class.value, "rationale": p.rationale}
            for p in SCHEDULE
            if not p.survives_tenant_deletion
        ],
        "retained": [
            {"data_class": p.data_class.value, "rationale": p.rationale}
            for p in SCHEDULE
            if p.survives_tenant_deletion
        ],
    }


async def purge_expired(session, *, now: datetime | None = None) -> dict[str, int]:  # noqa: ANN001
    """Actually enforce the schedule (PRD §15.2).

    Deletion must be *demonstrable*, so this returns a count per data class and is
    meant to run on the scheduler. FK order matters — findings and deliveries
    reference alerts, so they go first. Message bodies are the highest-sensitivity
    class and expire first (30 days); the metadata row survives to power A9/A12.
    """
    from sqlalchemy import delete, select, update

    from envelock.models import (
        Alert,
        AuditEvent,
        Finding,
        Message,
        NotificationDelivery,
        SensorSession,
    )

    now = now or datetime.now(UTC)
    counts: dict[str, int] = {}

    # 1. Message bodies (30d): drop the body pointer + subject, keep the metadata
    #    row. Nulling an already-null body (metadata-only tenants) is a no-op.
    body_cut = cutoff(DataClass.MESSAGE_BODY, now=now)
    if body_cut is not None:
        res = await session.execute(
            update(Message)
            .where(Message.received_at < body_cut, Message.body_storage_key.isnot(None))
            .values(body_storage_key=None, subject=None)
        )
        counts["message_body"] = res.rowcount or 0

    # 2. Identity events (365d).
    id_cut = cutoff(DataClass.IDENTITY_EVENT, now=now)
    if id_cut is not None:
        res = await session.execute(
            delete(SensorSession).where(SensorSession.last_seen_at < id_cut)
        )
        counts["identity_event"] = res.rowcount or 0

    # 3. Audit events (365d).
    audit_cut = cutoff(DataClass.AUDIT_EVENT, now=now)
    if audit_cut is not None:
        res = await session.execute(
            delete(AuditEvent).where(AuditEvent.created_at < audit_cut)
        )
        counts["audit_event"] = res.rowcount or 0

    # 4/5/6. Findings + deliveries + alerts (730d) — FK-safe order.
    finding_cut = cutoff(DataClass.FINDING, now=now)
    alert_cut = cutoff(DataClass.ALERT, now=now)
    if finding_cut is not None:
        res = await session.execute(
            delete(Finding).where(Finding.created_at < finding_cut)
        )
        counts["finding"] = res.rowcount or 0
    if alert_cut is not None:
        old_alert_ids = (
            await session.execute(select(Alert.id).where(Alert.created_at < alert_cut))
        ).scalars().all()
        if old_alert_ids:
            await session.execute(
                delete(NotificationDelivery).where(
                    NotificationDelivery.alert_id.in_(old_alert_ids)
                )
            )
            res = await session.execute(delete(Alert).where(Alert.id.in_(old_alert_ids)))
            counts["alert"] = res.rowcount or 0

    await session.commit()
    return counts


def schedule_payload() -> list[dict]:
    """Customer-facing retention schedule."""
    return [
        {
            "data_class": p.data_class.value,
            "retention_days": p.days,
            "retention": "indefinite" if p.days is None else f"{p.days} days",
            "rationale": p.rationale,
            "exists_in_metadata_only_mode": p.metadata_only_mode,
            "survives_tenant_deletion": p.survives_tenant_deletion,
        }
        for p in SCHEDULE
    ]
