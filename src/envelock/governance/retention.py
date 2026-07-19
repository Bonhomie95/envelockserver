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
