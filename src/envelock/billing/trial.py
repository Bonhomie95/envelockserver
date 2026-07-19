"""Trial eligibility (PRD §12.7).

15 days free, one per domain, ever. The ledger is append-only and permanent — it
survives account deletion, which *is* the anti-abuse mechanism. A registrable
domain is not personal data, so retaining it through erasure requests is
defensible.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from envelock.util.domains import is_free_mail, registrable_domain


class Eligibility(StrEnum):
    ELIGIBLE = "eligible"
    ALREADY_USED = "already_used"
    REVIEW = "review"  # soft flag — never a hard block
    OVERRIDDEN = "overridden"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    registrable_domain: str
    first_trial_at: datetime
    outcome: str
    payment_fingerprint: str | None = None
    override_by: str | None = None


@dataclass(frozen=True, slots=True)
class TrialDecision:
    eligibility: Eligibility
    trial_key: str
    reason: str
    ends_at: datetime | None = None

    @property
    def allowed(self) -> bool:
        """REVIEW is deliberately allowed.

        A related-domain match is a soft flag for a human to look at, never a
        hard block — multi-brand groups are legitimate and are good customers
        (PRD §12.7). Only ALREADY_USED refuses.
        """
        return self.eligibility is not Eligibility.ALREADY_USED


def trial_key(identifier: str, payment_fingerprint: str | None = None) -> str:
    """What the trial is locked to.

    Domains lock on eTLD+1. Free-mail addresses cannot — locking `gmail.com`
    would block every subsequent Gmail signup — so the no-domain segment locks on
    mailbox address plus payment instrument instead (PRD §12.6, §12.7).
    """
    reg = registrable_domain(identifier)
    if reg and not is_free_mail(reg):
        return f"domain:{reg}"
    address = identifier.strip().lower()
    suffix = f"|{payment_fingerprint}" if payment_fingerprint else ""
    return f"mailbox:{address}{suffix}"


def _related(a: str, b: str) -> bool:
    """`acme.com` vs `acme-group.com` — technically distinct entities.

    Soft-flagged for review, never hard-blocked: multi-brand groups are
    legitimate and are good customers.
    """
    la = a.partition(".")[0]
    lb = b.partition(".")[0]
    if not la or not lb or la == lb:
        return False
    return (la in lb or lb in la) and min(len(la), len(lb)) >= 4


def evaluate(
    *,
    identifier: str,
    existing: LedgerEntry | None,
    related_entries: list[LedgerEntry] | None = None,
    payment_fingerprint: str | None = None,
    now: datetime | None = None,
    trial_days: int = 15,
) -> TrialDecision:
    now = now or datetime.now().astimezone()
    key = trial_key(identifier, payment_fingerprint)

    if existing is not None:
        if existing.override_by:
            return TrialDecision(
                Eligibility.OVERRIDDEN,
                key,
                "sales-granted re-trial",
                now + timedelta(days=trial_days),
            )
        return TrialDecision(
            Eligibility.ALREADY_USED,
            key,
            f"this domain already used its trial on "
            f"{existing.first_trial_at.date().isoformat()}",
        )

    reg = registrable_domain(identifier)
    for entry in related_entries or []:
        matches_payment = (
            payment_fingerprint is not None
            and entry.payment_fingerprint == payment_fingerprint
        )
        if matches_payment or (reg and _related(reg, entry.registrable_domain)):
            return TrialDecision(
                Eligibility.REVIEW,
                key,
                f"resembles a prior trial on {entry.registrable_domain} — "
                f"flagged for review, not blocked",
                now + timedelta(days=trial_days),
            )

    return TrialDecision(
        Eligibility.ELIGIBLE, key, "first trial", now + timedelta(days=trial_days)
    )


def backfill_days(*, in_trial: bool, trial_days: int = 30, full_days: int = 90) -> int:
    """Backfill is capped during trial (PRD §12.7).

    Ninety days of history per mailbox, analysed before the customer has paid, is
    the expensive part of a trial. Thirty is enough for A9 and A12 to be useful.
    """
    return trial_days if in_trial else full_days
