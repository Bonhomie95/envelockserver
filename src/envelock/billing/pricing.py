"""Pricing engine — PRD §12.

Structure: platform fee per mail-carrying domain + volume-banded per-mailbox fee,
pooled across domains. Two mailbox classes (§12.2) so whole-domain coverage stays
affordable, which is what closes the "attacker enters via an unprotected mailbox"
hole.

Price is identical across integration tiers — a customer does not pay more for
being on HiNet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from envelock.core.enums import MailboxClass


class Plan(StrEnum):
    GUARD = "guard"  # Channel 3 only — free forever
    ESSENTIAL = "essential"
    COMPLETE = "complete"
    SOLO = "solo"  # no-domain segment (PRD §12.6)


class BillingTerm(StrEnum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMIANNUAL = "semiannual"
    ANNUAL = "annual"


#: Term discounts. Monthly stays unpenalised — annual prepay is genuinely hard
#: for SMBs in our markets.
TERM_DISCOUNT: dict[BillingTerm, float] = {
    BillingTerm.MONTHLY: 0.00,
    BillingTerm.QUARTERLY: 0.05,
    BillingTerm.SEMIANNUAL: 0.10,
    BillingTerm.ANNUAL: 0.20,
}

#: Platform fee per mail-carrying domain, in cents.
PLATFORM_CENTS: dict[Plan, int] = {
    Plan.GUARD: 0,
    Plan.ESSENTIAL: 1500,
    Plan.COMPLETE: 3000,
    Plan.SOLO: 0,
}

#: Additional mail-carrying domains cost half. Defensive/parked domains are free
#: and unlimited — monitoring one costs a daily DNS lookup.
ADDITIONAL_DOMAIN_RATE = 0.5

#: (upper_bound_inclusive, cents_per_mailbox). Marginal: each band applies only
#: to mailboxes falling within it.
_BANDS: tuple[int, ...] = (10, 50, 200, 1000, 10**9)

_PROTECTED_RATES: dict[Plan, tuple[int, ...]] = {
    Plan.ESSENTIAL: (200, 170, 140, 100, 70),
    Plan.COMPLETE: (350, 300, 240, 175, 120),
}
_MONITORED_RATES: tuple[int, ...] = (60, 50, 40, 30, 20)

#: Flat per-mailbox pricing for the no-domain segment.
SOLO_CENTS = 600
SOLO_TEAM_CENTS = 500
SOLO_TEAM_MIN = 3


@dataclass(frozen=True, slots=True)
class Quote:
    plan: Plan
    term: BillingTerm
    platform_cents: int
    protected_cents: int
    monitored_cents: int
    subtotal_cents: int
    discount_cents: int
    total_cents: int
    breakdown: dict

    @property
    def total_usd(self) -> float:
        return self.total_cents / 100


def _banded_cost(count: int, rates: tuple[int, ...]) -> tuple[int, list[dict]]:
    """Marginal banding across `_BANDS`."""
    total = 0
    detail: list[dict] = []
    remaining = count
    lower = 0
    for bound, rate in zip(_BANDS, rates, strict=True):
        if remaining <= 0:
            break
        in_band = min(remaining, bound - lower)
        if in_band > 0:
            cost = in_band * rate
            total += cost
            detail.append(
                {"band": f"{lower + 1}-{bound if bound < 10**9 else '+'}",
                 "count": in_band, "rate_cents": rate, "cents": cost}
            )
            remaining -= in_band
        lower = bound
    return total, detail


def quote(
    *,
    plan: Plan,
    term: BillingTerm = BillingTerm.MONTHLY,
    mail_domains: int = 1,
    protected: int = 0,
    monitored: int = 0,
    solo_mailboxes: int = 0,
) -> Quote:
    """Monthly-equivalent cost. Mailbox bands pool across all domains."""
    if plan is Plan.GUARD:
        return Quote(plan, term, 0, 0, 0, 0, 0, 0, {"note": "Guard is free forever"})

    if plan is Plan.SOLO:
        rate = SOLO_TEAM_CENTS if solo_mailboxes >= SOLO_TEAM_MIN else SOLO_CENTS
        subtotal = rate * solo_mailboxes
        discount = int(subtotal * TERM_DISCOUNT[term])
        return Quote(
            plan, term, 0, subtotal, 0, subtotal, discount, subtotal - discount,
            {"mailboxes": solo_mailboxes, "rate_cents": rate},
        )

    base = PLATFORM_CENTS[plan]
    extra_domains = max(0, mail_domains - 1)
    platform = base + int(base * ADDITIONAL_DOMAIN_RATE) * extra_domains

    protected_cents, protected_detail = _banded_cost(protected, _PROTECTED_RATES[plan])
    monitored_cents, monitored_detail = _banded_cost(monitored, _MONITORED_RATES)

    subtotal = platform + protected_cents + monitored_cents
    discount = int(subtotal * TERM_DISCOUNT[term])

    return Quote(
        plan=plan,
        term=term,
        platform_cents=platform,
        protected_cents=protected_cents,
        monitored_cents=monitored_cents,
        subtotal_cents=subtotal,
        discount_cents=discount,
        total_cents=subtotal - discount,
        breakdown={
            "mail_domains": mail_domains,
            "platform": {"base_cents": base, "additional_domains": extra_domains},
            "protected": protected_detail,
            "monitored": monitored_detail,
            "term_discount_pct": int(TERM_DISCOUNT[term] * 100),
        },
    )


def classify_cost_profile(mailbox_class: MailboxClass) -> str:
    """Which IMAP strategy a class implies (PRD §12.11D).

    PROTECTED holds IDLE because quarantine latency is the product. MONITORED
    polls, which needs no persistent connection — that is what keeps the class
    cheap enough to mandate whole-domain coverage.
    """
    return "idle" if mailbox_class is MailboxClass.PROTECTED else "poll"
