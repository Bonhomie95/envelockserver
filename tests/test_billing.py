"""Pricing and trial rules. Numbers here must match PRD §12.9 worked examples."""

from __future__ import annotations

from datetime import UTC, datetime

from envelock.billing import trial
from envelock.billing.pricing import BillingTerm, Plan, quote


def test_worked_example_b_five_seat_essential() -> None:
    """PRD §12.9B — the affordability floor for a real B2B customer."""
    q = quote(plan=Plan.ESSENTIAL, protected=5)
    assert q.total_usd == 25.00


def test_worked_example_a_five_seat_complete_annual() -> None:
    q = quote(plan=Plan.COMPLETE, term=BillingTerm.ANNUAL, protected=5)
    assert q.subtotal_cents == 4750  # $47.50 list
    assert q.total_usd == 38.00  # −20%


def test_worked_example_c_thousand_seats() -> None:
    """PRD §12.9C — ~$442/mo, roughly $0.44/user.

    Two mailbox classes are what make whole-domain coverage affordable, which is
    what closes the unprotected-mailbox hole.
    """
    q = quote(plan=Plan.COMPLETE, protected=30, monitored=970)
    assert 43000 <= q.total_cents <= 45000
    assert q.total_cents / 1000 < 50  # under $0.50 per user


def test_two_class_pricing_beats_all_protected() -> None:
    both = quote(plan=Plan.COMPLETE, protected=30, monitored=970)
    all_protected = quote(plan=Plan.COMPLETE, protected=1000)
    assert both.total_cents < all_protected.total_cents / 3


def test_worked_example_d_multi_domain() -> None:
    """Additional mail domains cost half; mailbox bands pool across them."""
    q = quote(plan=Plan.COMPLETE, mail_domains=3, protected=40, monitored=200)
    assert q.platform_cents == 3000 + 1500 + 1500
    assert 26000 <= q.total_cents <= 28000


def test_guard_is_free() -> None:
    assert quote(plan=Plan.GUARD, mail_domains=5).total_cents == 0


def test_solo_segment() -> None:
    """PRD §12.6 — no domain, so no platform fee."""
    assert quote(plan=Plan.SOLO, solo_mailboxes=1).total_usd == 6.00
    assert quote(plan=Plan.SOLO, solo_mailboxes=3).total_usd == 15.00


def test_term_discounts() -> None:
    base = quote(plan=Plan.COMPLETE, protected=10).total_cents
    for term, expected in (
        (BillingTerm.QUARTERLY, 0.95),
        (BillingTerm.SEMIANNUAL, 0.90),
        (BillingTerm.ANNUAL, 0.80),
    ):
        assert quote(plan=Plan.COMPLETE, term=term, protected=10).total_cents == int(
            base * expected
        )


# ── Trial ────────────────────────────────────────────────────────────────────
def test_trial_locks_on_registrable_domain() -> None:
    """Subdomain evasion must not earn a second trial."""
    assert trial.trial_key("acme.com.ng") == trial.trial_key("emea.acme.com.ng")


def test_free_mail_is_not_domain_locked() -> None:
    """Locking gmail.com would block every subsequent Gmail signup."""
    key = trial.trial_key("trader@gmail.com", payment_fingerprint="fp_1")
    assert key.startswith("mailbox:")
    assert trial.trial_key("other@gmail.com", "fp_2") != key


def test_second_trial_refused() -> None:
    entry = trial.LedgerEntry(
        registrable_domain="acme.com.ng",
        first_trial_at=datetime(2026, 1, 1, tzinfo=UTC),
        outcome="lapsed",
    )
    decision = trial.evaluate(identifier="acme.com.ng", existing=entry)
    assert decision.eligibility is trial.Eligibility.ALREADY_USED
    assert not decision.allowed


def test_sales_override_allows_retrial() -> None:
    entry = trial.LedgerEntry(
        registrable_domain="acme.com.ng",
        first_trial_at=datetime(2024, 1, 1, tzinfo=UTC),
        outcome="lapsed",
        override_by="sales-1",
    )
    assert trial.evaluate(identifier="acme.com.ng", existing=entry).allowed


def test_related_domain_is_flagged_not_blocked() -> None:
    """Multi-brand groups are legitimate and are good customers."""
    entry = trial.LedgerEntry(
        registrable_domain="acme.com",
        first_trial_at=datetime(2026, 1, 1, tzinfo=UTC),
        outcome="converted",
    )
    decision = trial.evaluate(
        identifier="acme-group.com", existing=None, related_entries=[entry]
    )
    assert decision.eligibility is trial.Eligibility.REVIEW
    assert decision.allowed  # soft flag, never a hard block


def test_backfill_capped_during_trial() -> None:
    """The expensive part of a trial, capped before conversion (PRD §12.7)."""
    assert trial.backfill_days(in_trial=True) == 30
    assert trial.backfill_days(in_trial=False) == 90
