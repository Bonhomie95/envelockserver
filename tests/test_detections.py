"""End-to-end detection behaviour against realistic BEC messages."""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections import identity as _identity  # noqa: F401
from envelock.detections import impersonation as _impersonation  # noqa: F401
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.risk.engine import assess
from envelock.util.domains import classify_lookalike, registrable_domain, skeleton
from envelock.util.payments import extract_bank_identifiers, valid_iban

OWNED = frozenset({"acme.com"})
KNOWN = frozenset({"gemini.com"})


def build(raw: str, source=SourceMechanism.IMAP_IDLE, counterparty=None):
    event = parse_message(
        raw.encode(),
        tenant_id=uuid4(),
        mailbox_id=uuid4(),
        source=source,
        owned_domains=OWNED,
        remediable=True,
    )
    return DetectionContext(
        event=event,
        tenant_id="t",
        capabilities=capabilities_for(frozenset({source})),
        owned_domains=OWNED,
        known_counterparties=KNOWN,
        counterparty=counterparty,
    )


BANK_CHANGE = """\
From: "Gemini Accounts" <billing@gemini.com>
To: pay@acme.com
Subject: Re: Invoice 4471
Message-ID: <a@gemini.com>
In-Reply-To: <old@gemini.com>
References: <old@gemini.com>
Content-Type: text/plain

Please note our bank account has changed. Remit payment to
IBAN GB33BUKB20201555555555, urgent, today please.
"""


def test_a1_fires_critical_on_bank_change() -> None:
    cp = CounterpartyState(
        registrable_domain="gemini.com",
        message_count=40,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
        verified_phone="+18030000000",
    )
    findings = run_all(build(BANK_CHANGE, counterparty=cp))
    services = {f.service for f in findings}
    assert "A1" in services

    a1 = next(f for f in findings if f.service == "A1")
    assert a1.tier is AlertTier.CRITICAL
    # E3 — the number on file with us, never the one in the email.
    assert a1.evidence["callback_phone"] == "+18030000000"


def test_a1_silent_when_account_already_known() -> None:
    cp = CounterpartyState(
        registrable_domain="gemini.com",
        message_count=40,
        known_bank_ids=frozenset({"GB33BUKB20201555555555"}),
    )
    findings = run_all(build(BANK_CHANGE, counterparty=cp))
    assert "A1" not in {f.service for f in findings}


def test_a1_silent_on_first_contact() -> None:
    """Nothing to diff against — A7 covers first contact instead."""
    findings = run_all(build(BANK_CHANGE, counterparty=None))
    assert "A1" not in {f.service for f in findings}


LOOKALIKE = """\
From: "Gemini Ltd" <billing@gemini-invoices.com>
To: pay@acme.com
Subject: Updated payment instructions
Reply-To: finance@gemini-pay.net
Content-Type: text/plain

Kindly update our bank account details. New IBAN GB33BUKB20201555555555.
Please treat as urgent and confidential.
"""


def test_lookalike_plus_replyto_plus_urgency() -> None:
    findings = run_all(build(LOOKALIKE))
    services = {f.service for f in findings}
    assert "A3" in services  # cousin domain
    assert "A6" in services  # reply-to mismatch
    assert "A14" in services  # urgency


def test_combination_promotes_tier() -> None:
    """A7 + A1 together is the BEC signature (PRD §8)."""
    cp = CounterpartyState(
        registrable_domain="gemini-invoices.com",
        message_count=0,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
    )
    findings = run_all(build(LOOKALIKE, counterparty=cp))
    result = assess(findings)
    assert result is not None
    assert result.tier is AlertTier.CRITICAL
    assert result.requires_callback
    assert result.rationale


THREAD_HIJACK = """\
From: <accounts@gemini.com>
To: pay@acme.com
Subject: Re: Purchase Order 8891
Content-Type: text/plain

Following up on the below, please send payment to the new account.
"""


def test_a8_detects_missing_thread_chain() -> None:
    findings = run_all(build(THREAD_HIJACK))
    assert "A8" in {f.service for f in findings}


def test_forwarding_is_never_remediable() -> None:
    """PRD §4 fn.3 — the copy arrives post-delivery."""
    ctx = build(BANK_CHANGE, source=SourceMechanism.FORWARD_INGEST)
    assert ctx.event.remediable is False


def test_imap_is_remediable() -> None:
    """IMAP MOVE works on a 1998 server — the Tier 4 → Tier 3 upgrade argument."""
    ctx = build(BANK_CHANGE, source=SourceMechanism.IMAP_IDLE)
    assert ctx.event.remediable is True


def test_low_findings_are_not_alertable() -> None:
    """Noisy alerts burn margin directly as well as trust (PRD P5)."""
    clean = """\
From: <someone@gemini.com>
To: pay@acme.com
Subject: Lunch
Content-Type: text/plain

See you at 1.
"""
    result = assess(run_all(build(clean)))
    assert result is None or not result.is_alertable


# ── Utility-level ────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("gemini.org", "tld_swap"),
        ("gemíni.com", "homoglyph"),
        ("gemini-invoices.com", "cousin"),
        ("gemni.com", "typosquat"),
    ],
)
def test_lookalike_techniques(candidate: str, expected: str) -> None:
    result = classify_lookalike(candidate, "gemini.com")
    assert result is not None
    assert result[0] == expected


def test_rn_m_confusion_collapses() -> None:
    assert skeleton("rnicrosoft") == skeleton("microsoft")


def test_registrable_domain_handles_multipart_suffixes() -> None:
    """Naive splitting here would break our actual markets."""
    assert registrable_domain("mail.acme.com") == "acme.com"
    assert registrable_domain("emea.acme.co.uk") == "acme.co.uk"
    assert registrable_domain("acme.com.tw") == "acme.com.tw"


def test_iban_checksum() -> None:
    assert valid_iban("GB33BUKB20201555555555")
    assert not valid_iban("GB33BUKB20201555555556")


def test_bank_extraction_requires_payment_context() -> None:
    assert extract_bank_identifiers("Order reference 123456789012 shipped") == []
    found = extract_bank_identifiers("Bank account 123456789012 for payment")
    assert found


def test_swift_requires_an_explicit_label() -> None:
    """Regression: an unlabelled 8-letter uppercase token parses as a
    structurally valid BIC. "ATTACHED" is bank ATTA, country CH, location ED —
    it was being learned as a vendor's bank code and then firing A1 on routine
    invoices."""
    assert extract_bank_identifiers("Documents ATTACHED for bank payment") == []
    assert extract_bank_identifiers("Please find REGARDS bank account details") == []

    labelled = extract_bank_identifiers("Payment via SWIFT: BARCGB22XXX for the invoice")
    assert [b.identifier for b in labelled] == ["BARCGB22XXX"]


def test_bic_country_code_must_be_real() -> None:
    # ZZ is not an ISO country, so this is not a BIC.
    assert extract_bank_identifiers("SWIFT: ABCDZZ11 bank transfer") == []
