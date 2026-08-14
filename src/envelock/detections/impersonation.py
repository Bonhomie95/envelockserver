"""Group A — counterparty fraud and impersonation. The wedge (PRD §3).

A1 is the lead feature: any change to a previously-seen vendor's payment details
is Critical, always, with a callback prompt showing the number *on file with us*.
"""

from __future__ import annotations

from dataclasses import dataclass

from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier, AuthResult, MailDirection
from envelock.detections.base import (
    DetectionContext,
    FindingResult,
    register,
)
from envelock.util.domains import classify_lookalike, is_free_mail, registrable_domain
from envelock.util.payments import (
    extract_bank_identifiers,
    has_payment_context,
    urgency_score,
)

_INBOUND = frozenset({Capability.READ_INBOUND})

#: Plain-English explanation of *why* two domains look alike — no jargon reaches
#: the client (PRD §16 keeps the internal technique codes out of view).
_LOOKALIKE_PLAIN: dict[str, str] = {
    "homoglyph": "letters swapped for look-alikes (like the letter i for l)",
    "cousin": "extra or rearranged letters in the name",
    "typosquat": "a slight misspelling of the name",
    "tld_swap": "the same name with a different ending (like .com vs .co)",
}


def _body(ctx: DetectionContext) -> str:
    mail = ctx.mail
    if mail is None:
        return ""
    parts = [mail.subject, mail.body_text]
    # A1's most common real case: the changed IBAN lives inside an attached PDF or
    # Word invoice, or an image. The parser extracted that text; fold it in so the
    # payment-fraud detections see it exactly as if it were in the body.
    for att in mail.attachments:
        if att.extracted_text:
            parts.append(att.extracted_text)
    return " ".join(filter(None, parts))


def _is_external(ctx: DetectionContext) -> bool:
    mail = ctx.mail
    return (
        mail is not None
        and mail.direction is MailDirection.INBOUND
        and registrable_domain(mail.sender.domain) not in ctx.owned_domains
    )


@dataclass(frozen=True)
class _A1BankChange:
    service: str = "A1"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _is_external(ctx):
            return []
        text = _body(ctx)
        if not has_payment_context(text):
            return []

        found = extract_bank_identifiers(text)
        if not found:
            return []

        cp = ctx.counterparty
        # No prior relationship: nothing to diff against. A7 covers first contact.
        if cp is None or not cp.known_bank_ids:
            return []

        changed = [b for b in found if b.identifier not in cp.known_bank_ids]
        if not changed:
            return []

        return [
            FindingResult(
                service="A1",
                tier=AlertTier.CRITICAL,
                score=100,
                summary=(
                    f"{cp.registrable_domain} sent payment details that do not match "
                    f"the account on file. Verify by phone before paying."
                ),
                evidence={
                    "counterparty": cp.registrable_domain,
                    "new_identifiers": [
                        {"scheme": b.scheme, "identifier": b.identifier} for b in changed
                    ],
                    "known_count": len(cp.known_bank_ids),
                    # E3 — never the number in the email.
                    "callback_phone": cp.verified_phone,
                    "urgency": urgency_score(text),
                },
            )
        ]


@dataclass(frozen=True)
class _A3A4A5Impersonation:
    """Cousin domains, homoglyphs and display-name spoofing.

    One detection because they share the comparison set; the reported technique
    distinguishes them.
    """

    service: str = "A3"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _is_external(ctx):
            return []

        sender_domain = registrable_domain(mail.sender.domain)
        findings: list[FindingResult] = []
        comparison = set(ctx.owned_domains) | set(ctx.known_counterparties)
        comparison.discard(sender_domain)

        for protected in comparison:
            result = classify_lookalike(sender_domain, protected)
            if result is None:
                continue
            technique, score = result
            # Say it the way a person would: name the real domain, name the fake,
            # and whether it's someone they email with or their own name.
            you_know = protected not in ctx.owned_domains
            # A near-copy of a domain the client actually corresponds with — or a
            # very close visual match — is High: it's impersonating a real relationship.
            tier = AlertTier.HIGH if (score >= 0.9 or you_know) else AlertTier.MEDIUM
            who = (
                f"a company you exchange email with ({protected})"
                if you_know
                else f"your own domain ({protected})"
            )
            findings.append(
                FindingResult(
                    service="A4" if technique == "homoglyph" else "A3",
                    tier=tier,
                    score=int(score * 90),
                    summary=(
                        f"This email address, {sender_domain}, is a near-copy of "
                        f"{who} — {_LOOKALIKE_PLAIN.get(technique, 'a look-alike')}. "
                        f"Confirm it's really them before trusting it."
                    ),
                    evidence={
                        "sender_domain": sender_domain,
                        "resembles": protected,
                        "resembles_a_correspondent": you_know,
                        "technique": technique,
                        "similarity": round(score, 3),
                    },
                )
            )
            break  # closest single explanation is enough for the alert

        # Brand display-name spoofing ("Gemini Accounts" from a non-Gemini domain)
        # is handled by the dedicated A5 detection in content.py — not duplicated
        # here. What this adds is the *internal* case below.

        # CEO / staff impersonation: the sender uses the name of someone at the
        # client's own company, but the email came from outside. This is the classic
        # "urgent request from the boss" fraud, and it isn't a brand lookalike.
        display = (mail.sender.display or "").strip().lower()
        if display and not findings and ctx.internal_names:
            for name in ctx.internal_names:
                if len(name) >= 4 and name in display:
                    findings.append(
                        FindingResult(
                            service="A5",
                            tier=AlertTier.HIGH,
                            score=80,
                            summary=(
                                f'This email uses the name of someone at your company '
                                f'("{mail.sender.display}") but was sent from an outside '
                                f"address, {sender_domain}. Verify before acting on it."
                            ),
                            evidence={
                                "display_name": mail.sender.display,
                                "impersonates_internal_name": name,
                                "actual_domain": sender_domain,
                                "free_mail": is_free_mail(sender_domain),
                            },
                        )
                    )
                    break

        return findings


@dataclass(frozen=True)
class _A6ReplyToMismatch:
    service: str = "A6"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or mail.reply_to is None or not _is_external(ctx):
            return []

        sender = registrable_domain(mail.sender.domain)
        reply_to = registrable_domain(mail.reply_to.domain)
        if sender == reply_to:
            return []

        payment = has_payment_context(_body(ctx))
        return [
            FindingResult(
                service="A6",
                tier=AlertTier.HIGH if payment else AlertTier.MEDIUM,
                score=75 if payment else 45,
                summary=(
                    f"Replies to this message would go to {reply_to}, "
                    f"not {sender}."
                ),
                evidence={
                    "sender_domain": sender,
                    "reply_to_domain": reply_to,
                    "payment_context": payment,
                },
            )
        ]


@dataclass(frozen=True)
class _A7FirstContact:
    service: str = "A7"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _is_external(ctx):
            return []
        if ctx.counterparty is not None and ctx.counterparty.message_count > 0:
            return []

        text = _body(ctx)
        payment = has_payment_context(text)
        has_bank = bool(extract_bank_identifiers(text))
        if not payment:
            return []

        dom = registrable_domain(mail.sender.domain)
        # If the domain is also newly registered, say so — a brand-new domain
        # emailing you for the first time about money is the classic setup.
        age = ctx.sender_domain_age_days
        new_domain = age is not None and age <= 45
        if new_domain:
            summary = (
                f"This is the first email you've ever had from {dom}, it's about "
                f"payment, and the domain was only registered recently. Treat any "
                f"request to pay or share details with caution."
            )
        else:
            summary = (
                f"This is the first email you've ever had from {dom}, and it's about "
                f"payment. Confirm who they are before acting."
            )
        return [
            FindingResult(
                service="A7",
                tier=AlertTier.HIGH if (has_bank or new_domain) else AlertTier.MEDIUM,
                score=70 if (has_bank or new_domain) else 40,
                summary=summary,
                evidence={
                    "sender_domain": dom,
                    "contains_bank_details": has_bank,
                    "domain_age_days": age,
                },
            )
        ]


@dataclass(frozen=True)
class _A8ThreadHijack:
    service: str = "A8"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _is_external(ctx):
            return []
        # Claims to continue a thread but supplies no chain to continue.
        looks_like_reply = bool(
            mail.subject and mail.subject.lower().startswith(("re:", "fw:", "fwd:"))
        )
        if not looks_like_reply:
            return []
        if mail.in_reply_to or mail.references:
            return []

        return [
            FindingResult(
                service="A8",
                tier=AlertTier.HIGH,
                score=80,
                summary=(
                    "Message presents as a reply but carries no thread chain — "
                    "consistent with conversation hijacking."
                ),
                evidence={
                    "subject": mail.subject,
                    "has_in_reply_to": False,
                    "has_references": False,
                },
            )
        ]


@dataclass(frozen=True)
class _A10InfrastructureChange:
    """Replaces the impossible "real IP behind VPN" requirement (PRD §7.2/7.3).

    Detects that a counterparty's *sending setup* changed, which is what we
    actually care about and is far more reliable than sender geolocation.
    """

    service: str = "A10"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        cp = ctx.counterparty
        if mail is None or cp is None or not _is_external(ctx):
            return []
        if cp.message_count < 5 or not cp.known_dkim_domains:
            return []

        dkim_domain = mail.authentication.dkim_domain
        if not dkim_domain or dkim_domain in cp.known_dkim_domains:
            return []

        payment = has_payment_context(_body(ctx))
        return [
            FindingResult(
                service="A10",
                tier=AlertTier.HIGH if payment else AlertTier.MEDIUM,
                score=75 if payment else 45,
                summary=(
                    f"{cp.registrable_domain} is now sending from different mail "
                    f"infrastructure ({dkim_domain})."
                ),
                evidence={
                    "counterparty": cp.registrable_domain,
                    "new_dkim_domain": dkim_domain,
                    "known_dkim_domains": sorted(cp.known_dkim_domains),
                    "payment_context": payment,
                },
            )
        ]


@dataclass(frozen=True)
class _A14Urgency:
    service: str = "A14"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        if ctx.mail is None or not _is_external(ctx):
            return []
        text = _body(ctx)
        score = urgency_score(text)
        if score < 2 or not has_payment_context(text):
            return []
        return [
            FindingResult(
                service="A14",
                tier=AlertTier.LOW,
                score=20 * score,
                summary="Payment request uses urgency or secrecy pressure language.",
                evidence={"urgency_markers": score},
            )
        ]


@dataclass(frozen=True)
class _B8AuthPosture:
    service: str = "B8"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _is_external(ctx):
            return []
        auth = mail.authentication
        failed = [
            name
            for name, value in (
                ("SPF", auth.spf),
                ("DKIM", auth.dkim),
                ("DMARC", auth.dmarc),
            )
            if value in (AuthResult.FAIL, AuthResult.SOFTFAIL)
        ]
        if not failed:
            return []
        return [
            FindingResult(
                service="B8",
                tier=AlertTier.MEDIUM if len(failed) > 1 else AlertTier.LOW,
                score=25 * len(failed),
                summary=f"Sender authentication failed: {', '.join(failed)}.",
                evidence={"failed": failed},
            )
        ]


A1 = register(_A1BankChange())
A3 = register(_A3A4A5Impersonation())
A6 = register(_A6ReplyToMismatch())
A7 = register(_A7FirstContact())
A8 = register(_A8ThreadHijack())
A10 = register(_A10InfrastructureChange())
A14 = register(_A14Urgency())
B8 = register(_B8AuthPosture())
