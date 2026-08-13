"""Risk scoring and alert tiering (PRD §8).

Tiers are defined by *required action*, not by how alarming a finding sounds.
Combination logic matters more than any single rule: A7 alone is Medium, A1 alone
is Critical, and A7 + A1 + A14 together is the actual BEC signature.
"""

from __future__ import annotations

from dataclasses import dataclass

from envelock.core.enums import AlertTier
from envelock.detections.base import FindingResult

_ORDER = {
    AlertTier.LOW: 0,
    AlertTier.MEDIUM: 1,
    AlertTier.HIGH: 2,
    AlertTier.CRITICAL: 3,
}
_BY_RANK = {rank: tier for tier, rank in _ORDER.items()}

#: Co-occurring services that together mean more than they do apart. Each entry
#: is (services, explanation, floor). When every service is present the alert is
#: raised to at least `floor`; `floor=None` promotes by one tier instead (used by
#: the A1 combos, where A1 is already Critical so the promotion only adds context).
_COMBINATIONS: tuple[tuple[frozenset[str], str, AlertTier | None], ...] = (
    (
        frozenset({"A7", "A1"}),
        "First-ever contact from this domain, and it changes payment details.",
        None,
    ),
    (
        frozenset({"A3", "A1"}),
        "A lookalike domain is requesting a payment-detail change.",
        None,
    ),
    (
        frozenset({"A6", "A1"}),
        "Payment details changed and replies would be redirected elsewhere.",
        None,
    ),
    (
        frozenset({"A10", "A1"}),
        "Sending infrastructure changed and payment details changed with it.",
        None,
    ),
    (
        frozenset({"A8", "A1"}),
        "Thread hijacking combined with a payment-detail change.",
        None,
    ),
    (
        frozenset({"A14", "A1"}),
        "Payment-detail change delivered with urgency pressure.",
        None,
    ),
    (
        frozenset({"C1", "C11"}),
        "External forwarding rule alongside unexplained mailbox access.",
        None,
    ),
    # ── Novel-vendor BEC (no prior A1 baseline to diff against) ──────────────
    # A2 fires when payment instructions arrive from an unverified payee. On its
    # own that is Medium — a legit new vendor's first invoice. But combined with a
    # domain that is impersonating someone, or with first-contact + urgency, it is
    # the classic first-strike BEC that A1 structurally cannot catch (nothing to
    # diff). These force Critical, whose action is "verify by phone before paying"
    # — the correct response to any new payee, so a false positive costs a callback.
    (
        frozenset({"A2", "A4"}),
        "Payment instructions from an unverified payee on a homoglyph domain.",
        AlertTier.CRITICAL,
    ),
    (
        frozenset({"A2", "A3"}),
        "Payment instructions from an unverified payee on a lookalike domain.",
        AlertTier.CRITICAL,
    ),
    (
        frozenset({"A2", "A5"}),
        "Payment instructions from an unverified payee spoofing a known display name.",
        AlertTier.CRITICAL,
    ),
    (
        frozenset({"A2", "A6"}),
        "Payment instructions from an unverified payee, with replies redirected elsewhere.",
        AlertTier.CRITICAL,
    ),
    (
        frozenset({"A2", "B7"}),
        "Payment instructions from a sender on a public blocklist.",
        AlertTier.CRITICAL,
    ),
    (
        frozenset({"A2", "A7", "A14"}),
        "First-ever contact, urgent, sending payment instructions to a new payee — "
        "verify by phone before paying.",
        AlertTier.CRITICAL,
    ),
)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    tier: AlertTier
    score: int
    title: str
    body: str
    services: tuple[str, ...]
    requires_callback: bool
    callback_phone: str | None
    rationale: tuple[str, ...]

    @property
    def is_alertable(self) -> bool:
        """Low findings are logged for context, not notified (PRD §8)."""
        return self.tier is not AlertTier.LOW


def _promote(tier: AlertTier, steps: int = 1) -> AlertTier:
    return _BY_RANK[min(3, _ORDER[tier] + steps)]


def assess(findings: list[FindingResult]) -> RiskAssessment | None:
    if not findings:
        return None

    services = {f.service for f in findings}
    base = max(findings, key=lambda f: (_ORDER[f.tier], f.score))
    tier = base.tier

    rationale: list[str] = []
    for combo, explanation, floor in _COMBINATIONS:
        if not (combo <= services):
            continue
        if floor is None:
            tier = _promote(tier)  # A1 combos: step up (A1 is already Critical)
        elif _ORDER[floor] > _ORDER[tier]:
            tier = floor  # novel-vendor combos: force a floor, never demote
        rationale.append(explanation)

    # Diminishing-returns aggregate so ten Low findings never sum to a Critical.
    ordered = sorted((f.score for f in findings), reverse=True)
    score = min(100, int(sum(s / (i + 1) for i, s in enumerate(ordered))))

    # A1 always carries the callback prompt — it is the step that stops the loss.
    # A novel-vendor Critical (A2 + a deception signal) warrants the same callback:
    # confirm the new payee's account by phone before paying.
    callback_phone: str | None = None
    requires_callback = False
    for finding in findings:
        if finding.service == "A1":
            requires_callback = True
            callback_phone = finding.evidence.get("callback_phone")
            break
    if not requires_callback and tier is AlertTier.CRITICAL and "A2" in services:
        requires_callback = True

    # The headline finding becomes the title, so it must not repeat in the body.
    body_lines = [f.summary for f in findings if f.summary != base.summary]
    body_lines.extend(rationale)

    return RiskAssessment(
        tier=tier,
        score=score,
        title=base.summary,
        body="\n".join(body_lines),
        services=tuple(sorted(services)),
        requires_callback=requires_callback,
        callback_phone=callback_phone,
        rationale=tuple(rationale),
    )
