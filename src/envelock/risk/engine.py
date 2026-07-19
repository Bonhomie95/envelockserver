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

#: Co-occurring services that together mean more than they do apart.
#: Each entry promotes the alert by one tier when every service is present.
_COMBINATIONS: tuple[tuple[frozenset[str], str], ...] = (
    (
        frozenset({"A7", "A1"}),
        "First-ever contact from this domain, and it changes payment details.",
    ),
    (
        frozenset({"A3", "A1"}),
        "A lookalike domain is requesting a payment-detail change.",
    ),
    (
        frozenset({"A6", "A1"}),
        "Payment details changed and replies would be redirected elsewhere.",
    ),
    (
        frozenset({"A10", "A1"}),
        "Sending infrastructure changed and payment details changed with it.",
    ),
    (
        frozenset({"A8", "A1"}),
        "Thread hijacking combined with a payment-detail change.",
    ),
    (
        frozenset({"A14", "A1"}),
        "Payment-detail change delivered with urgency pressure.",
    ),
    (
        frozenset({"C1", "C11"}),
        "External forwarding rule alongside unexplained mailbox access.",
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
    for combo, explanation in _COMBINATIONS:
        if combo <= services:
            tier = _promote(tier)
            rationale.append(explanation)

    # Diminishing-returns aggregate so ten Low findings never sum to a Critical.
    ordered = sorted((f.score for f in findings), reverse=True)
    score = min(100, int(sum(s / (i + 1) for i, s in enumerate(ordered))))

    # A1 always carries the callback prompt — it is the step that stops the loss.
    callback_phone: str | None = None
    requires_callback = False
    for finding in findings:
        if finding.service == "A1":
            requires_callback = True
            callback_phone = finding.evidence.get("callback_phone")
            break

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
