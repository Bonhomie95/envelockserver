"""The cascade gate — the single most important cost control.

An LLM call on *every* message would blow the margin (§12.11). This decides the
small fraction worth escalating: mail that already tripped a payment/impersonation
signal but sits in an ambiguous band where a human judgment call adds real value.
Clear-cut cases (a confirmed A1 bank change already Critical; plainly benign mail
with no signal) skip the LLM entirely.
"""

from __future__ import annotations

from envelock.core.enums import AlertTier
from envelock.risk.engine import RiskAssessment

#: Services whose presence marks a message as "about money/identity" — the only
#: class of mail where a BEC judge earns its cost.
_PAYMENT_SIGNALS = frozenset(
    {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A10", "A11", "A13", "A14"}
)


def should_escalate(assessment: RiskAssessment | None) -> bool:
    """True for the ambiguous middle: a payment/impersonation signal fired, and the
    rule tier is Medium or High (not Low noise, not an already-certain Critical)."""
    if assessment is None:
        return False
    services = set(assessment.services)
    if not (services & _PAYMENT_SIGNALS):
        return False
    # Low is logged, not alerted — not worth a call. Critical already interrupts a
    # human, so the confirmation adds little. The value is in the Medium/High band.
    return assessment.tier in (AlertTier.MEDIUM, AlertTier.HIGH)


__all__ = ["should_escalate"]
