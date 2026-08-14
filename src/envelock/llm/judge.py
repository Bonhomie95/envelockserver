"""The BEC-intent judge: build a tight classification prompt, call the provider,
and return a structured `LlmVerdict`. Confidential detection logic stays server-
side — the prompt describes the *task* (is this business-email-compromise?), never
our internal signal weights or thresholds (PRD §16)."""

from __future__ import annotations

import logging

from envelock.llm.base import LlmError, LlmProvider, LlmVerdict

logger = logging.getLogger("envelock.llm")

_SYSTEM = (
    "You are a fraud analyst reviewing one inbound business email that automated "
    "checks already flagged as possibly suspicious. Decide whether it is business "
    "email compromise (BEC) / payment fraud — e.g. a request to send or redirect "
    "money to a new account, a fake invoice, an impersonated vendor or executive, "
    "or urgency/secrecy pressure around a payment. A legitimate but unusual invoice "
    "is NOT fraud. Respond ONLY with a JSON object: "
    '{"verdict": "fraud"|"suspicious"|"benign", "confidence": 0.0-1.0, '
    '"rationale": "one concise sentence"}. Be conservative: reserve "fraud" for '
    "clear payment-fraud intent."
)

#: Redaction cap — keep the prompt small and never ship a whole thread to the LLM.
_MAX_BODY = 4000


def _build_user_prompt(*, sender: str, subject: str, body: str, signals: list[str]) -> str:
    body = (body or "")[:_MAX_BODY]
    return (
        f"From: {sender}\n"
        f"Subject: {subject or '(none)'}\n"
        f"Automated signals: {', '.join(signals) or 'none'}\n\n"
        f"Body:\n{body}"
    )


class Judge:
    """Wraps a provider with the BEC prompt and turns its JSON into a verdict."""

    def __init__(self, provider: LlmProvider) -> None:
        self.provider = provider

    async def evaluate(
        self, *, sender: str, subject: str, body: str, signals: list[str], max_tokens: int = 300
    ) -> LlmVerdict | None:
        user = _build_user_prompt(sender=sender, subject=subject, body=body, signals=signals)
        try:
            data = await self.provider.complete_json(
                system=_SYSTEM, user=user, max_tokens=max_tokens
            )
        except LlmError as exc:
            logger.warning("llm judge failed (%s): %s", self.provider.name, exc)
            return None

        verdict = str(data.get("verdict", "suspicious")).lower()
        if verdict not in ("fraud", "suspicious", "benign"):
            verdict = "suspicious"
        try:
            confidence = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))
        usage = data.get("_usage") or {}
        return LlmVerdict(
            verdict=verdict,
            confidence=confidence,
            rationale=str(data.get("rationale", ""))[:500],
            # Only a confident fraud verdict escalates; the engine decides the action.
            escalate=(verdict == "fraud"),
            provider=self.provider.name,
            model=self.provider.model,
            input_tokens=int(usage.get("in", 0)),
            output_tokens=int(usage.get("out", 0)),
            cost_micros=int(usage.get("cost_micros", 0)),
            raw=data,
        )


__all__ = ["Judge"]
