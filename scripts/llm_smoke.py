"""Live smoke test for the AI cascade against a real provider.

Reads the provider + key from the environment (.env), sends one clearly-fraudulent
and one clearly-benign message through the real judge, and prints the verdicts,
token usage and metered cost. Run:

    ENVELOCK_LLM_PROVIDER=openai python -m scripts.llm_smoke
"""

from __future__ import annotations

import asyncio

from envelock.config import get_settings
from envelock.llm.judge import Judge
from envelock.llm.providers import get_provider

FRAUD = (
    "Hi, this is urgent and confidential — do not discuss with anyone. Our bank "
    "changed; please wire the outstanding $48,200 today to the new account IBAN "
    "GB33BUKB20201555555555. Send confirmation once done."
)
BENIGN = (
    "Hi team, attaching the minutes from Tuesday's planning call. Let me know if "
    "you spot anything I missed. Thanks!"
)


async def main() -> None:
    s = get_settings()
    provider = get_provider()
    if provider is None:
        print("LLM cascade is off — set ENVELOCK_LLM_PROVIDER (openai|anthropic|local).")
        return
    if not provider.configured:
        print(f"Provider '{provider.name}' is not configured — add its API key to .env.")
        return

    print(f"Provider: {provider.name}  Model: {provider.model}\n")
    judge = Judge(provider)

    for label, body, signals in [
        ("FRAUD sample", FRAUD, ["A2", "A4", "A14"]),
        ("BENIGN sample", BENIGN, ["A7"]),
    ]:
        v = await judge.evaluate(
            sender="billing@vendor-example.com",
            subject="Payment",
            body=body,
            signals=signals,
        )
        if v is None:
            print(f"{label}: judge returned nothing (see logs).")
            continue
        cost = v.cost_micros / 1_000_000
        print(
            f"{label}: verdict={v.verdict} confidence={v.confidence:.0%} "
            f"escalate={v.escalate}\n  rationale: {v.rationale}\n"
            f"  tokens in/out={v.input_tokens}/{v.output_tokens}  cost=${cost:.6f}\n"
        )

    print(f"(cap: {s.llm_max_calls_per_mailbox_month} calls/mailbox/month, "
          f"min confidence to act: {s.llm_min_confidence})")


if __name__ == "__main__":
    asyncio.run(main())
