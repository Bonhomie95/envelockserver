"""The AI cascade — an LLM BEC-intent judge that sits at the *last* rung.

Free rule detections and free feeds resolve the overwhelming majority of mail.
Only the small fraction that trips a rule signal but stays ambiguous is escalated
to an LLM, which confirms or escalates the verdict (never silently suppresses a
rule verdict) and explains why in plain language. The provider is pluggable —
Anthropic, OpenAI, or any OpenAI-compatible local server — selected in `.env`.
"""

from envelock.llm.base import LlmError, LlmProvider, LlmVerdict, Transport
from envelock.llm.judge import Judge
from envelock.llm.providers import get_provider

__all__ = [
    "Judge",
    "LlmError",
    "LlmProvider",
    "LlmVerdict",
    "Transport",
    "get_provider",
]
