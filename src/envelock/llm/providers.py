"""Concrete LLM providers, selected by `ENVELOCK_LLM_PROVIDER`.

Each speaks its vendor's native chat endpoint over raw HTTP (behind the injectable
`Transport`), asks for a JSON object back, and reports token usage so the cascade
can meter cost. Adding a provider is a new class here, never a branch in the judge.
"""

from __future__ import annotations

import json
import re

from envelock.config import get_settings
from envelock.llm.base import HttpxTransport, LlmError, Transport

#: Rough list prices ($/1M tokens) for cost metering only — not billing. Keyed by
#: a model-name prefix so minor version suffixes still match.
_PRICE_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-haiku": (1.0, 5.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-opus": (5.0, 25.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.0, 8.0),
}


def _cost_micros(model: str, tin: int, tout: int) -> int:
    for prefix, (pin, pout) in _PRICE_PER_MTOK.items():
        if model.startswith(prefix):
            dollars = (tin / 1_000_000) * pin + (tout / 1_000_000) * pout
            return int(round(dollars * 1_000_000))
    return 0  # local / unknown model: no metered cost


def _extract_json(text: str) -> dict:
    """Parse a JSON object out of a model's text response, tolerating code fences
    or a leading sentence."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise LlmError(f"model did not return JSON: {text[:200]}") from None


# ── Anthropic (Messages API) ──────────────────────────────────────────────────
class AnthropicProvider:
    name = "anthropic"

    def __init__(self, transport: Transport | None = None) -> None:
        s = get_settings()
        self.model = s.anthropic_model
        self._key = s.anthropic_api_key.get_secret_value() if s.anthropic_api_key else None
        self._base = s.anthropic_base_url.rstrip("/")
        self._transport = transport or HttpxTransport(s.llm_timeout_seconds)

    @property
    def configured(self) -> bool:
        return bool(self._key)

    async def complete_json(self, *, system: str, user: str, max_tokens: int) -> dict:
        if not self.configured:
            raise LlmError("anthropic api key not configured")
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self._key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = await self._transport.post_json(
            f"{self._base}/v1/messages", headers=headers, body=body
        )
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))
        result = _extract_json(text)
        result["_usage"] = {
            "in": tin, "out": tout, "cost_micros": _cost_micros(self.model, tin, tout),
        }
        return result


# ── OpenAI (and OpenAI-compatible "local") ───────────────────────────────────
class OpenAIProvider:
    name = "openai"

    def __init__(self, transport: Transport | None = None, *, local: bool = False) -> None:
        s = get_settings()
        if local:
            self.name = "local"
            self.model = s.local_llm_model
            self._key = (
                s.local_llm_api_key.get_secret_value() if s.local_llm_api_key else "sk-local"
            )
            self._base = s.local_llm_base_url.rstrip("/")
            #: A local server is "configured" whenever a base URL is set — no key needed.
            self._require_key = False
        else:
            self.model = s.openai_model
            self._key = s.openai_api_key.get_secret_value() if s.openai_api_key else None
            self._base = s.openai_base_url.rstrip("/")
            self._require_key = True
        self._transport = transport or HttpxTransport(s.llm_timeout_seconds)

    @property
    def configured(self) -> bool:
        if self._require_key:
            return bool(self._key)
        return bool(self._base)

    async def complete_json(self, *, system: str, user: str, max_tokens: int) -> dict:
        if not self.configured:
            raise LlmError(f"{self.name} not configured")
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"content-type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        data = await self._transport.post_json(
            f"{self._base}/chat/completions", headers=headers, body=body
        )
        choices = data.get("choices") or []
        if not choices:
            raise LlmError(f"{self.name} returned no choices: {str(data)[:200]}")
        text = (choices[0].get("message") or {}).get("content") or ""
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
        result = _extract_json(text)
        result["_usage"] = {
            "in": tin, "out": tout, "cost_micros": _cost_micros(self.model, tin, tout),
        }
        return result


def get_provider(transport: Transport | None = None):  # noqa: ANN201
    """Build the provider named by `ENVELOCK_LLM_PROVIDER`. Returns None when the
    cascade is off, so callers can cheaply skip it."""
    name = get_settings().llm_provider
    if name == "none":
        return None
    if name == "anthropic":
        return AnthropicProvider(transport)
    if name == "openai":
        return OpenAIProvider(transport)
    if name == "local":
        return OpenAIProvider(transport, local=True)
    return None
