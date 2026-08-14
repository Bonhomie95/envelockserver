"""Tests for the AI cascade: providers (via injectable transport), the gate, the
judge, and the pipeline refinement — all without a live LLM or an API key."""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.risk.engine import assess

OWNED = frozenset({"acme.com"})
KNOWN = frozenset({"gemini.com"})


class _FakeTransport:
    """Returns a canned provider response and records the request."""

    def __init__(self, response: dict) -> None:
        self.response = response
        self.calls: list[dict] = []

    async def post_json(self, url, *, headers, body):  # noqa: ANN001
        self.calls.append({"url": url, "headers": headers, "body": body})
        return self.response


# ── Providers parse their vendor's shape into a verdict ──────────────────────
@pytest.mark.asyncio
async def test_openai_provider_parses_chat_completion(monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.llm.judge import Judge
    from envelock.llm.providers import OpenAIProvider

    monkeypatch.setenv("ENVELOCK_OPENAI_API_KEY", "sk-test")
    get_settings.cache_clear()
    try:
        transport = _FakeTransport({
            "choices": [
                {"message": {"content": '{"verdict":"fraud","confidence":0.9,'
                                        '"rationale":"new IBAN"}'}}
            ],
            "usage": {"prompt_tokens": 800, "completion_tokens": 30},
        })
        provider = OpenAIProvider(transport)
        assert provider.configured
        verdict = await Judge(provider).evaluate(
            sender="billing@gemini.com", subject="Invoice",
            body="pay to new account", signals=["A2", "A4"],
        )
        assert verdict is not None
        assert verdict.is_fraud and verdict.escalate
        assert verdict.confidence == pytest.approx(0.9)
        assert verdict.input_tokens == 800
        assert verdict.cost_micros > 0  # gpt-4o-mini priced
        # It really hit the chat/completions endpoint with json response_format.
        assert transport.calls[0]["url"].endswith("/chat/completions")
        assert transport.calls[0]["body"]["response_format"] == {"type": "json_object"}
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_anthropic_provider_parses_messages_api(monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.llm.judge import Judge
    from envelock.llm.providers import AnthropicProvider

    monkeypatch.setenv("ENVELOCK_ANTHROPIC_API_KEY", "sk-ant-test")
    get_settings.cache_clear()
    try:
        transport = _FakeTransport({
            "content": [
                {"type": "text",
                 "text": '{"verdict":"benign","confidence":0.8,"rationale":"ok"}'}
            ],
            "usage": {"input_tokens": 500, "output_tokens": 20},
        })
        provider = AnthropicProvider(transport)
        verdict = await Judge(provider).evaluate(
            sender="ap@supplier.com", subject="Invoice 12", body="usual invoice", signals=["A7"]
        )
        assert verdict is not None
        assert verdict.is_benign and not verdict.escalate
        assert transport.calls[0]["url"].endswith("/v1/messages")
        assert transport.calls[0]["headers"]["anthropic-version"] == "2023-06-01"
    finally:
        get_settings.cache_clear()


def test_local_provider_needs_no_key(monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.llm.providers import OpenAIProvider

    get_settings.cache_clear()
    try:
        provider = OpenAIProvider(_FakeTransport({}), local=True)
        assert provider.name == "local"
        assert provider.configured  # base URL is enough, no key required
    finally:
        get_settings.cache_clear()


# ── The gate escalates only the ambiguous payment band ───────────────────────
def test_gate_only_escalates_medium_high_payment() -> None:
    from envelock.llm.gate import should_escalate
    from envelock.risk.engine import RiskAssessment

    def a(tier, services):
        return RiskAssessment(
            tier=tier, score=50, title="t", body="b", services=tuple(services),
            requires_callback=False, callback_phone=None, rationale=(),
        )

    assert should_escalate(a(AlertTier.HIGH, ["A2", "A4"])) is True
    assert should_escalate(a(AlertTier.MEDIUM, ["A7"])) is True
    # No payment/impersonation signal → skip.
    assert should_escalate(a(AlertTier.HIGH, ["C6"])) is False
    # Already Critical → the human is already interrupted; don't pay for a call.
    assert should_escalate(a(AlertTier.CRITICAL, ["A1"])) is False
    # Low is logged, not alerted.
    assert should_escalate(a(AlertTier.LOW, ["A14"])) is False
    assert should_escalate(None) is False


# ── The pipeline refinement promotes on a confident fraud verdict ────────────
class _FakeProvider:
    name = "openai"
    model = "gpt-4o-mini"
    configured = True

    def __init__(self, verdict: dict) -> None:
        self._verdict = verdict

    async def complete_json(self, *, system, user, max_tokens):  # noqa: ANN001
        return {**self._verdict, "_usage": {"in": 700, "out": 25, "cost_micros": 120}}


# A typosquat sender with urgency but NO bank identifiers → A3 fires High, but with
# a verified phone on file A2 stays silent, so no novel-vendor combo reaches
# Critical. This is exactly the ambiguous High band the AI judge is meant to review.
_HIGH_BAND = """\
From: "Gemini Accounts" <billing@gemini-invoices.com>
To: pay@acme.com
Subject: Outstanding payment
Message-ID: <x@gemini-invoices.com>
Content-Type: text/plain

Please process the outstanding invoice payment urgently, today.
See the attached invoice for details.
"""


def _high_band_assessment():
    event = parse_message(
        _HIGH_BAND.encode(), tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
    )
    cp = CounterpartyState(registrable_domain="gemini-invoices.com", message_count=0,
                           known_bank_ids=frozenset(), verified_phone="+18030000000")
    ctx = DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, known_counterparties=KNOWN, counterparty=cp,
    )
    return event, assess(run_all(ctx))


_RANK = {AlertTier.LOW: 0, AlertTier.MEDIUM: 1, AlertTier.HIGH: 2, AlertTier.CRITICAL: 3}


@pytest.mark.asyncio
async def test_cascade_promotes_one_tier_on_fraud(session) -> None:
    from envelock.llm.cascade import refine

    event, assessment = _high_band_assessment()
    assert assessment is not None
    if assessment.tier is AlertTier.CRITICAL:
        pytest.skip("rules already Critical; escalation path not exercised")
    original = assessment.tier

    tid = uuid4()
    provider = _FakeProvider(
        {"verdict": "fraud", "confidence": 0.95, "rationale": "impersonated vendor"}
    )
    refined, verdict = await refine(session, event, assessment, tenant_id=tid, provider=provider)
    assert verdict is not None and verdict.is_fraud
    # A confident fraud verdict raises the tier exactly one step.
    assert _RANK[refined.tier] == _RANK[original] + 1
    # Client-facing rationale is plain and carries no confidence % or model name.
    ai_line = next(r for r in refined.rationale if "fraud check" in r)
    assert "%" not in ai_line and "gpt-4o-mini" not in ai_line and "openai" not in ai_line
    # A promotion to Critical also arms the callback.
    if refined.tier is AlertTier.CRITICAL:
        assert refined.requires_callback is True

    # Usage was metered for the cap/COGS view.
    from sqlalchemy import select

    from envelock.models import LlmUsage
    rows = (
        await session.execute(select(LlmUsage).where(LlmUsage.tenant_id == tid))
    ).scalars().all()
    assert len(rows) == 1 and rows[0].calls == 1 and rows[0].cost_micros == 120


@pytest.mark.asyncio
async def test_cascade_never_demotes_and_respects_cap(session, monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.llm.cascade import refine
    from envelock.models import LlmUsage

    event, assessment = _high_band_assessment()
    if assessment and assessment.tier is AlertTier.CRITICAL:
        pytest.skip("rules already Critical")
    original_tier = assessment.tier
    tid = uuid4()

    # Benign verdict must NOT lower the rule tier.
    benign = _FakeProvider({"verdict": "benign", "confidence": 0.99, "rationale": "looks routine"})
    refined, _ = await refine(session, event, assessment, tenant_id=tid, provider=benign)
    assert refined.tier is original_tier  # unchanged — recall preserved

    # The benign call already metered one use for this mailbox+month.
    from sqlalchemy import select
    row = (
        await session.execute(select(LlmUsage).where(LlmUsage.tenant_id == tid))
    ).scalar_one()
    assert row.calls == 1

    # Cap at 1: the next call must not run.
    monkeypatch.setenv("ENVELOCK_LLM_MAX_CALLS_PER_MAILBOX_MONTH", "1")
    get_settings.cache_clear()
    try:
        provider = _FakeProvider({"verdict": "fraud", "confidence": 0.99, "rationale": "x"})
        refined2, verdict2 = await refine(
            session, event, assessment, tenant_id=tid, provider=provider
        )
        assert verdict2 is None  # capped — judge not called
        assert refined2.tier is original_tier
    finally:
        get_settings.cache_clear()
