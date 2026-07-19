"""Channel machinery: IMAP broker, ingest, cascades, watchers, brand, platform."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from envelock.channels.external.brand import (
    DmarcPosture,
    build_takedown,
    parse_dmarc_report,
    summarise_spoofing,
)
from envelock.channels.mail.broker import EgressPool, ImapBroker, Strategy, strategy_for
from envelock.channels.mail.ingest import (
    ForwardingIngest,
    ingest_address,
    tenant_token_from,
)
from envelock.channels.mail.providers import ForwardingProvider, GraphProvider
from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.detections.cascade import (
    AttachmentCascade,
    Layer,
    UrlCascade,
    Verdict,
    VerdictCache,
    static_triage,
)
from envelock.notify.ladder import Rung
from envelock.notify.senders import Dispatcher, Notification
from envelock.platform.graph import (
    CounterpartyGraph,
    RiskProfile,
    plan_backfill,
    simulations,
)
from envelock.platform.graph import (
    Verdict as GraphVerdict,
)
from envelock.platform.remediation import (
    RemediationAction,
    imap_commands,
    plan_remediation,
)
from envelock.workers.watchers import CertTransparencyWatcher, ZoneFileWatcher


# ── IMAP broker (PRD §5.3, §12.11D) ──────────────────────────────────────────
def test_protected_holds_idle_monitored_polls() -> None:
    """The decision that keeps whole-domain coverage affordable."""
    assert strategy_for(MailboxClass.PROTECTED) is Strategy.IDLE
    assert strategy_for(MailboxClass.MONITORED) is Strategy.POLL


def test_egress_pool_spreads_load_and_reports_exhaustion() -> None:
    pool = EgressPool(["10.0.0.1", "10.0.0.2"], per_ip_limit=2)
    assert pool.capacity == 4
    ips = [pool.acquire() for _ in range(4)]
    assert sorted(ips) == ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2"]
    assert pool.exhausted
    assert pool.acquire() is None

    pool.release("10.0.0.1")
    assert not pool.exhausted


def test_broker_degrades_to_polling_rather_than_dropping_a_mailbox() -> None:
    """Providers cap connections per source IP. Reduced latency beats no
    coverage, and the degradation is visible rather than silent."""
    broker = ImapBroker(egress_ips=["10.0.0.1"], per_ip_limit=1, jitter_seconds=0)
    first = broker.register(
        mailbox_id=uuid4(), address="a@x.com", host="imap.x.com", port=993,
        mailbox_class=MailboxClass.PROTECTED,
    )
    second = broker.register(
        mailbox_id=uuid4(), address="b@x.com", host="imap.x.com", port=993,
        mailbox_class=MailboxClass.PROTECTED,
    )
    assert first.strategy is Strategy.IDLE
    assert second.strategy is Strategy.POLL
    assert broker.stats.degraded_to_poll == 1


def test_idle_refresh_beats_the_rfc_limit() -> None:
    """IMAP servers drop IDLE at 29 minutes; we must re-issue before that."""
    broker = ImapBroker(egress_ips=[""], jitter_seconds=0)
    conn = broker.register(
        mailbox_id=uuid4(), address="a@x.com", host="h", port=993,
        mailbox_class=MailboxClass.PROTECTED,
    )
    assert broker.next_wake(conn) < 29 * 60


def test_backoff_is_bounded() -> None:
    broker = ImapBroker(egress_ips=[""])
    assert broker.backoff(1) < broker.backoff(6)
    assert broker.backoff(50) <= 305


def test_unregister_returns_the_egress_slot() -> None:
    broker = ImapBroker(egress_ips=["10.0.0.1"], per_ip_limit=1, jitter_seconds=0)
    mailbox_id = uuid4()
    broker.register(
        mailbox_id=mailbox_id, address="a@x.com", host="h", port=993,
        mailbox_class=MailboxClass.PROTECTED,
    )
    assert broker.pool.exhausted
    broker.unregister(mailbox_id)
    assert not broker.pool.exhausted


# ── Tier 4 ingest ────────────────────────────────────────────────────────────
def test_ingest_address_round_trips() -> None:
    address = ingest_address("abc12345")
    assert tenant_token_from(address) == "abc12345"
    assert tenant_token_from("someone@example.com") is None


@pytest.mark.asyncio
async def test_ingest_rejects_unknown_tenants() -> None:
    seen = []

    async def resolve(token):  # noqa: ANN001, ANN202
        return uuid4() if token == "good1234" else None  # noqa: S105 — ingest token, not a secret

    async def on_message(*, tenant_id, raw):  # noqa: ANN001, ANN003
        seen.append(raw)

    ingest = ForwardingIngest(resolve_tenant=resolve, on_message=on_message)
    assert (await ingest.handle_rcpt(ingest_address("good1234"))).accepted
    assert not (await ingest.handle_rcpt(ingest_address("bad00000"))).accepted

    result = await ingest.handle_data(recipient=ingest_address("good1234"), raw=b"raw")
    assert result.accepted and seen == [b"raw"]


def test_forwarding_never_quarantines() -> None:
    assert ForwardingProvider().configured is True  # needs no credentials


def test_unconfigured_provider_reports_honestly() -> None:
    status = GraphProvider().status()
    assert status["configured"] in (True, False)
    if not status["configured"]:
        assert status["reason"] == "credentials not set"


# ── Attachment cascade (PRD §12.12A) ─────────────────────────────────────────
def test_static_triage_catches_executables_and_disguises() -> None:
    assert static_triage(filename="a.pdf", payload=b"MZ\x90\x00").verdict is Verdict.MALICIOUS
    disguised = static_triage(
        filename="invoice.png", payload=b"MZ\x90\x00", declared_mime="image/png"
    )
    assert disguised.verdict is Verdict.MALICIOUS
    assert static_triage(filename="a.txt", payload=b"hello there").verdict is Verdict.CLEAN


def test_pdf_with_javascript_is_suspicious_not_clean() -> None:
    result = static_triage(filename="inv.pdf", payload=b"%PDF-1.7 /JavaScript foo")
    assert result.verdict is Verdict.SUSPICIOUS


def test_clean_verdicts_expire_but_malicious_never_does() -> None:
    cache = VerdictCache(clean_ttl_days=7)
    now = datetime.now(UTC)
    cache.put("clean", Verdict.CLEAN, now=now)
    cache.put("bad", Verdict.MALICIOUS, now=now)

    later = now + timedelta(days=8)
    assert cache.get("clean", now=later) is None, "clean-today can be flagged-tomorrow"
    assert cache.get("bad", now=later) is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_cascade_resolves_at_the_free_layers() -> None:
    cascade = AttachmentCascade(detonation_enabled=False)
    result = await cascade.analyse(
        sha256="h1", filename="report.txt", payload=b"just some text"
    )
    assert result.layer is Layer.STATIC
    assert cascade.metrics.detonations == 0

    # Second sighting of the same hash costs nothing at all.
    again = await cascade.analyse(sha256="h1", filename="report.txt", payload=b"x")
    assert again.layer is Layer.CACHE
    assert cascade.metrics.cache_hits == 1


@pytest.mark.asyncio
async def test_fallthrough_rate_is_metered() -> None:
    """The single number that predicts COGS."""
    cascade = AttachmentCascade(detonation_enabled=False)
    for i in range(20):
        await cascade.analyse(sha256=f"h{i}", filename="a.txt", payload=b"text")
    payload = cascade.metrics.payload()
    assert payload["attachments_seen"] == 20
    assert payload["within_target"] is True


@pytest.mark.asyncio
async def test_url_cascade_flags_without_paying() -> None:
    urls = UrlCascade(feed_domains=frozenset({"evil.example"}))
    assert (await urls.check("http://evil.example/x")).verdict is Verdict.MALICIOUS
    assert (await urls.check("http://192.168.1.1/login")).verdict is Verdict.SUSPICIOUS
    assert (await urls.check("http://bit.ly/abc")).verdict is Verdict.SUSPICIOUS
    assert urls.metrics.paid_calls == 0


# ── Remediation (E2) ─────────────────────────────────────────────────────────
def test_forwarding_cannot_quarantine_but_imap_can() -> None:
    caps = frozenset({Capability.READ_INBOUND, Capability.MODIFY_MESSAGE})

    forwarded = plan_remediation(
        action=RemediationAction.QUARANTINE,
        capabilities=caps,
        source=SourceMechanism.FORWARD_INGEST,
    )
    assert not forwarded.succeeded
    assert forwarded.alert_only

    imap = plan_remediation(
        action=RemediationAction.QUARANTINE,
        capabilities=caps,
        source=SourceMechanism.IMAP_IDLE,
    )
    assert imap.succeeded


def test_imap_move_is_the_quarantine_mechanism() -> None:
    commands = imap_commands(RemediationAction.QUARANTINE, 42)
    assert commands == ['UID MOVE 42 "Envelock Quarantine"']


# ── Channel 3 watchers ───────────────────────────────────────────────────────
def test_ct_watcher_matches_only_lookalikes() -> None:
    hits: list = []
    watcher = CertTransparencyWatcher(
        protected_domains=frozenset({"gemini.com"}), on_match=hits.append
    )
    watcher.handle_certificate(
        ["*.unrelated.com", "gemini-invoices.com", "example.org", "gemíni.com"]
    )
    assert {h.domain for h in hits} >= {"gemini-invoices.com"}
    assert watcher.stats.observed == 4
    assert watcher.stats.matched == len(hits)


def test_zone_file_scan_dedupes() -> None:
    watcher = ZoneFileWatcher(protected_domains=frozenset({"acme.com"}))
    hits = watcher.scan_zone(
        ["acme-invoices.com. 3600 IN NS a.gtld.net.", "acme-invoices.com. 3600 IN NS b.gtld.net.",
         "unrelated.com. 3600 IN NS c.gtld.net."]
    )
    assert len(hits) == 1


def test_zone_watcher_reports_unconfigured_without_failing() -> None:
    status = ZoneFileWatcher().status()
    assert status["source"] == "czds"
    assert "Certificate Transparency" in status["covers"]


# ── Brand (D5–D7) ────────────────────────────────────────────────────────────
def test_dmarc_p_none_is_not_protection() -> None:
    posture = DmarcPosture(
        domain="acme.com", spf_present=True, spf_record="v=spf1 -all",
        dkim_selectors_found=("default",), dmarc_present=True, dmarc_policy="none",
        dmarc_pct=100, rua_configured=False, rua_points_to_us=False,
    )
    assert not posture.protected
    assert posture.tier is AlertTier.MEDIUM
    assert any("quarantine" in r for r in posture.recommendations)


def test_dmarc_report_identifies_spoof_sources() -> None:
    xml = """<feedback><record><row><source_ip>203.0.113.5</source_ip>
    <count>42</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf>
    </policy_evaluated></row><identifiers><header_from>acme.com</header_from>
    </identifiers></record></feedback>"""
    sources = parse_dmarc_report(xml)
    assert sources[0].is_spoof
    summary = summarise_spoofing(sources)
    assert summary["spoofed_messages"] == 42
    assert summary["tier"] is AlertTier.HIGH


def test_takedown_packet_names_the_technique() -> None:
    packet = build_takedown(
        candidate="acrne.com", protected="acme.com", technique="homoglyph", has_mx=True
    )
    assert "acrne.com" in packet.subject
    assert "homoglyph" in packet.body
    assert packet.evidence["has_mx"] is True


# ── Counterparty graph (E8) ──────────────────────────────────────────────────
def test_graph_needs_independent_confirmations() -> None:
    graph = CounterpartyGraph()
    tenant_a, tenant_b = uuid4(), uuid4()

    entry = graph.report(domain="bad.com", verdict=GraphVerdict.FRAUDULENT, tenant_id=tenant_a)
    assert not entry.actionable, "one tenant's word is not enough"

    # The same tenant reporting twice must not inflate confidence.
    graph.report(domain="bad.com", verdict=GraphVerdict.FRAUDULENT, tenant_id=tenant_a)
    assert not graph.lookup("bad.com").actionable

    entry = graph.report(domain="bad.com", verdict=GraphVerdict.FRAUDULENT, tenant_id=tenant_b)
    assert entry.actionable
    assert "bad.com" in graph.known_bad()


def test_risk_profile_scores_and_advises() -> None:
    unknown = RiskProfile(
        domain="new.com", first_seen=None, message_count=1, bank_records=0,
        verified_phone=None, auth_pass_rate=0.5, incidents=0,
        graph_verdict=None, domain_age_days=10,
    )
    assert unknown.score >= 50
    assert "phone" in unknown.advice.lower()

    known_bad = RiskProfile(
        domain="bad.com", first_seen=None, message_count=50, bank_records=1,
        verified_phone="+1", auth_pass_rate=1.0, incidents=0,
        graph_verdict=GraphVerdict.FRAUDULENT, domain_age_days=900,
    )
    assert known_bad.score == 100
    assert "Do not pay" in known_bad.advice


# ── Backfill and simulation (E11, E12) ───────────────────────────────────────
def test_trial_backfill_is_capped() -> None:
    assert plan_backfill(mailbox_id=uuid4(), in_trial=True).days == 30
    assert plan_backfill(mailbox_id=uuid4(), in_trial=False).days == 90


def test_simulations_are_labelled_so_they_cannot_be_mistaken_for_real() -> None:
    sims = simulations(protected_domain="acme.com.ng", vendor_domain="supplier.com")
    assert len(sims) >= 4
    for sim in sims:
        assert "X-Envelock-Simulation: true" in sim.raw_message


# ── Notification ladder delivery ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_in_app_always_delivers_and_sms_is_gated() -> None:
    dispatcher = Dispatcher()
    notification = Notification(
        alert_id=uuid4(), tenant_id=uuid4(), tier=AlertTier.CRITICAL,
        title="Bank details changed", body="verify by phone",
    )
    results = await dispatcher.dispatch(
        notification,
        rungs=(Rung.L0_IN_APP, Rung.L3_SMS),
        destinations={Rung.L0_IN_APP: "user-1", Rung.L3_SMS: "+2348030000000"},
    )
    by_rung = {r.rung: r for r in results}
    assert by_rung[Rung.L0_IN_APP].delivered
    # SMS is the only metered rung; unset provider means it simply does not fire.
    assert by_rung[Rung.L3_SMS].delivered == dispatcher.sms.configured


def test_sms_body_is_a_nudge_not_the_fraud_detail() -> None:
    notification = Notification(
        alert_id=uuid4(), tenant_id=uuid4(), tier=AlertTier.CRITICAL,
        title="X" * 300, body="full detail that must not be in an SMS",
    )
    text = Dispatcher().sms.compose(notification)
    assert len(text) <= 160
    assert "full detail" not in text
