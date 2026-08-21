"""Configuration, loaded from environment / .env.

Mirrors .env.example one-for-one. Optional providers default to unset: a missing
provider disables the detections that depend on it and downgrades the mailbox's
protection level (PRD P4) rather than failing at runtime or silently pretending
coverage exists.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ENVELOCK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    env: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"  # noqa: S104
    api_port: int = 8010
    #: Trust the client IP in `X-Forwarded-For`. Enable ONLY when the app sits
    #: behind a proxy you control (nginx, a load balancer, Cloudflare) — otherwise
    #: every client shares the proxy's single IP and rate limits apply globally.
    #: Off by default because a spoofable header would otherwise bypass throttling.
    trust_forwarded_for: bool = False

    secret_key: SecretStr = SecretStr("")

    # ── Credential key custody (PRD §5.2) ────────────────────────────────────
    # We store hundreds of businesses' mailbox passwords. Which provider wraps the
    # per-secret data key — and, critically, whether THIS process can unwrap it —
    # is the difference between "a compromised web pod leaks one request" and "a
    # compromised web pod leaks every credential we hold". See security/keys.py.
    #
    #   local   — AES-GCM under credential_master_key. Development only.
    #   x25519  — public-key wrapping; the API gets only the public half.
    #             Recommended for self-hosted production.
    #   aws     — AWS KMS Encrypt/Decrypt, split by IAM.
    #   gcp     — Cloud KMS encrypt/decrypt, split by IAM.
    #   auto    — infer from whichever key material is set (the default).
    credential_key_provider: Literal["auto", "local", "x25519", "aws", "gcp"] = "auto"

    credential_master_key: SecretStr = SecretStr("")

    #: base64 X25519 public key. Set this ALONE on the API to make it structurally
    #: incapable of reading the credential store. Generate a pair with
    #: `python -m envelock.security.keygen`.
    credential_public_key: str | None = None
    #: base64 X25519 private key. Set ONLY on the worker/broker deployment.
    credential_private_key: SecretStr | None = None

    kms_key_id: str | None = None
    kms_provider: Literal["aws", "gcp"] | None = None
    kms_region: str | None = None
    #: Declares that this process's IAM role is granted Decrypt. It is a statement
    #: about the deployment, not something we can probe — an API pod should leave
    #: it false so an attempt to decrypt fails loudly here rather than succeeding
    #: because someone over-granted the role.
    credential_can_decrypt: bool = True

    # ── Datastores ───────────────────────────────────────────────────────────
    postgres_dsn: str = "postgresql+asyncpg://envelock:envelock@localhost:5432/envelock"
    #: Disable connection pooling — set only for the test suite, where many short
    #: event loops would otherwise reuse a connection across loops. Production
    #: keeps pooling for performance.
    db_nullpool: bool = False
    redis_dsn: str = "redis://localhost:6379/0"
    #: "memory" (single instance) or "redis" (shared across instances, PRD §17.3).
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    clickhouse_dsn: str = "clickhouse://envelock:envelock@localhost:8123/envelock"
    kafka_bootstrap: str = "localhost:19092"
    kafka_topic_events: str = "envelock.events"

    # ── Channel 1: Tier 1 ────────────────────────────────────────────────────
    ms_client_id: str | None = None
    ms_client_secret: SecretStr | None = None
    ms_redirect_uri: str | None = None
    ms_webhook_url: str | None = None

    #: Shared secret a provider must present on the push endpoints. Graph carries
    #: it in the subscription's signed `clientState`; Gmail Pub/Sub appends it to
    #: the push URL as `?token=`. Without it those endpoints are unauthenticated
    #: cross-tenant triggers, so an unset secret means "reject every push" in
    #: production. Defaults to the app secret key when unset.
    webhook_shared_secret: SecretStr | None = None

    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    google_redirect_uri: str | None = None
    google_pubsub_topic: str | None = None

    # ── Channel 1: Tier 3 IMAP broker (PRD §5.3, §12.11D) ────────────────────
    imap_idle_enabled: bool = True
    imap_monitored_poll_seconds: int = 900
    imap_max_connections_per_egress_ip: int = 15
    """MEASURE this per provider before launch — it is the dominant Tier 3 cost
    driver and it is set by provider policy, not by our efficiency."""

    imap_idle_refresh_seconds: int = 1500
    imap_reconnect_jitter_seconds: int = 120
    imap_egress_ips: str = ""

    #: The live IMAP poll worker (workers/imap_fetch). On by default so a
    #: connected mailbox is actually read; the poll cadence is the protection
    #: latency for Monitored mailboxes and the fallback for Protected ones.
    #: Disabled in the test suite, which drives the worker directly.
    imap_poll_worker_enabled: bool = True
    imap_poll_worker_seconds: int = 60

    #: Allow an IMAP connection to a loopback/private/link-local address. OFF by
    #: default: the host comes straight from a customer form, so without this
    #: guard "test connection" is a blind port scanner pointed at our own
    #: infrastructure (including the cloud metadata endpoint). Turn it on only
    #: for a self-hosted deployment whose mail server really is on the LAN.
    imap_allow_private_hosts: bool = False

    #: Extra ports the IMAP connector may dial, beyond 143/993/1143/2143 —
    #: comma-separated. Restricting ports is what stops the connect form being
    #: used as a general port scanner, so widen this deliberately.
    imap_extra_allowed_ports: str = ""

    #: Per-candidate connect+login budget while probing IMAP settings. The whole
    #: ladder has to fit inside a request the customer is watching.
    imap_probe_timeout_seconds: float = 8.0
    #: How many discovered candidates one probe may dial.
    imap_probe_max_candidates: int = 8

    # ── Channel 1: Tier 4 ────────────────────────────────────────────────────
    ingest_domain: str = "in.envelock.io"
    ingest_smtp_host: str = "0.0.0.0"  # noqa: S104
    ingest_smtp_port: int = 2525
    #: Start the forwarding SMTP listener inside the API process so Tier-4
    #: forwarding works without deploying a separate process. Off by default and
    #: in tests; a dedicated MX host is still the production-scale option.
    ingest_smtp_in_app: bool = False

    # ── Channel 2 ────────────────────────────────────────────────────────────
    vapid_public_key: str | None = None
    vapid_private_key: SecretStr | None = None
    vapid_subject: str = "mailto:security@envelock.io"

    ipinfo_token: SecretStr | None = None
    ipqs_api_key: SecretStr | None = None

    # ── Channel 3 (free-first) ───────────────────────────────────────────────
    certstream_url: str = "wss://certstream.calidog.io/"
    czds_username: str | None = None
    czds_password: SecretStr | None = None
    rdap_bootstrap_url: str = "https://rdap.org/"
    nrd_feed_api_key: SecretStr | None = None
    #: Enrich /domains/scan hits with RDAP registration dates (and sort by them).
    #: On in production; the suite turns it off so scans stay hermetic.
    scan_registration_dates: bool = True

    # ── Detection cascades (PRD §12.12) ──────────────────────────────────────
    safebrowsing_api_key: SecretStr | None = None
    urlhaus_enabled: bool = True

    # ── AI cascade (last rung — LLM BEC-intent judge, PRD §12.11 §12.12) ─────
    #: Provider for the LLM judge: "none" (off, default), "anthropic", "openai",
    #: or "local" (any OpenAI-compatible endpoint — Ollama, vLLM, llama.cpp).
    #: The judge only runs on the small fraction of mail the rules already flag as
    #: ambiguous/risky (the cascade gate), and is capped per mailbox, so cost stays
    #: near-zero. It can confirm or escalate a verdict, never silently suppress one.
    llm_provider: Literal["none", "anthropic", "openai", "local"] = "none"
    #: Hard monthly cap on judge calls per mailbox (COGS guardrail).
    llm_max_calls_per_mailbox_month: int = 200
    #: Confidence (0-1) the judge must reach before it acts on a verdict.
    llm_min_confidence: float = 0.75
    llm_timeout_seconds: float = 20.0

    # Anthropic — cheap, fast Haiku is the right last-rung triage default; raise to
    # a larger model only if the fall-through data justifies it (§12.12D).
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-haiku-4-5"
    anthropic_base_url: str = "https://api.anthropic.com"

    # OpenAI (also the shape used by "local"). gpt-4o-mini is the cost default.
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    # Local / self-hosted OpenAI-compatible server (Ollama default port shown).
    local_llm_base_url: str = "http://localhost:11434/v1"
    local_llm_model: str = "llama3.1"
    local_llm_api_key: SecretStr | None = None

    clamav_host: str = "localhost"
    clamav_port: int = 3310
    yara_rules_path: str = "./rules/yara"
    attachment_cache_ttl_clean_days: int = 14
    detonation_enabled: bool = False
    virustotal_api_key: SecretStr | None = None
    detonation_provider: str | None = None
    detonation_monthly_cap_per_mailbox: int = 150

    # ── Notifications (PRD §8.1) ─────────────────────────────────────────────
    #: Unset by default (like every other provider): L2 email is disabled until a
    #: real SMTP host is configured, rather than silently failing against
    #: localhost. L0 in-app always covers the alert regardless.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "alerts@envelock.io"
    smtp_dkim_private_key_path: str | None = None
    smtp_dkim_selector: str = "envelock"
    smtp_relay_fallback_dsn: str | None = None

    sms_enabled: bool = False
    sms_provider: str | None = None
    sms_api_key: SecretStr | None = None
    sms_sender_id: str = "Envelock"
    #: Provider REST endpoint for SMS. Twilio-style form POST by default; any
    #: provider that accepts an HTTP form/JSON body works via sms_provider.
    sms_api_url: str | None = None
    sms_account_sid: str | None = None  # Twilio account SID (basic-auth user)
    escalate_critical_after_seconds: int = 900
    escalate_unacked_count: int = 5

    # ── Background scheduler (PRD §8.1 E6, §15.2 retention, §17 watchers) ─────
    #: The in-process periodic scheduler that runs everything that must fire on a
    #: timer: E6 escalation, retention purge, OAuth token refresh, and the
    #: Channel-3 domain watchers. Disabled in the test suite (which drives each
    #: job directly); on by default so the product actually *does* things.
    scheduler_enabled: bool = True
    escalation_cycle_seconds: int = 60
    retention_purge_seconds: int = 3600
    oauth_refresh_seconds: int = 1800
    #: How often to re-check that verified domains still have their DNS proof, and
    #: revoke verification if the record was deleted (so access re-gates on the
    #: verify step). Hourly — deletion is rare and revocation is high-impact.
    domain_reverify_seconds: int = 3600
    #: Channel-3 CT-log watcher (certstream). The free Guard tier and the S12
    #: pre-signup demo depend on this running.
    ct_watcher_enabled: bool = True
    #: How often the watcher reloads the set of protected domains from the DB.
    watcher_domain_refresh_seconds: int = 300

    # ── Tenant isolation (PRD §11, §15) ──────────────────────────────────────
    #: Enforce Postgres row-level security by connecting through the restricted
    #: `envelock_app` role and setting the per-request tenant GUC. Off by default
    #: because it requires the RLS migration + role to be provisioned first; when
    #: on, every session sets `envelock.tenant_id` so the DB backstops isolation
    #: even if an application query forgets its `WHERE tenant_id`.
    rls_enabled: bool = False

    #: Require DNS domain-control verification before a mailbox on that domain can
    #: be connected for live mail. On by default so nobody can sign up with a
    #: company address they do not control and receive that company's alerts.
    require_domain_verification: bool = True

    #: At registration, reject an email whose domain doesn't resolve in DNS (no MX
    #: and no A/AAAA) — catches typos/made-up domains like test@hjsbcjsjs.com
    #: before ownership verification. Fails open on a transient DNS failure.
    check_email_domain_exists: bool = True

    # ── Sender-domain reputation (free feeds — user requirement #3) ──────────
    #: DNSBL zones queried for the FROM domain's registrable domain. All free and
    #: DNS-based (no API key). Spamhaus DBL is free for low-volume/non-commercial
    #: — audit terms before high volume (README licensing note).
    domain_reputation_enabled: bool = True
    dnsbl_domain_zones: str = "dbl.spamhaus.org,multi.surbl.org"
    reputation_cache_seconds: int = 3600

    # ── Tier-4 forwarding ingest authentication (PRD §5.4 / security) ────────
    #: Comma-separated CIDR/IP allowlist of forwarders permitted to submit to the
    #: SMTP/HTTP ingest. Empty = allow any (dev only). A per-tenant token in the
    #: RCPT address is necessary but not sufficient; pin the source too.
    ingest_allowed_ips: str = ""

    # ── Billing (PRD §12) ────────────────────────────────────────────────────
    trial_days: int = 15
    trial_backfill_days: int = 30
    backfill_days: int = 90
    #: Max messages a single backfill sweep will pull per mailbox. Generous so
    #: onboarding can scan the whole recent history, bounded so a pathologically
    #: huge mailbox can't stall a worker. A "scan everything" backfill uses this.
    backfill_max_messages: int = 5000

    # Public origin of the web app, used to build Stripe Checkout return URLs
    # (success/cancel). Server-built rather than client-supplied so a caller can't
    # turn checkout into an open redirect. Defaults to the local dev origin.
    public_base_url: str = "http://localhost:5173"

    # Global payment rails. Stripe is the primary processor (North America and
    # global); the regional acquirers cover markets Stripe serves less well.
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    # Stripe Price IDs (recurring, monthly) for each paid plan. Created once in the
    # Stripe dashboard; the checkout session references them so pricing lives in
    # Stripe, not hardcoded in a charge call.
    stripe_price_essential: str | None = None
    stripe_price_complete: str | None = None
    adyen_api_key: SecretStr | None = None  # Europe / global enterprise
    adyen_merchant_account: str | None = None
    mercadopago_access_token: SecretStr | None = None  # Latin America
    razorpay_key_id: str | None = None  # Asia (India and neighbours)
    razorpay_key_secret: SecretStr | None = None
    paypal_client_id: str | None = None
    paypal_client_secret: SecretStr | None = None

    # Platform operators who can reach the cross-tenant admin console. A simple
    # allowlist (comma-separated emails) rather than a self-service flag — super
    # admin can never be granted through the product itself, only by deployment.
    superadmin_emails: str = ""

    # Browser origins allowed to call the API cross-origin (comma-separated). The
    # web client is served from a different origin than the API in production
    # (e.g. Vercel → Render), so its origin must be allow-listed or the browser
    # blocks every call. Localhost dev origins are always allowed.
    cors_origins: str = "https://envelockclient.vercel.app"

    # Public URL of the web client — used to build links in outbound email (e.g.
    # the password-reset link). Should match the deployed client origin.
    web_base_url: str = "https://envelockclient.vercel.app"

    # DANGER — one-time schema rebuild. When true, the app DROPS AND RECREATES the
    # database schema on startup (wiping all data), to repair a drifted pre-launch
    # database. Set true, redeploy once, then set back to false. Never true with
    # real customer data — use Alembic migrations instead.
    reset_schema_on_startup: bool = False

    # ── Derived ──────────────────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def superadmin_email_set(self) -> frozenset[str]:
        return frozenset(
            e.strip().lower() for e in self.superadmin_emails.split(",") if e.strip()
        )

    @property
    def cors_origin_list(self) -> list[str]:
        """Configured cross-origin callers plus the local dev origins."""
        configured = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        dev = ["http://localhost:5173", "http://localhost:5174"]
        # De-dupe while preserving order.
        return list(dict.fromkeys(configured + dev))

    @property
    def egress_ip_pool(self) -> list[str]:
        return [ip.strip() for ip in self.imap_egress_ips.split(",") if ip.strip()]

    @property
    def imap_extra_port_set(self) -> frozenset[int]:
        ports: set[int] = set()
        for raw in self.imap_extra_allowed_ports.split(","):
            token = raw.strip()
            if token.isdigit() and 1 <= int(token) <= 65535:
                ports.add(int(token))
        return frozenset(ports)

    @property
    def dnsbl_domain_zone_list(self) -> list[str]:
        return [z.strip() for z in self.dnsbl_domain_zones.split(",") if z.strip()]

    @property
    def ingest_allowed_ip_list(self) -> list[str]:
        return [ip.strip() for ip in self.ingest_allowed_ips.split(",") if ip.strip()]

    @model_validator(mode="after")
    def _reject_leaked_comments(self) -> Settings:
        """Catch `.env` lines where an example comment became the value.

        python-dotenv does not strip a trailing `# comment` from an unquoted
        value, so `KEY=   # explains the key` loads the comment text as the
        setting. That silently "configures" a provider with nonsense — a KMS key
        id, an API key — and fails much later at call time. Fail at boot instead.
        """
        bad: list[str] = []
        for name in type(self).model_fields:
            raw = getattr(self, name, None)
            value = (
                raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            )
            if isinstance(value, str) and value.lstrip().startswith("#"):
                bad.append(f"ENVELOCK_{name.upper()}")
        if bad:
            raise ValueError(
                "These .env values are example comments, not real values — the "
                "comment must go on its own line above the key: "
                + ", ".join(sorted(bad))
            )
        return self

    @model_validator(mode="after")
    def _check_production_secrets(self) -> Settings:
        """Fail loudly at boot rather than quietly in production.

        A missing credential master key would mean tenant mail passwords stored
        without envelope encryption — that must never start.
        """
        if self.env != "production":
            return self

        missing: list[str] = []
        if not self.secret_key.get_secret_value():
            missing.append("ENVELOCK_SECRET_KEY")
        if missing:
            raise ValueError(
                f"Refusing to start in production without: {', '.join(missing)}"
            )

        # Prove the credential key provider can actually be built. The previous
        # check accepted ENVELOCK_KMS_KEY_ID on its own as satisfying the
        # requirement, and then the sealing path raised at the first mailbox
        # connect because no master key was set — a production deployment that
        # started cleanly and could not store a single credential.
        from envelock.security.keys import KeyProviderError, build_provider

        try:
            build_provider()
        except KeyProviderError as exc:
            raise ValueError(
                f"Refusing to start in production: credential key custody is not "
                f"usable — {exc}"
            ) from exc
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
