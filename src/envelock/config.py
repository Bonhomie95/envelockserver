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

    secret_key: SecretStr = SecretStr("")
    credential_master_key: SecretStr = SecretStr("")
    kms_key_id: str | None = None

    # ── Datastores ───────────────────────────────────────────────────────────
    postgres_dsn: str = "postgresql+asyncpg://envelock:envelock@localhost:5432/envelock"
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

    # ── Channel 1: Tier 4 ────────────────────────────────────────────────────
    ingest_domain: str = "in.envelock.io"
    ingest_smtp_host: str = "0.0.0.0"  # noqa: S104
    ingest_smtp_port: int = 2525

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

    # ── Detection cascades (PRD §12.12) ──────────────────────────────────────
    safebrowsing_api_key: SecretStr | None = None
    urlhaus_enabled: bool = True

    clamav_host: str = "localhost"
    clamav_port: int = 3310
    yara_rules_path: str = "./rules/yara"
    attachment_cache_ttl_clean_days: int = 14
    detonation_enabled: bool = False
    virustotal_api_key: SecretStr | None = None
    detonation_provider: str | None = None
    detonation_monthly_cap_per_mailbox: int = 150

    # ── Notifications (PRD §8.1) ─────────────────────────────────────────────
    smtp_host: str = "localhost"
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
    escalate_critical_after_seconds: int = 900
    escalate_unacked_count: int = 5

    # ── Billing (PRD §12) ────────────────────────────────────────────────────
    trial_days: int = 15
    trial_backfill_days: int = 30
    backfill_days: int = 90

    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    paystack_secret_key: SecretStr | None = None
    flutterwave_secret_key: SecretStr | None = None
    paypal_client_id: str | None = None
    paypal_client_secret: SecretStr | None = None

    # ── Derived ──────────────────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def egress_ip_pool(self) -> list[str]:
        return [ip.strip() for ip in self.imap_egress_ips.split(",") if ip.strip()]

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
        if not self.credential_master_key.get_secret_value() and not self.kms_key_id:
            missing.append("ENVELOCK_CREDENTIAL_MASTER_KEY or ENVELOCK_KMS_KEY_ID")
        if missing:
            raise ValueError(
                f"Refusing to start in production without: {', '.join(missing)}"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
