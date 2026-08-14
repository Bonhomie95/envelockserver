"""Database engine, session and base model.

**Postgres only.** The same engine runs in local development, test and
production — moving between them is one thing: the `ENVELOCK_POSTGRES_DSN` URL.
Native Postgres column types (ARRAY, JSONB) are used directly (see `types.py`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextvars import ContextVar
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from envelock.config import get_settings

#: The tenant whose rows the current task may touch. Set by the auth dependency
#: (per request) or explicitly by a worker acting for one tenant. When RLS is
#: enabled, this drives the `envelock.tenant_id` GUC on every connection, so the
#: database backstops isolation even if an application query forgets its filter.
current_tenant_id: ContextVar[str | None] = ContextVar("current_tenant_id", default=None)


def set_current_tenant(tenant_id: UUID | str | None) -> None:
    current_tenant_id.set(str(tenant_id) if tenant_id else None)

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


class UUIDMixin:
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _normalise_dsn(dsn: str) -> str:
    """Accept a plain Postgres URL and route it through the asyncpg driver.

    Only Postgres is supported — a non-Postgres DSN is a configuration error we
    fail on loudly rather than silently degrading to a different database.
    """
    if dsn.startswith("postgresql+asyncpg:"):
        return dsn
    if dsn.startswith("postgresql:"):
        return dsn.replace("postgresql:", "postgresql+asyncpg:", 1)
    raise ValueError(
        "ENVELOCK_POSTGRES_DSN must be a PostgreSQL URL "
        "(postgresql://… or postgresql+asyncpg://…); "
        f"got {dsn.split('://', 1)[0] if '://' in dsn else dsn!r}"
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        dsn = _normalise_dsn(settings.postgres_dsn)
        kwargs: dict = {"pool_pre_ping": True}
        if settings.db_nullpool:
            from sqlalchemy.pool import NullPool

            # No pooled connection outlives the loop that opened it — required for
            # the test suite, which spins up many short-lived event loops.
            kwargs = {"poolclass": NullPool}
        _engine = create_async_engine(dsn, **kwargs)
        if settings.rls_enabled:
            _install_rls_guc(_engine)
    return _engine


def _install_rls_guc(engine: AsyncEngine) -> None:
    """Set the `envelock.tenant_id` GUC at the start of every transaction from the
    `current_tenant_id` contextvar, so Postgres row-level security scopes every
    query to the active tenant (PRD §11). A request with no tenant in context
    (e.g. an unauthenticated call) sets an empty string, which the RLS policy
    treats as "match nothing" — fail closed, never leak."""

    @event.listens_for(engine.sync_engine, "begin")
    def _set_tenant(conn) -> None:  # noqa: ANN001
        tid = current_tenant_id.get() or ""
        # Parameterised via set_config to avoid any SQL injection through the id.
        conn.exec_driver_sql("SELECT set_config('envelock.tenant_id', %s, true)", (tid,))


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


#: Columns added to existing tables after their first release. `create_all` only
#: creates missing *tables*, never new columns on an existing one, so a table that
#: already exists on a long-running database would silently miss these. Each entry
#: is an idempotent `ADD COLUMN IF NOT EXISTS`, applied on every startup.
_RUNTIME_COLUMNS: tuple[str, ...] = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "status varchar(16) NOT NULL DEFAULT 'active'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "must_change_password boolean NOT NULL DEFAULT false",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id varchar(64)",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "extra_mailbox_seats integer NOT NULL DEFAULT 0",
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS "
    "imap_security varchar(16) DEFAULT 'ssl'",
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS imap_username varchar(320)",
    # OAuth access-token expiry, tracked in plaintext so the refresh scheduler can
    # find due tokens without decrypting every credential.
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS "
    "token_expires_at timestamptz",
    # Domain-verification challenge method (txt|cname) alongside the token.
    "ALTER TABLE domains ADD COLUMN IF NOT EXISTS "
    "verification_method varchar(8) NOT NULL DEFAULT 'txt'",
    # ── Auth self-heal ──────────────────────────────────────────────────────
    # A database first built by an older release can be missing columns that
    # register/login/MFA write. Bringing them up to date here means a plain
    # redeploy fixes a drifted schema WITHOUT dropping data (the old, lossy path
    # was ENVELOCK_RESET_SCHEMA_ON_STARTUP). All nullable or defaulted so they
    # apply cleanly to a populated table.
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan varchar(32) NOT NULL DEFAULT 'guard'",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "billing_term varchar(16) NOT NULL DEFAULT 'monthly'",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_started_at timestamptz",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at timestamptz",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "payment_method_ok boolean NOT NULL DEFAULT false",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id uuid",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS name varchar(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash varchar(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role varchar(16) NOT NULL DEFAULT 'member'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret varchar(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "recovery_hashes varchar[] NOT NULL DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS out_of_band_email varchar(320)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone varchar(32)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "phone_verified boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_otp_hash varchar(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_otp_expires_at timestamptz",
)


async def create_all() -> None:
    """Create any missing tables, then backfill any newly added columns. Idempotent,
    so it is safe to run on every startup — this is what makes "just point at a
    fresh Postgres" work. Alembic remains available for managed migrations and RLS."""

    from envelock import models  # noqa: F401  (register metadata)

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for stmt in _RUNTIME_COLUMNS:
            await conn.execute(text(stmt))


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
