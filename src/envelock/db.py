"""Database engine, session and base model.

**Postgres only.** The same engine runs in local development, test and
production — moving between them is one thing: the `ENVELOCK_POSTGRES_DSN` URL.
Native Postgres column types (ARRAY, JSONB) are used directly (see `types.py`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from envelock.config import get_settings

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
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


async def create_all() -> None:
    """Create any missing tables. Idempotent (checkfirst), so it is safe to run
    on every startup — this is what makes "just point at a fresh Postgres" work.
    Alembic remains available for managed migrations and row-level security."""
    from envelock import models  # noqa: F401  (register metadata)

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
