"""Database engine, session and base model.

Postgres in production; SQLite is supported so the whole system runs and tests
without Docker. Column types that differ (ARRAY, JSONB) are handled by the
portable types in `models.py`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, event
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
    if dsn.startswith("sqlite") and "+aiosqlite" not in dsn:
        return dsn.replace("sqlite:", "sqlite+aiosqlite:", 1)
    if dsn.startswith("postgresql:"):
        return dsn.replace("postgresql:", "postgresql+asyncpg:", 1)
    return dsn


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        dsn = _normalise_dsn(get_settings().postgres_dsn)
        kwargs: dict = {"pool_pre_ping": True}
        if dsn.startswith("sqlite"):
            kwargs = {}
        _engine = create_async_engine(dsn, **kwargs)

        if dsn.startswith("sqlite"):
            # Foreign keys are off by default in SQLite.
            @event.listens_for(_engine.sync_engine, "connect")
            def _fk_on(conn, _record):  # noqa: ANN001
                conn.execute("PRAGMA foreign_keys=ON")

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
    """Used by tests and first-run bootstrap. Alembic owns production schema."""
    from envelock import models  # noqa: F401  (register metadata)

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
