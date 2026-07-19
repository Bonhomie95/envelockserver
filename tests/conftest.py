"""Test fixtures. Everything runs on SQLite so the suite needs no Docker."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="envelock-test-"))
os.environ["ENVELOCK_POSTGRES_DSN"] = f"sqlite+aiosqlite:///{_TMP / 'test.db'}"
os.environ["ENVELOCK_ENV"] = "development"
os.environ.setdefault("ENVELOCK_SECRET_KEY", "test-secret-key-not-used-in-production")


@pytest.fixture(autouse=True)
def _isolate_settings():
    from envelock.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def session() -> AsyncIterator:
    """A fresh schema per test — no cross-test leakage of tenant data."""
    from envelock.db import Base, dispose, get_engine, get_sessionmaker

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with get_sessionmaker()() as s:
        yield s

    await dispose()


@pytest.fixture
def tenant_id():
    from uuid import uuid4

    return uuid4()


@pytest.fixture
def mailbox_id():
    from uuid import uuid4

    return uuid4()
