"""Shared test fixtures."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

# Point the whole suite at a throwaway SQLite file before anything imports
# settings, so tests never touch a real database.
_TMP_DB = Path(tempfile.gettempdir()) / f"envelock-test-{os.getpid()}.db"
os.environ.setdefault("ENVELOCK_POSTGRES_DSN", f"sqlite+aiosqlite:///{_TMP_DB}")
os.environ.setdefault("ENVELOCK_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ENVELOCK_ENV", "development")


@pytest.fixture(autouse=True)
def _reset_security_state() -> Iterator[None]:
    """Rate limits, lockouts and replay guards are process-global.

    Without this the suite trips its own throttling, and a test that fails
    because of state leaked from an earlier test teaches nothing.
    """
    from envelock.security.limits import reset_all

    reset_all()
    yield
    reset_all()


@pytest_asyncio.fixture
async def db() -> AsyncIterator[None]:
    """Fresh schema per test — no cross-test contamination."""
    from envelock.db import Base, dispose, get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await dispose()


@pytest_asyncio.fixture
async def session(db: None) -> AsyncIterator:
    from envelock.db import get_sessionmaker

    async with get_sessionmaker()() as s:
        yield s


@pytest.fixture
def tenant_id() -> UUID:
    """Just an id. Tests that need the row persist it themselves, so creating
    one here would collide on the primary key."""
    return uuid4()


@pytest.fixture
def client() -> Iterator[TestClient]:
    from envelock.api.auth import _reset_store
    from envelock.main import app

    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


@pytest.fixture
def api(client: TestClient) -> TestClient:
    return client
