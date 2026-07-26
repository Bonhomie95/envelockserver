"""Shared test fixtures."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

# The suite runs against a dedicated Postgres database (the same engine as
# production — Postgres is the only supported backend). Override with
# ENVELOCK_TEST_POSTGRES_DSN if your local role/DB differ.
os.environ["ENVELOCK_POSTGRES_DSN"] = os.environ.get(
    "ENVELOCK_TEST_POSTGRES_DSN",
    "postgresql+asyncpg://envelock:envelock@localhost:5432/envelock_test",
)
os.environ.setdefault("ENVELOCK_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ENVELOCK_ENV", "development")
# No connection pooling in tests: the suite runs many short event loops and a
# pooled asyncpg connection must never be reused across a different loop.
os.environ["ENVELOCK_DB_NULLPOOL"] = "true"


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    """Create the schema once for the whole session so the client-fixture tests
    (which don't use the per-test `db` fixture) have their tables."""
    import asyncio
    import contextlib

    from envelock.db import Base, create_all, dispose, get_engine

    async def _setup() -> None:
        await create_all()
        await dispose()

    asyncio.run(_setup())
    yield

    # Best-effort teardown: drop everything so the next run starts clean.
    async def _teardown() -> None:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await dispose()

    with contextlib.suppress(Exception):
        asyncio.run(_teardown())


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
