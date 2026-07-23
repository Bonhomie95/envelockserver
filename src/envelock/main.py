"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from envelock.api import auth, billing, channels, governance, health, tenants, v1
from envelock.config import get_settings
from envelock.detections import (  # noqa: F401  (registers detections)
    content,
    identity,
    impersonation,
    sessions,
)
from envelock.security.middleware import (
    RequestGuardMiddleware,
    SecurityHeadersMiddleware,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    logger.info("envelock starting", extra={"env": settings.env})

    # SQLite bootstraps its own schema so the system runs without Docker;
    # Postgres schema is owned by Alembic.
    if settings.postgres_dsn.startswith("sqlite"):
        from envelock.db import create_all

        await create_all()

    # Hydrate the E8 counterparty graph from its durable store so the moat — one
    # tenant's confirmation protecting every other tenant — survives restarts and
    # is shared across instances, not reset on every deploy.
    try:
        from envelock.db import get_sessionmaker
        from envelock.platform import graph_store

        async with get_sessionmaker()() as session:
            loaded = await graph_store.hydrate(session)
        logger.info("counterparty graph hydrated", extra={"verdicts": loaded})
    except Exception as exc:  # noqa: BLE001
        logger.warning("counterparty graph hydrate skipped: %s", exc)

    # Cross-instance rate limiting (PRD §17.3). A single instance stays on the
    # in-process limiter; a redis-backed deployment shares one window. A failed
    # connection is logged and falls back rather than blocking startup.
    if settings.rate_limit_backend == "redis":
        try:
            import redis.asyncio as aioredis

            from envelock.security import limits

            client = aioredis.from_url(settings.redis_dsn, socket_timeout=2)
            await client.ping()
            limits.use_backend(limits.RedisRateLimiter(client, fallback=limits.limiter))
            logger.info("rate limiter: redis backend active")
        except Exception as exc:  # noqa: BLE001
            logger.warning("rate limiter: redis unavailable (%s) — using in-process", exc)

    # Connection pools, the IMAP broker and channel subscribers attach here as
    # they land. Keep startup ordered: datastores, then channels, then workers.
    yield

    logger.info("envelock stopped")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Envelock",
        description="Email fraud and account-takeover protection",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
    )

    # Order matters: guards run before routing, headers wrap everything.
    app.add_middleware(SecurityHeadersMiddleware, production=settings.is_production)
    app.add_middleware(RequestGuardMiddleware)

    if not settings.is_production:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173"],
            # Explicit rather than "*": a wildcard with credentials is a
            # cross-origin credential leak waiting to happen.
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )

    app.include_router(health.router, tags=["health"])
    app.include_router(v1.router, tags=["v1"])
    app.include_router(auth.router)
    app.include_router(billing.router)
    app.include_router(governance.router)
    app.include_router(tenants.router)
    app.include_router(channels.router)
    return app


app = create_app()
