"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from envelock.api import admin, auth, billing, channels, governance, health, tenants, v1
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

    # Ensure the schema exists on the configured Postgres. Idempotent, so moving
    # from a local DB to a production one is only a change of ENVELOCK_POSTGRES_DSN.
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

    # Cross-instance shared state (PRD §17.3). A single instance stays fully
    # in-process; a redis-backed deployment shares the rate-limit window AND the
    # auth-security stores (login lockout, TOTP replay guard, token revocations),
    # so those protections hold across replicas. Any failure logs and falls back
    # to per-instance rather than blocking startup.
    if settings.rate_limit_backend == "redis":
        try:
            import redis.asyncio as aioredis

            from envelock.security import limits

            client = aioredis.from_url(settings.redis_dsn, socket_timeout=2)
            await client.ping()
            limits.use_backend(limits.RedisRateLimiter(client, fallback=limits.limiter))
            limits.use_auth_backends(
                lockout=limits.RedisAccountLockout(client, fallback=limits.lockout),
                replay=limits.RedisReplayGuard(client, fallback=limits.totp_replay),
                revocations=limits.RedisTokenRevocations(client, fallback=limits.revocations),
            )
            logger.info("shared state: redis backend active (rate limit + auth stores)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("shared state: redis unavailable (%s) — using in-process", exc)

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
            # 5173 = tenant web app, 5174 = the super-admin console (separate app).
            allow_origins=["http://localhost:5173", "http://localhost:5174"],
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
    app.include_router(admin.router)
    return app


app = create_app()
