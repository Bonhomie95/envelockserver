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

    # One-time schema rebuild for a DRIFTED database (e.g. a pre-launch Render DB
    # whose `users` table predates `tenant_id`). `create_all` only creates missing
    # tables, never alters existing ones, so a drifted schema keeps 500-ing. Set
    # ENVELOCK_RESET_SCHEMA_ON_STARTUP=true, redeploy once, then set it back to
    # false. DANGER: this WIPES ALL DATA — only for a pre-launch/throwaway DB.
    if settings.reset_schema_on_startup:
        from sqlalchemy import text

        from envelock.db import get_engine

        logger.warning(
            "ENVELOCK_RESET_SCHEMA_ON_STARTUP=true — DROPPING AND REBUILDING THE "
            "SCHEMA. ALL DATA IN THIS DATABASE IS BEING ERASED. Set this back to "
            "false immediately after this deploy, or every restart will wipe it."
        )
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))

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

    # Live IMAP worker (PRD §5.3). This is what actually *reads* a connected
    # mailbox: without it, connect_imap stores a credential but no mail is ever
    # fetched or analysed. Runs as a background task in-process; a redis-backed
    # multi-instance deployment would elect a single poller, but a single instance
    # is correct as-is. Disabled in tests (they drive the worker directly).
    import asyncio

    imap_stop = asyncio.Event()
    imap_task: asyncio.Task | None = None
    if settings.imap_poll_worker_enabled:
        from envelock.workers.imap_fetch import imap_poll_loop

        imap_task = asyncio.create_task(
            imap_poll_loop(imap_stop, interval_seconds=settings.imap_poll_worker_seconds)
        )
        logger.info("imap poll worker enabled (%ss)", settings.imap_poll_worker_seconds)

    yield

    if imap_task is not None:
        imap_stop.set()
        imap_task.cancel()
        import contextlib

        with contextlib.suppress(asyncio.CancelledError):
            await imap_task

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

    # CORS is required in production too: the web client is served from a
    # different origin (e.g. Vercel) than this API (e.g. Render), so its origin
    # must be allow-listed or the browser blocks every call. Origins come from
    # ENVELOCK_CORS_ORIGINS (plus localhost dev). Explicit list rather than "*":
    # a wildcard with credentials is a cross-origin credential leak waiting to
    # happen.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
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
