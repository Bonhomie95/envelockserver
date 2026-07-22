"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from envelock.api import auth, channels, governance, health, tenants, v1
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
    app.include_router(governance.router)
    app.include_router(tenants.router)
    app.include_router(channels.router)
    return app


app = create_app()
