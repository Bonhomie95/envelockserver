"""Rebuild the database schema to match the current models.

WHY THIS EXISTS: the app creates tables with `create_all` at startup, which
creates *missing* tables but never *alters* existing ones. So a database that was
first created by an older version drifts — e.g. a `users` table without the newer
`tenant_id` column — and every query then 500s with "column ... does not exist".
This is exactly the Render production symptom.

For a pre-launch database (test data only) the clean fix is to drop and recreate
the schema so `create_all` rebuilds it exactly from the current models.

    DANGER: THIS WIPES ALL DATA IN THE TARGET DATABASE.

Usage (point it at the database you want to rebuild — e.g. the Render one):

    ENVELOCK_POSTGRES_DSN="postgresql+asyncpg://USER:PASS@HOST:5432/DB" \
    ENVELOCK_CONFIRM_RESET=yes \
        python -m scripts.reset_schema

Run it from the server/ directory (or with the package importable). On Render you
can run it from the service Shell, or from your machine using the database's
external connection string.

AFTER a launch (real customer data), do NOT use this — adopt Alembic migrations
(`alembic upgrade head`) on deploy instead.
"""

from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import text


async def _reset() -> None:
    from envelock.db import create_all, dispose, get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        # Drop everything, including the alembic_version table, then recreate an
        # empty public schema. CASCADE clears all dependent objects.
        await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    # Rebuild the full current schema from the SQLAlchemy models.
    await create_all()
    await dispose()


def main() -> None:
    if os.environ.get("ENVELOCK_CONFIRM_RESET") != "yes":
        print(
            "Refusing to run: this DROPS AND REBUILDS the schema and WIPES ALL "
            "DATA.\nSet ENVELOCK_CONFIRM_RESET=yes to proceed, and make sure "
            "ENVELOCK_POSTGRES_DSN points at the database you intend to reset."
        )
        raise SystemExit(2)
    dsn = os.environ.get("ENVELOCK_POSTGRES_DSN", "(default localhost)")
    # Show only the host/db, never credentials.
    safe = dsn.split("@")[-1] if "@" in dsn else dsn
    print(f"Rebuilding schema on: {safe}")
    asyncio.run(_reset())
    print("Done — schema dropped and rebuilt to match the current models.")
    print("Restart/redeploy the app if it is running, then register your account.")


if __name__ == "__main__":
    sys.exit(main())
