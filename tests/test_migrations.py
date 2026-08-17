"""Guards the Alembic migration chain.

Two failures had crept in and stayed invisible because the app builds its schema
at boot via `create_all` (+ the reconciler), not via migrations:
  * the migrations were DEAD — they called `StringList()` / `JsonDict()` as if
    callable, so `alembic upgrade head` crashed on the first migration; and
  * they had drifted far behind the models (no user roles/MFA/recovery, no
    billing/imap/domain-lifecycle columns, missing whole tables).

These tests keep both from recurring: the chain must have a single head, must
apply cleanly end-to-end, and must leave ZERO difference from the models.
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_INI = os.path.join(os.path.dirname(_HERE), "alembic.ini")


def _config(url: str | None = None):
    from alembic.config import Config

    cfg = Config(_INI)
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_single_migration_head() -> None:
    """A branched history (two heads) means a merge was missed — upgrades become
    ambiguous. There must be exactly one head."""
    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(_config()).get_heads()
    assert len(heads) == 1, f"expected a single migration head, got {heads}"


def test_migrations_apply_and_match_models(monkeypatch) -> None:
    """Run the whole chain into a throwaway database and assert it matches the
    models (compare_metadata finds nothing). Skips where the DB role can't create
    databases/roles — where it runs, it is the real drift guard."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from envelock.config import get_settings
    from envelock.db import Base, _normalise_dsn

    base_url = _normalise_dsn(get_settings().postgres_dsn)
    if "@" not in base_url or "/" not in base_url.rsplit("@", 1)[1]:
        pytest.skip("non-standard DSN; migration apply-test skipped")
    prefix, tail = base_url.rsplit("/", 1)  # tail = dbname
    tmp_db = f"envelock_migcheck_{uuid.uuid4().hex[:10]}"
    tmp_url = f"{prefix}/{tmp_db}"
    admin_url = f"{prefix}/postgres"

    async def _run_admin(sql: str) -> None:
        eng = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            from sqlalchemy import text

            async with eng.connect() as conn:
                await conn.execute(text(sql))
        finally:
            await eng.dispose()

    try:
        asyncio.run(_run_admin(f'CREATE DATABASE "{tmp_db}"'))
    except Exception as exc:  # noqa: BLE001 — no createdb privilege in this env
        pytest.skip(f"cannot create a scratch database here: {exc}")

    try:
        # env.py reads ENVELOCK_POSTGRES_DSN via get_settings(); point it at the
        # scratch DB (the autouse settings-cache fixture keeps this from leaking).
        monkeypatch.setenv("ENVELOCK_POSTGRES_DSN", tmp_url)
        get_settings.cache_clear()

        from alembic import command

        try:
            command.upgrade(_config(), "head")
        except Exception as exc:  # noqa: BLE001
            if "permission denied to create role" in str(exc).lower():
                pytest.skip("role lacks CREATEROLE for the RLS migration")
            raise

        async def _diff() -> list:
            from alembic.autogenerate import compare_metadata
            from alembic.migration import MigrationContext

            eng = create_async_engine(tmp_url)
            try:
                async with eng.connect() as conn:
                    return await conn.run_sync(
                        lambda sconn: compare_metadata(
                            MigrationContext.configure(sconn), Base.metadata
                        )
                    )
            finally:
                await eng.dispose()

        diffs = asyncio.run(_diff())
        assert diffs == [], f"migrations drifted from the models: {diffs}"
    finally:
        get_settings.cache_clear()
        try:
            asyncio.run(
                _run_admin(
                    f'DROP DATABASE IF EXISTS "{tmp_db}" WITH (FORCE)'
                )
            )
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
