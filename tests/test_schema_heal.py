"""The self-heal must fix a column whose TYPE is too small on an old schema
(the real Render failure: users.password_hash was varchar(32), truncating a
scrypt hash), not just add missing columns."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from envelock.db import create_all, get_engine

pytestmark = pytest.mark.asyncio

# The exact scrypt hash shape that overflowed varchar(32) on Render (~76 chars).
_SCRYPT = "scrypt$32768$8$1$EBxy6sIeip+zcV49dcOkog==$eO+CQ1ITBFhTkSb+vHsu41/YhJoyHsCFkSVpEOChKJU="


async def test_widens_undersized_password_hash(db) -> None:
    await create_all()
    eng = get_engine()
    # Simulate the legacy drift: password_hash sized varchar(32).
    async with eng.begin() as c:
        await c.execute(text("ALTER TABLE users ALTER COLUMN password_hash TYPE varchar(32)"))
        length = (await c.execute(text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name='users' AND column_name='password_hash'"))).scalar_one()
        assert length == 32
        assert len(_SCRYPT) > 32  # would truncate

    # A plain startup must widen it — no reset, no data loss.
    await create_all()
    async with eng.begin() as c:
        length = (await c.execute(text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name='users' AND column_name='password_hash'"))).scalar_one()
        assert length == 255
        # The scrypt hash that overflowed varchar(32) now fits the column.
        assert len(_SCRYPT) <= length


async def test_reconciler_heals_drift_on_any_table(db) -> None:
    """The generic reconciler must fix drift on tables NOT in the hand-listed
    self-heal — a dropped column and an under-sized one are both restored, with no
    reset and no data loss."""
    await create_all()
    eng = get_engine()

    async def _col(table: str, column: str):
        async with eng.begin() as c:
            return (await c.execute(text(
                "SELECT character_maximum_length FROM information_schema.columns "
                "WHERE table_name=:t AND column_name=:col"),
                {"t": table, "col": column})).first()

    # Pick a text column on a NON-auth table straight from the models, so this test
    # stays true as the schema evolves.
    from envelock.db import Base
    target = None
    for tbl in Base.metadata.sorted_tables:
        if tbl.name in {"users", "tenants"}:
            continue
        for col in tbl.columns:
            if getattr(col.type, "length", None) and int(col.type.length) >= 64:
                target = (tbl.name, col.name, int(col.type.length))
                break
        if target:
            break
    assert target, "expected at least one sized varchar column on a non-auth table"
    table, column, model_len = target

    # Simulate legacy drift on that arbitrary table: shrink the column well below
    # what the model needs.
    async with eng.begin() as c:
        await c.execute(text(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE varchar(8)'))
    assert (await _col(table, column))[0] == 8

    # A plain startup reconciles it back up to the model size.
    await create_all()
    assert (await _col(table, column))[0] == model_len
