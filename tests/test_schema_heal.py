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
