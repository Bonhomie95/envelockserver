"""Redis-backed auth security stores (PRD §17.3, §11.1).

Exercised against a fake Redis that implements the exact primitives the stores
use (GET/SET-NX-EX/INCR/EXPIRE/DELETE/EXISTS), so cross-instance behaviour and
the fail-over path are proven without a live Redis. On a single instance the
in-process classes are already covered by the auth flow tests; these prove the
shared-state variants a multi-instance deployment relies on.
"""

from __future__ import annotations

import asyncio
import time

from envelock.security import limits


class _FakeRedis:
    """Minimal async Redis: one dict of key -> (value, expiry|None)."""

    def __init__(self, *, fail: bool = False) -> None:
        self._d: dict[str, tuple[str, float | None]] = {}
        self.fail = fail

    def _live(self, k: str, now: float) -> str | None:
        v = self._d.get(k)
        if v is None:
            return None
        val, exp = v
        if exp is not None and exp <= now:
            del self._d[k]
            return None
        return val

    async def get(self, k):
        if self.fail:
            raise ConnectionError("down")
        return self._live(k, time.time())

    async def set(self, k, val, *, nx=False, ex=None):
        if self.fail:
            raise ConnectionError("down")
        now = time.time()
        if nx and self._live(k, now) is not None:
            return None
        self._d[k] = (str(val), now + ex if ex else None)
        return True

    async def incr(self, k):
        if self.fail:
            raise ConnectionError("down")
        now = time.time()
        cur = self._live(k, now)
        n = (int(cur) if cur else 0) + 1
        exp = self._d.get(k, (None, None))[1]
        self._d[k] = (str(n), exp)
        return n

    async def expire(self, k, ttl):
        if self.fail:
            raise ConnectionError("down")
        if k in self._d:
            self._d[k] = (self._d[k][0], time.time() + ttl)
        return True

    async def delete(self, *keys):
        if self.fail:
            raise ConnectionError("down")
        return sum(1 for k in keys if self._d.pop(k, None) is not None)

    async def exists(self, *keys):
        if self.fail:
            raise ConnectionError("down")
        now = time.time()
        return sum(1 for k in keys if self._live(k, now) is not None)


# ── Lockout ──────────────────────────────────────────────────────────────────
def test_redis_lockout_locks_after_threshold() -> None:
    lk = limits.RedisAccountLockout(_FakeRedis())

    async def run():
        for _ in range(limits.AccountLockout.THRESHOLD):
            await lk.arecord_failure("bob@acme.com")
        return await lk.ais_locked("bob@acme.com")

    locked, retry = asyncio.run(run())
    assert locked is True
    assert retry > 0


def test_redis_lockout_is_shared_across_instances() -> None:
    """Two app instances sharing one Redis must sum failures — an attacker cannot
    dodge lockout by spreading attempts across replicas."""
    shared = _FakeRedis()
    a = limits.RedisAccountLockout(shared)
    b = limits.RedisAccountLockout(shared)

    async def run():
        # 3 failures on instance A, 2 on instance B -> threshold of 5 reached.
        for _ in range(3):
            await a.arecord_failure("carol@acme.com")
        for _ in range(2):
            await b.arecord_failure("carol@acme.com")
        return await a.ais_locked("carol@acme.com")

    locked, _ = asyncio.run(run())
    assert locked is True


def test_redis_lockout_success_clears() -> None:
    lk = limits.RedisAccountLockout(_FakeRedis())

    async def run():
        for _ in range(limits.AccountLockout.THRESHOLD):
            await lk.arecord_failure("dan@acme.com")
        await lk.arecord_success("dan@acme.com")
        return await lk.ais_locked("dan@acme.com")

    locked, _ = asyncio.run(run())
    assert locked is False


def test_redis_lockout_fails_over_to_in_process() -> None:
    fb = limits.AccountLockout()
    lk = limits.RedisAccountLockout(_FakeRedis(fail=True), fallback=fb)

    async def run():
        for _ in range(limits.AccountLockout.THRESHOLD):
            await lk.arecord_failure("eve@acme.com")
        return await lk.ais_locked("eve@acme.com")

    # Redis is down; it degrades to the per-instance fallback rather than raising.
    locked, _ = asyncio.run(run())
    assert locked is True


# ── Replay guard ─────────────────────────────────────────────────────────────
def test_redis_replay_rejects_second_use() -> None:
    rp = limits.RedisReplayGuard(_FakeRedis(), ttl=30)

    async def run():
        first = await rp.acheck_and_record("user:123456")
        second = await rp.acheck_and_record("user:123456")
        return first, second

    first, second = asyncio.run(run())
    assert first is True and second is False


def test_redis_replay_is_shared_across_instances() -> None:
    """A TOTP code consumed on one instance cannot be replayed on another."""
    shared = _FakeRedis()
    a = limits.RedisReplayGuard(shared, ttl=30)
    b = limits.RedisReplayGuard(shared, ttl=30)

    async def run():
        used_on_a = await a.acheck_and_record("user:999")
        replay_on_b = await b.acheck_and_record("user:999")
        return used_on_a, replay_on_b

    used, replay = asyncio.run(run())
    assert used is True and replay is False


# ── Token revocation ─────────────────────────────────────────────────────────
def test_redis_revocation_jti_and_user() -> None:
    rev = limits.RedisTokenRevocations(_FakeRedis())

    async def run():
        future = time.time() + 600
        await rev.arevoke_jti("jti-1", expires_at=future)
        await rev.arevoke_user("user-1", until=future)
        return (
            await rev.ais_revoked("jti-1", "someone"),
            await rev.ais_revoked("other", "user-1"),
            await rev.ais_revoked("clean", "clean"),
        )

    jti_hit, user_hit, clean = asyncio.run(run())
    assert jti_hit is True and user_hit is True and clean is False


def test_redis_revocation_is_shared_across_instances() -> None:
    """Logout / stolen-refresh revocation on one instance is seen by another."""
    shared = _FakeRedis()
    a = limits.RedisTokenRevocations(shared)
    b = limits.RedisTokenRevocations(shared)

    async def run():
        await a.arevoke_user("user-42", until=time.time() + 600)
        return await b.ais_revoked("any", "user-42")

    assert asyncio.run(run()) is True


# ── Backend swapping ─────────────────────────────────────────────────────────
def test_reset_all_restores_in_process_auth_backends() -> None:
    limits.use_auth_backends(
        lockout=limits.RedisAccountLockout(_FakeRedis()),
        replay=limits.RedisReplayGuard(_FakeRedis()),
        revocations=limits.RedisTokenRevocations(_FakeRedis()),
    )
    limits.reset_all()
    assert limits.active_lockout() is limits.lockout
    assert limits.active_replay() is limits.totp_replay
    assert limits.active_revocations() is limits.revocations
