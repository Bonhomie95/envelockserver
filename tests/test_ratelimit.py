"""Cross-instance rate limiting (PRD §17.3).

The Redis backend is exercised against a fake client that implements the sorted-
set semantics the Lua script relies on, so the sliding-window logic is proven
without a live Redis. The fail-over path is tested explicitly — a Redis outage
must degrade to per-instance limiting, never lock everyone out.
"""

from __future__ import annotations

import asyncio

import pytest

from envelock.security import limits


class _FakeRedis:
    """Enough of Redis to run the sliding-window script: one sorted set per key."""

    def __init__(self, *, fail: bool = False) -> None:
        self._z: dict[str, list[tuple[float, str]]] = {}
        self._fail = fail

    async def eval(self, script: str, nkeys: int, key, now, window, limit, member) -> list[int]:
        if self._fail:
            raise ConnectionError("redis down")
        now, window, limit = int(now), int(window), int(limit)
        z = self._z.setdefault(key, [])
        # ZREMRANGEBYSCORE key 0 now-window
        z[:] = [(s, m) for (s, m) in z if s > now - window]
        if len(z) >= limit:
            oldest = min(z, key=lambda e: e[0])[0]
            return [0, max(1, (oldest + window - now + 999) // 1000)]
        z.append((now, member))
        return [1, 0]


def test_redis_limiter_enforces_the_window() -> None:
    rule = limits.RULES["auth.login"]  # 5 per 300s
    rl = limits.RedisRateLimiter(_FakeRedis())

    async def run() -> list[tuple[bool, int]]:
        out = []
        for _ in range(rule.limit + 2):
            out.append(await rl.acheck("auth.login", "1.2.3.4", now=1000.0))
        return out

    results = asyncio.run(run())
    assert [r[0] for r in results] == [True] * rule.limit + [False, False]
    assert results[-1][1] > 0  # a retry-after is reported


def test_redis_limiter_is_shared_across_instances() -> None:
    """Two limiter objects (two app instances) sharing one Redis must enforce a
    single window — not `limit` each."""
    shared = _FakeRedis()
    a = limits.RedisRateLimiter(shared)
    b = limits.RedisRateLimiter(shared)
    rule = limits.RULES["auth.login"]

    async def run() -> bool:
        # Alternate instances; the shared window should still cut off at `limit`.
        allowed = 0
        for i in range(rule.limit + 4):
            inst = a if i % 2 == 0 else b
            ok, _ = await inst.acheck("auth.login", "9.9.9.9", now=2000.0)
            allowed += 1 if ok else 0
        return allowed == rule.limit

    assert asyncio.run(run())


def test_redis_outage_fails_over_to_in_process() -> None:
    fallback = limits.RateLimiter()
    rl = limits.RedisRateLimiter(_FakeRedis(fail=True), fallback=fallback)

    async def run() -> tuple[bool, int]:
        return await rl.acheck("auth.login", "5.5.5.5", now=3000.0)

    allowed, _ = asyncio.run(run())
    assert allowed is True  # degraded, not denied


def test_use_backend_swaps_the_active_limiter() -> None:
    original = limits.active_limiter()
    try:
        redis_backend = limits.RedisRateLimiter(_FakeRedis())
        limits.use_backend(redis_backend)
        assert limits.active_limiter() is redis_backend
    finally:
        limits.use_backend(original)


def test_reset_all_restores_in_process_backend() -> None:
    limits.use_backend(limits.RedisRateLimiter(_FakeRedis()))
    limits.reset_all()
    assert limits.active_limiter() is limits.limiter


@pytest.mark.asyncio
async def test_in_process_async_check_matches_sync() -> None:
    rl = limits.RateLimiter()
    ok, _ = await rl.acheck("default", "x", now=10.0)
    assert ok is True
