"""Rate limiting, lockout and request hardening.

A security product with an unthrottled login endpoint is not a security product.
The default limiter is in-process; a Redis-backed limiter (`RedisRateLimiter`)
shares one sliding window across instances so a multi-instance deployment throttles
correctly instead of allowing `limit × instances` (PRD §17.3). The interface is a
single async `acheck`, so the middleware does not care which backend is active, and
a Redis outage fails over to per-instance limiting rather than locking everyone out.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Protocol

logger = logging.getLogger(__name__)

# ── Input size ceilings ──────────────────────────────────────────────────────
# Unbounded input is the cheapest denial of service there is. These apply before
# any parsing or regex work.
MAX_RAW_MESSAGE_BYTES = 25 * 1024 * 1024  # 25 MB — larger than any real email
MAX_ANALYSED_TEXT_CHARS = 1_000_000  # detections truncate beyond this
MAX_DOMAIN_LENGTH = 253  # RFC 1035
MAX_LABEL_LENGTH = 63
MAX_ATTACHMENTS_SCANNED = 50
MAX_URLS_SCANNED = 200
MAX_OBSERVED_DOMAINS = 500


@dataclass(frozen=True, slots=True)
class Rule:
    """`limit` requests per `window` seconds."""

    limit: int
    window: int


#: Deliberately tight on anything that touches credentials.
RULES: dict[str, Rule] = {
    "auth.login": Rule(10, 300),
    # Account creation is low-harm (gated downstream by the payment/trial ledger)
    # and legitimately bursts — a small office behind one IP, or onboarding. Keep
    # it bounded against scripted farming, but not so tight that real signups fail.
    "auth.register": Rule(20, 3600),
    "auth.mfa": Rule(10, 300),
    "auth.refresh": Rule(30, 300),
    "auth.recovery": Rule(5, 3600),
    # Phone verification sends an SMS (a metered, abusable channel), so it is
    # capped hard — a few per hour is ample and stops SMS-bombing / cost abuse.
    "auth.phone": Rule(5, 3600),
    "scan.domain": Rule(20, 60),
    "scan.connect": Rule(20, 60),
    "analyse": Rule(30, 60),
    "export": Rule(60, 60),
    "default": Rule(120, 60),
}


class RateLimiterBackend(Protocol):
    async def acheck(
        self, bucket: str, identity: str, *, now: float | None = None
    ) -> tuple[bool, int]: ...


class RateLimiter:
    """In-process sliding window. Correct for a single instance and the fallback
    when Redis is unreachable."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, bucket: str, identity: str, *, now: float | None = None) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        rule = RULES.get(bucket, RULES["default"])
        key = f"{bucket}:{identity}"
        current = now if now is not None else time.time()

        with self._lock:
            hits = self._hits[key]
            cutoff = current - rule.window
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= rule.limit:
                return False, int(hits[0] + rule.window - current) + 1
            hits.append(current)
            return True, 0

    async def acheck(
        self, bucket: str, identity: str, *, now: float | None = None
    ) -> tuple[bool, int]:
        # No IO — the sync path is already non-blocking.
        return self.check(bucket, identity, now=now)

    def reset(self, bucket: str | None = None, identity: str | None = None) -> None:
        with self._lock:
            if bucket is None:
                self._hits.clear()
            else:
                self._hits.pop(f"{bucket}:{identity}", None)


#: Atomic sliding-window in one round-trip: drop expired hits, count, and admit
#: only if under the limit. Doing this in Lua avoids a check-then-add race that
#: would let concurrent requests across instances slip past the limit.
_REDIS_SLIDING_WINDOW = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = 1
  if oldest[2] then retry = math.ceil((tonumber(oldest[2]) + window - now) / 1000) end
  return {0, retry}
end
redis.call('ZADD', key, now, ARGV[4])
redis.call('PEXPIRE', key, window)
return {1, 0}
"""


class RedisRateLimiter:
    """Cross-instance sliding window backed by a Redis sorted set per key.

    A Redis error fails over to the in-process limiter (`fallback`) so a cache blip
    degrades to per-instance throttling rather than denying every login.
    """

    def __init__(self, client, *, fallback: RateLimiter | None = None) -> None:
        self._client = client
        self._fallback = fallback or RateLimiter()

    async def acheck(
        self, bucket: str, identity: str, *, now: float | None = None
    ) -> tuple[bool, int]:
        rule = RULES.get(bucket, RULES["default"])
        current = now if now is not None else time.time()
        now_ms = int(current * 1000)
        key = f"rl:{bucket}:{identity}"
        member = f"{now_ms}-{secrets.token_hex(4)}"
        try:
            allowed, retry = await self._client.eval(
                _REDIS_SLIDING_WINDOW,
                1,
                key,
                now_ms,
                rule.window * 1000,
                rule.limit,
                member,
            )
            return bool(int(allowed)), int(retry)
        except Exception:  # redis down, timeout, script error
            logger.warning("redis rate limiter unavailable — failing over to in-process")
            return self._fallback.check(bucket, identity, now=now)


# The active backend the middleware consults. Swapped at startup when Redis is
# configured (see `use_backend`); defaults to in-process so tests and single-node
# deployments need no Redis.
_active_limiter: RateLimiterBackend


def use_backend(backend: RateLimiterBackend) -> None:
    global _active_limiter
    _active_limiter = backend


def active_limiter() -> RateLimiterBackend:
    return _active_limiter


@dataclass
class _LockoutState:
    failures: int = 0
    locked_until: float = 0.0
    history: list[float] = field(default_factory=list)


# Multi-instance backing: these three stores are process-local, but Redis-backed
# variants below (`RedisAccountLockout`, `RedisReplayGuard`,
# `RedisTokenRevocations`) share them across replicas — selected at startup when
# `rate_limit_backend == "redis"`. So login lockout, TOTP replay protection and
# refresh-token reuse detection all hold across instances, with a per-instance
# fallback on a Redis outage. The in-process classes remain the single-instance
# default and the fallback.
class AccountLockout:
    """Progressive lockout keyed on the account, not the IP.

    IP-only throttling is trivially bypassed with a botnet; account-keyed
    lockout is what actually stops credential stuffing against one victim.
    """

    THRESHOLD = 5
    #: Doubling backoff, capped. Never permanent — that would be a denial of
    #: service an attacker could inflict on any customer at will.
    BACKOFFS = (60, 300, 900, 3600)

    def __init__(self) -> None:
        self._state: dict[str, _LockoutState] = defaultdict(_LockoutState)
        self._lock = Lock()

    def is_locked(self, identity: str, *, now: float | None = None) -> tuple[bool, int]:
        current = now if now is not None else time.time()
        with self._lock:
            state = self._state.get(identity)
            if state is None or state.locked_until <= current:
                return False, 0
            return True, int(state.locked_until - current) + 1

    def record_failure(self, identity: str, *, now: float | None = None) -> None:
        current = now if now is not None else time.time()
        with self._lock:
            state = self._state[identity]
            state.failures += 1
            if state.failures >= self.THRESHOLD:
                tier = min(
                    (state.failures - self.THRESHOLD) // self.THRESHOLD,
                    len(self.BACKOFFS) - 1,
                )
                state.locked_until = current + self.BACKOFFS[tier]

    def record_success(self, identity: str) -> None:
        with self._lock:
            self._state.pop(identity, None)

    # Async interface — no IO in-process, so these just wrap the sync path. The
    # Redis backend overrides them with real awaits (same shape).
    async def ais_locked(self, identity: str, *, now: float | None = None) -> tuple[bool, int]:
        return self.is_locked(identity, now=now)

    async def arecord_failure(self, identity: str, *, now: float | None = None) -> None:
        self.record_failure(identity, now=now)

    async def arecord_success(self, identity: str) -> None:
        self.record_success(identity)

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


class ReplayGuard:
    """One-time use for values that must never work twice.

    TOTP codes are the motivating case: a code stays valid for a 30s window, so
    without this an attacker who observes one (shoulder-surf, phishing proxy,
    malware) can replay it inside that window.
    """

    def __init__(self, ttl: int = 120) -> None:
        self._ttl = ttl
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def check_and_record(self, key: str, *, now: float | None = None) -> bool:
        """False if this key has already been used."""
        current = now if now is not None else time.time()
        with self._lock:
            for stale in [k for k, exp in self._seen.items() if exp <= current]:
                del self._seen[stale]
            if key in self._seen:
                return False
            self._seen[key] = current + self._ttl
            return True

    async def acheck_and_record(self, key: str, *, now: float | None = None) -> bool:
        return self.check_and_record(key, now=now)

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


class TokenRevocations:
    """Refresh-token rotation. Presenting a rotated token means it was stolen
    (or replayed), so the whole family is revoked rather than just that token."""

    def __init__(self) -> None:
        self._revoked_jti: dict[str, float] = {}
        self._revoked_users: dict[str, float] = {}
        self._lock = Lock()

    def revoke_jti(self, jti: str, *, expires_at: float) -> None:
        with self._lock:
            self._revoked_jti[jti] = expires_at

    def revoke_user(self, user_id: str, *, until: float) -> None:
        with self._lock:
            self._revoked_users[user_id] = until

    def is_revoked(self, jti: str, user_id: str, *, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        with self._lock:
            for store in (self._revoked_jti, self._revoked_users):
                for key in [k for k, exp in store.items() if exp <= current]:
                    del store[key]
            if jti in self._revoked_jti:
                return True
            return user_id in self._revoked_users

    async def arevoke_jti(self, jti: str, *, expires_at: float) -> None:
        self.revoke_jti(jti, expires_at=expires_at)

    async def arevoke_user(self, user_id: str, *, until: float) -> None:
        self.revoke_user(user_id, until=until)

    async def ais_revoked(self, jti: str, user_id: str, *, now: float | None = None) -> bool:
        return self.is_revoked(jti, user_id, now=now)

    def reset(self) -> None:
        with self._lock:
            self._revoked_jti.clear()
            self._revoked_users.clear()


# ── Redis-backed auth stores (shared across instances) ───────────────────────
# Same async interface as the in-process classes; a Redis error fails over to a
# per-instance fallback so a cache blip degrades protection rather than locking
# everyone out or throwing in the auth path.
class RedisAccountLockout:
    THRESHOLD = AccountLockout.THRESHOLD
    BACKOFFS = AccountLockout.BACKOFFS

    def __init__(self, client, *, fallback: AccountLockout | None = None) -> None:  # noqa: ANN001
        self._c = client
        self._fb = fallback or AccountLockout()

    async def ais_locked(self, identity: str, *, now: float | None = None) -> tuple[bool, int]:
        current = now if now is not None else time.time()
        try:
            v = await self._c.get(f"lk:until:{identity}")
        except Exception:
            return self._fb.is_locked(identity, now=now)
        if v is None:
            return False, 0
        until = float(v)
        return (True, int(until - current) + 1) if until > current else (False, 0)

    async def arecord_failure(self, identity: str, *, now: float | None = None) -> None:
        current = now if now is not None else time.time()
        try:
            fails = await self._c.incr(f"lk:fail:{identity}")
            await self._c.expire(f"lk:fail:{identity}", self.BACKOFFS[-1])
            if fails >= self.THRESHOLD:
                tier = min((fails - self.THRESHOLD) // self.THRESHOLD, len(self.BACKOFFS) - 1)
                backoff = self.BACKOFFS[tier]
                await self._c.set(f"lk:until:{identity}", current + backoff, ex=backoff + 1)
        except Exception:
            logger.warning("redis lockout unavailable — using in-process fallback")
            self._fb.record_failure(identity, now=now)

    async def arecord_success(self, identity: str) -> None:
        try:
            await self._c.delete(f"lk:fail:{identity}", f"lk:until:{identity}")
        except Exception:
            self._fb.record_success(identity)


class RedisReplayGuard:
    def __init__(self, client, *, ttl: int = 120, fallback: ReplayGuard | None = None) -> None:  # noqa: ANN001
        self._c = client
        self._ttl = ttl
        self._fb = fallback or ReplayGuard(ttl=ttl)

    async def acheck_and_record(self, key: str, *, now: float | None = None) -> bool:
        try:
            # SET NX is atomic: it succeeds only on first use inside the TTL.
            ok = await self._c.set(f"rp:{key}", "1", nx=True, ex=self._ttl)
            return bool(ok)
        except Exception:
            logger.warning("redis replay guard unavailable — using in-process fallback")
            return self._fb.check_and_record(key, now=now)


class RedisTokenRevocations:
    def __init__(self, client, *, fallback: TokenRevocations | None = None) -> None:  # noqa: ANN001
        self._c = client
        self._fb = fallback or TokenRevocations()

    async def arevoke_jti(self, jti: str, *, expires_at: float) -> None:
        ttl = max(1, int(expires_at - time.time()))
        try:
            await self._c.set(f"rev:jti:{jti}", "1", ex=ttl)
        except Exception:
            self._fb.revoke_jti(jti, expires_at=expires_at)

    async def arevoke_user(self, user_id: str, *, until: float) -> None:
        ttl = max(1, int(until - time.time()))
        try:
            await self._c.set(f"rev:user:{user_id}", "1", ex=ttl)
        except Exception:
            self._fb.revoke_user(user_id, until=until)

    async def ais_revoked(self, jti: str, user_id: str, *, now: float | None = None) -> bool:
        try:
            hits = await self._c.exists(f"rev:jti:{jti}", f"rev:user:{user_id}")
            return int(hits) > 0
        except Exception:
            return self._fb.is_revoked(jti, user_id, now=now)


limiter = RateLimiter()
_active_limiter = limiter  # in-process by default
lockout = AccountLockout()
totp_replay = ReplayGuard()
revocations = TokenRevocations()

# Active auth backends — swapped for the Redis variants at startup when a shared
# store is configured; default to the in-process instances (and their fallbacks).
_active_lockout: object = lockout
_active_replay: object = totp_replay
_active_revocations: object = revocations


def use_auth_backends(*, lockout=None, replay=None, revocations=None) -> None:  # noqa: ANN001
    global _active_lockout, _active_replay, _active_revocations
    if lockout is not None:
        _active_lockout = lockout
    if replay is not None:
        _active_replay = replay
    if revocations is not None:
        _active_revocations = revocations


def active_lockout():  # noqa: ANN201
    return _active_lockout


def active_replay():  # noqa: ANN201
    return _active_replay


def active_revocations():  # noqa: ANN201
    return _active_revocations


def reset_all() -> None:
    """Test hook."""
    global _active_lockout, _active_replay, _active_revocations
    limiter.reset()
    use_backend(limiter)  # never leave a test on a swapped backend
    lockout.reset()
    totp_replay.reset()
    revocations.reset()
    # Restore in-process auth backends so a test that swapped in Redis is isolated.
    _active_lockout, _active_replay, _active_revocations = lockout, totp_replay, revocations


def clamp_text(text: str, limit: int = MAX_ANALYSED_TEXT_CHARS) -> str:
    """Bound anything attacker-controlled before regex or tokenisation."""
    return text if len(text) <= limit else text[:limit]


def valid_domain(domain: str) -> bool:
    """Structural validation before a domain reaches DNS or comparison.

    Also blocks the obvious SSRF-adjacent inputs — an IP literal or a
    single-label internal name should never reach a resolver from user input.
    """
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    candidate = domain.strip().rstrip(".").lower()
    if not candidate or ".." in candidate or "/" in candidate or "@" in candidate:
        return False
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    # Reject bare IPv4 and anything with a port or scheme.
    if all(label.isdigit() for label in labels):
        return False
    if ":" in candidate:
        return False
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" or ord(c) > 127 for c in label):
            return False
    return True
