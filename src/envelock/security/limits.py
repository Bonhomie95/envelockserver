"""Rate limiting, lockout and request hardening.

A security product with an unthrottled login endpoint is not a security product.
Everything here is in-process; swap the backing store for Redis when running
more than one instance (the interface is deliberately narrow).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock

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
    "auth.login": Rule(5, 300),
    "auth.register": Rule(3, 3600),
    "auth.mfa": Rule(6, 300),
    "auth.refresh": Rule(30, 300),
    "auth.recovery": Rule(5, 3600),
    "scan.domain": Rule(20, 60),
    "scan.connect": Rule(20, 60),
    "analyse": Rule(30, 60),
    "export": Rule(60, 60),
    "default": Rule(120, 60),
}


class RateLimiter:
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

    def reset(self, bucket: str | None = None, identity: str | None = None) -> None:
        with self._lock:
            if bucket is None:
                self._hits.clear()
            else:
                self._hits.pop(f"{bucket}:{identity}", None)


@dataclass
class _LockoutState:
    failures: int = 0
    locked_until: float = 0.0
    history: list[float] = field(default_factory=list)


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

    def reset(self) -> None:
        with self._lock:
            self._revoked_jti.clear()
            self._revoked_users.clear()


limiter = RateLimiter()
lockout = AccountLockout()
totp_replay = ReplayGuard()
revocations = TokenRevocations()


def reset_all() -> None:
    """Test hook."""
    limiter.reset()
    lockout.reset()
    totp_replay.reset()
    revocations.reset()


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
