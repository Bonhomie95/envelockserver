"""Tier 3 IMAP connection broker (PRD §5.3, §12.11D).

Two strategies from day one, because retrofitting polling into an IDLE-only
broker means rewriting it:

* **Protected** mailboxes hold IDLE — quarantine latency is the product.
* **Monitored** mailboxes poll — no persistent connection, so the per-egress-IP
  concurrency ceiling stops binding, which is what keeps whole-domain coverage
  affordable.

The dominant Tier 3 cost is IP addresses, not compute: providers cap concurrent
connections per source IP, so the broker budgets connections per provider and
rotates a pool of egress addresses.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from envelock.config import get_settings
from envelock.core.enums import MailboxClass, SourceMechanism


class Strategy(StrEnum):
    IDLE = "idle"
    POLL = "poll"


def strategy_for(mailbox_class: MailboxClass) -> Strategy:
    return Strategy.IDLE if mailbox_class is MailboxClass.PROTECTED else Strategy.POLL


def source_for(strategy: Strategy) -> SourceMechanism:
    return (
        SourceMechanism.IMAP_IDLE if strategy is Strategy.IDLE else SourceMechanism.IMAP_POLL
    )


@dataclass(frozen=True, slots=True)
class Connection:
    mailbox_id: UUID
    address: str
    host: str
    port: int
    strategy: Strategy
    egress_ip: str | None


class EgressPool:
    """Rotates source IPs so a provider's per-IP cap does not bound how many
    mailboxes we can serve."""

    def __init__(self, ips: list[str], *, per_ip_limit: int) -> None:
        self._ips = ips or [""]  # "" = the host's default route
        self._limit = max(per_ip_limit, 1)
        self._counts: dict[str, int] = defaultdict(int)

    def acquire(self) -> str | None:
        for ip in sorted(self._ips, key=lambda i: self._counts[i]):
            if self._counts[ip] < self._limit:
                self._counts[ip] += 1
                return ip or None
        return None

    def release(self, ip: str | None) -> None:
        key = ip or ""
        if self._counts[key] > 0:
            self._counts[key] -= 1

    @property
    def capacity(self) -> int:
        return len(self._ips) * self._limit

    @property
    def in_use(self) -> int:
        return sum(self._counts.values())

    @property
    def exhausted(self) -> bool:
        return self.in_use >= self.capacity


@dataclass
class BrokerStats:
    idle_connections: int = 0
    polled_mailboxes: int = 0
    reconnects: int = 0
    throttled: int = 0
    degraded_to_poll: int = 0
    errors: int = 0


class ImapBroker:
    """Owns every IMAP connection. Deliberately a separate service from the API:
    a reconnect storm must never take the API down with it.
    """

    def __init__(
        self,
        *,
        egress_ips: list[str] | None = None,
        per_ip_limit: int | None = None,
        poll_seconds: int | None = None,
        idle_refresh_seconds: int | None = None,
        jitter_seconds: int | None = None,
    ) -> None:
        settings = get_settings()
        self.pool = EgressPool(
            egress_ips if egress_ips is not None else settings.egress_ip_pool,
            per_ip_limit=per_ip_limit or settings.imap_max_connections_per_egress_ip,
        )
        self.poll_seconds = poll_seconds or settings.imap_monitored_poll_seconds
        self.idle_refresh_seconds = (
            idle_refresh_seconds or settings.imap_idle_refresh_seconds
        )
        self.jitter_seconds = (
            jitter_seconds
            if jitter_seconds is not None
            else settings.imap_reconnect_jitter_seconds
        )
        self.stats = BrokerStats()
        self._connections: dict[UUID, Connection] = {}
        self._tasks: dict[UUID, asyncio.Task] = {}
        self._running = False

    # ── Registration ─────────────────────────────────────────────────────────
    def register(
        self,
        *,
        mailbox_id: UUID,
        address: str,
        host: str,
        port: int,
        mailbox_class: MailboxClass,
    ) -> Connection:
        """Assign a strategy and an egress IP. If the pool is exhausted an IDLE
        mailbox degrades to polling rather than being dropped — reduced latency
        beats no coverage, and the degradation is visible in stats."""
        strategy = strategy_for(mailbox_class)
        egress: str | None = None

        if strategy is Strategy.IDLE:
            if self.pool.exhausted:
                strategy = Strategy.POLL
                self.stats.degraded_to_poll += 1
                self.stats.throttled += 1
            else:
                egress = self.pool.acquire()

        conn = Connection(
            mailbox_id=mailbox_id,
            address=address,
            host=host,
            port=port,
            strategy=strategy,
            egress_ip=egress,
        )
        self._connections[mailbox_id] = conn
        if strategy is Strategy.IDLE:
            self.stats.idle_connections += 1
        else:
            self.stats.polled_mailboxes += 1
        return conn

    def unregister(self, mailbox_id: UUID) -> None:
        conn = self._connections.pop(mailbox_id, None)
        if conn is None:
            return
        if conn.strategy is Strategy.IDLE:
            self.pool.release(conn.egress_ip)
            self.stats.idle_connections -= 1
        else:
            self.stats.polled_mailboxes -= 1
        task = self._tasks.pop(mailbox_id, None)
        if task:
            task.cancel()

    def connection(self, mailbox_id: UUID) -> Connection | None:
        return self._connections.get(mailbox_id)

    # ── Scheduling ───────────────────────────────────────────────────────────
    def next_wake(self, conn: Connection, *, now: datetime | None = None) -> float:
        """Seconds until this connection next does work.

        IDLE re-issues before the RFC 29-minute limit; polling waits its
        interval. Both are jittered so a restart does not become a storm.
        """
        base = (
            self.idle_refresh_seconds
            if conn.strategy is Strategy.IDLE
            else self.poll_seconds
        )
        return base + random.uniform(0, self.jitter_seconds)  # noqa: S311 — scheduling jitter

    def backoff(self, attempt: int) -> float:
        """Exponential with jitter, capped. Providers throttle aggressively and a
        tight retry loop gets the egress IP blocked."""
        return min(2**attempt, 300) + random.uniform(0, 5)  # noqa: S311

    # ── Lifecycle ────────────────────────────────────────────────────────────
    async def start(self, handler) -> None:  # noqa: ANN001
        self._running = True
        for conn in list(self._connections.values()):
            self._tasks[conn.mailbox_id] = asyncio.create_task(self._run(conn, handler))

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks.values():
            task.cancel()
        for task in self._tasks.values():
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()

    async def _run(self, conn: Connection, handler) -> None:  # noqa: ANN001
        attempt = 0
        # Stagger the initial connect across the fleet.
        await asyncio.sleep(random.uniform(0, self.jitter_seconds))  # noqa: S311
        while self._running:
            try:
                await handler(conn)
                attempt = 0
                await asyncio.sleep(self.next_wake(conn))
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stats.errors += 1
                self.stats.reconnects += 1
                attempt += 1
                await asyncio.sleep(self.backoff(attempt))

    def snapshot(self) -> dict:
        return {
            "idle_connections": self.stats.idle_connections,
            "polled_mailboxes": self.stats.polled_mailboxes,
            "reconnects": self.stats.reconnects,
            "throttled": self.stats.throttled,
            "degraded_to_poll": self.stats.degraded_to_poll,
            "errors": self.stats.errors,
            "egress_capacity": self.pool.capacity,
            "egress_in_use": self.pool.in_use,
            "poll_seconds": self.poll_seconds,
            "measured_at": datetime.now(UTC).isoformat(),
        }
