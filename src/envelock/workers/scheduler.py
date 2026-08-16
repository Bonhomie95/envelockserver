"""The in-process periodic scheduler (PRD §8.1 E6, §15.2, §17).

Everything that must run on a timer lives here. Before this module the only
background task was the IMAP poller, which meant E6 escalation never fired,
retention never purged, OAuth tokens never refreshed, and the Channel-3 domain
watchers — the free Guard tier and the pre-signup demo — never ran. Each job is a
plain async function so it stays unit-testable; the scheduler only owns the loop,
the interval, and the "one crash never kills the others" isolation.

A single instance runs everything. A multi-instance deployment should elect one
scheduler leader (Redis lock); until then run the scheduler on exactly one replica
(`ENVELOCK_SCHEDULER_ENABLED=false` on the others).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from envelock.config import get_settings
from envelock.db import get_sessionmaker

logger = logging.getLogger(__name__)

Job = Callable[[], Awaitable[dict | list | None]]


async def _run_forever(name: str, job: Job, *, interval: float, stop: asyncio.Event) -> None:
    """Run `job` every `interval` seconds until `stop` is set. A job that raises is
    logged and retried next tick — one failing job never stops the others."""
    import contextlib

    # Small initial stagger so all jobs don't fire in the same instant at boot.
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=min(interval, 5.0))
    while not stop.is_set():
        try:
            result = await job()
            if result:
                logger.info("scheduler job ran", extra={"job": name, "result": result})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("scheduler job failed: %s", exc, extra={"job": name})
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue


# ── Individual jobs ───────────────────────────────────────────────────────────
async def escalation_job() -> dict:
    """E6 — escalate unacknowledged Criticals across every tenant."""
    from envelock.notify.dispatch import deliver_pending, run_escalation_cycle

    async with get_sessionmaker()() as session:
        escalated = await run_escalation_cycle(session)
        # Also flush any pending ladder deliveries (L1/L2) that the raise path
        # queued but a same-request dispatch didn't complete.
        delivered = await deliver_pending(session)
        await session.commit()
    return {"escalated": len(escalated), "delivered": len(delivered)}


async def retention_job() -> dict:
    """§15.2 — actually delete expired data. Demonstrable, on a timer."""
    from envelock.governance.retention import purge_expired

    async with get_sessionmaker()() as session:
        counts = await purge_expired(session)
    return {"purged": counts}


async def oauth_refresh_job() -> dict:
    """Keep Tier-1 (Graph/Gmail) access tokens alive. Without this, OAuth
    mailboxes go dark ~1h after connection."""
    from envelock.channels.mail.oauth_refresh import refresh_due_tokens

    async with get_sessionmaker()() as session:
        refreshed = await refresh_due_tokens(session)
    return {"refreshed": refreshed}


async def oauth_fetch_job() -> dict:
    """Pull new mail for connected Tier-1 mailboxes (the API/webhook-less fetch
    path). A webhook receiver short-circuits this when configured, but polling is
    the always-correct fallback."""
    from envelock.workers.oauth_fetch import fetch_all_oauth_mailboxes

    return await fetch_all_oauth_mailboxes()


async def domain_reverify_job() -> dict:
    """Revoke a domain's verification if its DNS proof was deleted — so a domain we
    once trusted can't stay trusted after the customer loses control of it. Only a
    conclusive 'record absent' revokes; transient DNS failures are ignored."""
    from envelock.api.tenants import revalidate_verified_domains

    async with get_sessionmaker()() as session:
        return await revalidate_verified_domains(session)


# ── Channel-3 CT-log watcher ──────────────────────────────────────────────────
async def _load_protected_domains() -> frozenset[str]:
    from sqlalchemy import select

    from envelock.models import Domain

    async with get_sessionmaker()() as session:
        rows = (await session.execute(select(Domain.registrable_domain))).scalars().all()
    return frozenset(r for r in rows if r)


async def run_ct_watcher(stop: asyncio.Event) -> None:
    """D2 — the primary Channel-3 sensor. Persists every lookalike match and
    raises a weaponisation-scored alert. Resilient: a certstream outage reconnects
    with backoff and the protected-domain set refreshes periodically."""
    from envelock.workers.watchers import CertTransparencyWatcher

    settings = get_settings()
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    def on_match(obs) -> None:  # noqa: ANN001
        import contextlib

        # Drop under flood rather than block the hot CT loop.
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(obs)

    protected = await _load_protected_domains()
    watcher = CertTransparencyWatcher(protected_domains=protected, on_match=on_match)

    async def refresh_domains() -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(
                    stop.wait(), timeout=settings.watcher_domain_refresh_seconds
                )
            except TimeoutError:
                watcher.protected = set(await _load_protected_domains())

    async def drain() -> None:
        from envelock.workers.ct_persist import persist_observation

        while not stop.is_set():
            try:
                obs = await asyncio.wait_for(queue.get(), timeout=2.0)
            except TimeoutError:
                continue
            try:
                async with get_sessionmaker()() as session:
                    await persist_observation(session, obs)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ct persist failed: %s", exc)

    watch_task = asyncio.create_task(watcher.run())
    refresh_task = asyncio.create_task(refresh_domains())
    drain_task = asyncio.create_task(drain())
    await stop.wait()
    watcher.stop()
    for t in (watch_task, refresh_task, drain_task):
        t.cancel()
    import contextlib

    for t in (watch_task, refresh_task, drain_task):
        with contextlib.suppress(asyncio.CancelledError):
            await t


# ── Scheduler entrypoint ──────────────────────────────────────────────────────
def start(stop: asyncio.Event) -> list[asyncio.Task]:
    """Launch every scheduled job as a background task. Returns the tasks so the
    lifespan can cancel them on shutdown."""
    settings = get_settings()
    tasks: list[asyncio.Task] = [
        asyncio.create_task(
            _run_forever(
                "escalation", escalation_job,
                interval=settings.escalation_cycle_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "retention", retention_job,
                interval=settings.retention_purge_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "oauth_refresh", oauth_refresh_job,
                interval=settings.oauth_refresh_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "oauth_fetch", oauth_fetch_job,
                interval=settings.oauth_refresh_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "domain_reverify", domain_reverify_job,
                interval=settings.domain_reverify_seconds, stop=stop,
            )
        ),
    ]
    if settings.ct_watcher_enabled:
        tasks.append(asyncio.create_task(run_ct_watcher(stop)))
    logger.info("scheduler started (%d jobs)", len(tasks))
    return tasks
