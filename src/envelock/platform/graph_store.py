"""Durable backing for the E8 counterparty graph.

Keeps `graph.py` a pure, synchronous structure (the detection pipeline reads it on
the hot path) while making the moat survive restarts and be shared across
instances: verdicts are written through to `graph_verdicts` on every report and
hydrated back into the in-memory projection at startup.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import GraphVerdict
from envelock.platform.graph import GRAPH, CounterpartyGraph, GraphEntry, Verdict


async def persist_report(
    session: AsyncSession, entry: GraphEntry, reporters: set[str]
) -> None:
    """Upsert a verdict. Called after `GRAPH.report(...)` so memory and the store
    never diverge."""
    row = await session.get(GraphVerdict, entry.registrable_domain)
    if row is None:
        row = GraphVerdict(
            registrable_domain=entry.registrable_domain,
            first_reported=entry.first_reported,
        )
        session.add(row)
    row.verdict = entry.verdict.value
    row.confirmations = entry.confirmations
    row.last_reported = entry.last_reported
    row.techniques = sorted(entry.techniques)
    row.reporter_tenant_ids = sorted(reporters)


async def hydrate(session: AsyncSession, graph: CounterpartyGraph = GRAPH) -> int:
    """Load every persisted verdict into the projection. Returns the count."""
    rows = (await session.execute(select(GraphVerdict))).scalars().all()
    graph.clear()
    for row in rows:
        graph.load(
            GraphEntry(
                registrable_domain=row.registrable_domain,
                verdict=Verdict(row.verdict),
                confirmations=row.confirmations,
                first_reported=row.first_reported,
                last_reported=row.last_reported,
                techniques=frozenset(row.techniques or []),
            ),
            set(row.reporter_tenant_ids or []),
        )
    return len(rows)
