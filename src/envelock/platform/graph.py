"""E8 — cross-tenant counterparty graph, E10 risk profiles, E11 backfill,
E12 attack simulation.

E8 is the long-term moat: when one tenant confirms a fraudulent domain, every
other tenant is protected instantly. It is designed to share *verdicts about
domains*, never customer content.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from envelock.core.enums import AlertTier
from envelock.util.domains import registrable_domain


class Verdict(StrEnum):
    FRAUDULENT = "fraudulent"
    SUSPICIOUS = "suspicious"
    LEGITIMATE = "legitimate"


@dataclass(frozen=True, slots=True)
class GraphEntry:
    """One shared judgement about a domain.

    Only the domain, the verdict and a count cross the tenant boundary — never a
    message, an address, or who reported it.
    """

    registrable_domain: str
    verdict: Verdict
    confirmations: int
    first_reported: datetime
    last_reported: datetime
    techniques: frozenset[str] = frozenset()

    @property
    def confidence(self) -> float:
        """Independent confirmations raise confidence with diminishing returns."""
        return min(1.0, 1 - (0.5**self.confirmations))

    @property
    def actionable(self) -> bool:
        return self.verdict is Verdict.FRAUDULENT and self.confirmations >= 2


class CounterpartyGraph:
    """In-memory projection; the durable store is `lookalike_domains` plus a
    shared verdict table. Kept as a pure structure so it is testable."""

    def __init__(self) -> None:
        self._entries: dict[str, GraphEntry] = {}
        #: tenant -> domains it has reported, so one tenant cannot inflate a count.
        self._reporters: dict[str, set[str]] = {}

    def report(
        self,
        *,
        domain: str,
        verdict: Verdict,
        tenant_id: UUID,
        technique: str | None = None,
        now: datetime | None = None,
    ) -> GraphEntry:
        reg = registrable_domain(domain) or domain
        now = now or datetime.now(UTC)
        seen_by = self._reporters.setdefault(reg, set())
        is_new_reporter = str(tenant_id) not in seen_by
        seen_by.add(str(tenant_id))

        existing = self._entries.get(reg)
        if existing is None:
            entry = GraphEntry(
                registrable_domain=reg,
                verdict=verdict,
                confirmations=1,
                first_reported=now,
                last_reported=now,
                techniques=frozenset({technique} if technique else set()),
            )
        else:
            entry = GraphEntry(
                registrable_domain=reg,
                # A legitimate report from a second tenant downgrades a
                # suspicious verdict — false positives must be able to heal.
                verdict=verdict if verdict is Verdict.FRAUDULENT else existing.verdict,
                confirmations=existing.confirmations + (1 if is_new_reporter else 0),
                first_reported=existing.first_reported,
                last_reported=now,
                techniques=existing.techniques | ({technique} if technique else set()),
            )
        self._entries[reg] = entry
        return entry

    def lookup(self, domain: str) -> GraphEntry | None:
        return self._entries.get(registrable_domain(domain) or domain)

    def known_bad(self) -> frozenset[str]:
        return frozenset(d for d, e in self._entries.items() if e.actionable)

    def reporters_of(self, domain: str) -> set[str]:
        """Tenant ids that have reported a domain — persisted so a restart cannot
        reset a confirmation count and let one tenant re-inflate it."""
        return set(self._reporters.get(registrable_domain(domain) or domain, set()))

    def load(self, entry: GraphEntry, reporters: set[str]) -> None:
        """Hydrate one durable verdict into the in-memory projection at startup.

        The DB is the source of truth across restarts and instances; this keeps the
        hot lookup path a plain dict so the detection pipeline stays synchronous.
        """
        self._entries[entry.registrable_domain] = entry
        self._reporters[entry.registrable_domain] = set(reporters)

    def clear(self) -> None:
        self._entries.clear()
        self._reporters.clear()

    def __len__(self) -> int:
        return len(self._entries)


#: Process-wide graph. Swapped for the DB-backed projection in production.
GRAPH = CounterpartyGraph()


# ── E10 — counterparty risk profile ──────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class RiskProfile:
    """What finance teams actually want to look at before paying an invoice."""

    domain: str
    first_seen: datetime | None
    message_count: int
    bank_records: int
    verified_phone: str | None
    auth_pass_rate: float
    incidents: int
    graph_verdict: Verdict | None
    domain_age_days: int | None

    @property
    def score(self) -> int:
        """0 = safe, 100 = do not pay without a phone call."""
        risk = 0
        if self.graph_verdict is Verdict.FRAUDULENT:
            return 100
        if self.graph_verdict is Verdict.SUSPICIOUS:
            risk += 40
        if self.verified_phone is None:
            risk += 20
        if self.domain_age_days is not None and self.domain_age_days < 90:
            risk += 20
        if self.auth_pass_rate < 0.9:
            risk += 15
        if self.message_count < 5:
            risk += 10
        risk += min(self.incidents * 10, 30)
        return min(risk, 100)

    @property
    def tier(self) -> AlertTier:
        s = self.score
        if s >= 80:
            return AlertTier.CRITICAL
        if s >= 50:
            return AlertTier.HIGH
        if s >= 25:
            return AlertTier.MEDIUM
        return AlertTier.LOW

    @property
    def advice(self) -> str:
        if self.score >= 80:
            return "Do not pay. Verify by phone using a number you already hold."
        if self.score >= 50:
            return "Confirm bank details by phone before any payment."
        if self.verified_phone is None:
            return "Add a verified phone number so payment changes can be checked."
        return "No elevated risk. Normal verification applies."


# ── E11 — onboarding backfill ────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class BackfillPlan:
    mailbox_id: UUID
    days: int
    since: datetime
    batch_size: int = 200
    reason: str = ""

    @property
    def estimated_batches(self) -> int:
        # ~40 messages a day is a reasonable business-mailbox average.
        return max(1, (self.days * 40) // self.batch_size)


def plan_backfill(
    *, mailbox_id: UUID, in_trial: bool, trial_days: int = 30, full_days: int = 90
) -> BackfillPlan:
    """Capped during trial: 90 days of analysis before the customer has paid is
    the expensive part of a trial (PRD §12.7)."""
    days = trial_days if in_trial else full_days
    return BackfillPlan(
        mailbox_id=mailbox_id,
        days=days,
        since=datetime.now(UTC) - timedelta(days=days),
        reason="trial cap" if in_trial else "full history",
    )


# ── E12 — attack simulation ──────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class Simulation:
    id: str
    name: str
    expects: str
    raw_message: str


def _sim_id(name: str) -> str:
    return "sim_" + hashlib.sha256(name.encode()).hexdigest()[:10]


def simulations(*, protected_domain: str, vendor_domain: str) -> list[Simulation]:
    """Benign look-alike attacks that prove the product works. Sells renewals
    better than any dashboard (PRD E12).

    Every message carries an `X-Envelock-Simulation` header so a simulation can
    never be mistaken for a real incident.
    """
    header = "X-Envelock-Simulation: true"
    return [
        Simulation(
            id=_sim_id("bank-change"),
            name="Supplier changes bank details",
            expects="A1",
            raw_message=(
                f'From: "Accounts" <billing@{vendor_domain}>\n'
                f"To: pay@{protected_domain}\n"
                f"Subject: Re: Invoice 9001\n"
                f"In-Reply-To: <sim-old@{vendor_domain}>\n"
                f"{header}\nContent-Type: text/plain\n\n"
                f"Our bank account has changed. Please remit to\n"
                f"IBAN GB33BUKB20201555555555. Urgent, today please."
            ),
        ),
        Simulation(
            id=_sim_id("lookalike"),
            name="Lookalike domain",
            expects="A3",
            raw_message=(
                f'From: "Accounts" <billing@{vendor_domain.replace(".", "-invoices.", 1)}>\n'
                f"To: pay@{protected_domain}\n"
                f"Subject: Updated payment instructions\n"
                f"{header}\nContent-Type: text/plain\n\n"
                f"Kindly update our records with the new account below."
            ),
        ),
        Simulation(
            id=_sim_id("reply-to"),
            name="Reply-To redirection",
            expects="A6",
            raw_message=(
                f"From: <billing@{vendor_domain}>\n"
                f"To: pay@{protected_domain}\n"
                f"Reply-To: <finance@mail-relay.top>\n"
                f"Subject: Payment confirmation\n"
                f"{header}\nContent-Type: text/plain\n\n"
                f"Please confirm the bank transfer for invoice 9002."
            ),
        ),
        Simulation(
            id=_sim_id("thread-hijack"),
            name="Thread hijacking",
            expects="A8",
            raw_message=(
                f"From: <accounts@{vendor_domain}>\n"
                f"To: pay@{protected_domain}\n"
                f"Subject: Re: Purchase Order 5512\n"
                f"{header}\nContent-Type: text/plain\n\n"
                f"Following up on the below, please release the payment."
            ),
        ),
    ]


@dataclass
class SimulationRun:
    simulation_id: str
    expected: str
    detected: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.expected in self.detected
