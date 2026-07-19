"""Detection quality targets and measurement (PRD §15.4).

P5 calls alert fatigue the failure mode that kills the product but sets no
number, which makes "is this too noisy?" unanswerable. These are the numbers.

The targets live in code so the evaluation harness, the internal dashboard and
the PRD cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class Direction(StrEnum):
    LOWER_IS_BETTER = "lower_is_better"
    HIGHER_IS_BETTER = "higher_is_better"


@dataclass(frozen=True, slots=True)
class Target:
    id: str
    name: str
    target: float
    unit: str
    direction: Direction
    rationale: str

    def meets(self, observed: float) -> bool:
        if self.direction is Direction.LOWER_IS_BETTER:
            return observed <= self.target
        return observed >= self.target


TARGETS: tuple[Target, ...] = (
    Target(
        "critical_fp_rate",
        "Critical false-positive rate",
        0.01,
        "ratio",
        Direction.LOWER_IS_BETTER,
        "Every Critical interrupts a human and may quarantine real mail. Above "
        "1% the interrupt stops being believed.",
    ),
    Target(
        "criticals_per_tenant_quarter",
        "Critical alerts per healthy tenant per quarter",
        5.0,
        "count",
        Direction.LOWER_IS_BETTER,
        "Above this the channel gets muted, and a muted channel protects nobody.",
    ),
    Target(
        "a1_recall",
        "A1 recall on payment-change fraud",
        0.95,
        "ratio",
        Direction.HIGHER_IS_BETTER,
        "This is the feature customers actually pay for. A miss is the whole loss.",
    ),
    Target(
        "detection_latency_p50_api",
        "Median detection latency, Tier 1–3",
        60.0,
        "seconds",
        Direction.LOWER_IS_BETTER,
        "Must beat the human reading the email, or quarantine is pointless.",
    ),
    Target(
        "detection_latency_p50_forward",
        "Median detection latency, Tier 4",
        300.0,
        "seconds",
        Direction.LOWER_IS_BETTER,
        "Post-delivery by nature; the target is alert speed, not prevention.",
    ),
    Target(
        "detonation_fallthrough",
        "Attachment detonation fall-through",
        0.05,
        "ratio",
        Direction.LOWER_IS_BETTER,
        "The single number that predicts COGS (§12.12D).",
    ),
    Target(
        "high_fp_rate",
        "High-tier false-positive rate",
        0.05,
        "ratio",
        Direction.LOWER_IS_BETTER,
        "Looser than Critical because High does not interrupt or quarantine.",
    ),
)

_BY_ID = {t.id: t for t in TARGETS}


def target(metric_id: str) -> Target:
    return _BY_ID[metric_id]


@dataclass(frozen=True, slots=True)
class Observation:
    metric_id: str
    value: float
    sample_size: int
    window_start: datetime
    window_end: datetime

    @property
    def meets_target(self) -> bool:
        return target(self.metric_id).meets(self.value)

    @property
    def significant(self) -> bool:
        """Below this, the number is noise and should not trigger action."""
        return self.sample_size >= 30


@dataclass(frozen=True, slots=True)
class Confusion:
    """Outcomes for one detection over an evaluation window."""

    service: str
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0

    @property
    def total_alerts(self) -> int:
        return self.true_positive + self.false_positive

    @property
    def precision(self) -> float:
        return self.true_positive / self.total_alerts if self.total_alerts else 1.0

    @property
    def recall(self) -> float:
        actual = self.true_positive + self.false_negative
        return self.true_positive / actual if actual else 1.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positive / self.total_alerts if self.total_alerts else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def evaluate(
    confusions: list[Confusion],
    *,
    critical_services: frozenset[str] = frozenset({"A1", "C1", "C2", "C4", "C11", "C12"}),
) -> dict:
    """Roll per-detection outcomes into the tier-level targets."""
    crit = [c for c in confusions if c.service in critical_services]
    crit_alerts = sum(c.total_alerts for c in crit)
    crit_fps = sum(c.false_positive for c in crit)
    crit_fp_rate = crit_fps / crit_alerts if crit_alerts else 0.0

    a1 = next((c for c in confusions if c.service == "A1"), None)

    results = [
        {
            "metric_id": "critical_fp_rate",
            "observed": round(crit_fp_rate, 4),
            "target": target("critical_fp_rate").target,
            "meets": target("critical_fp_rate").meets(crit_fp_rate),
            "sample_size": crit_alerts,
        }
    ]
    if a1 is not None:
        results.append(
            {
                "metric_id": "a1_recall",
                "observed": round(a1.recall, 4),
                "target": target("a1_recall").target,
                "meets": target("a1_recall").meets(a1.recall),
                "sample_size": a1.true_positive + a1.false_negative,
            }
        )

    return {
        "evaluated_at": datetime.now(UTC).isoformat(),
        "results": results,
        "all_targets_met": all(r["meets"] for r in results),
        "per_service": [
            {
                "service": c.service,
                "precision": round(c.precision, 4),
                "recall": round(c.recall, 4),
                "f1": round(c.f1, 4),
                "alerts": c.total_alerts,
            }
            for c in confusions
        ],
    }


def requires_postmortem(service: str, tier: str, was_false_positive: bool) -> bool:
    """Every Critical false positive gets a written post-mortem (PRD §15.4).

    Not because the bug is large, but because the trust cost is: a customer who
    is interrupted wrongly once discounts the next interrupt.
    """
    return was_false_positive and tier == "critical"


def targets_payload() -> list[dict]:
    return [
        {
            "id": t.id,
            "name": t.name,
            "target": t.target,
            "unit": t.unit,
            "direction": t.direction.value,
            "rationale": t.rationale,
        }
        for t in TARGETS
    ]
