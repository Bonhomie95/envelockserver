"""Channel 3 — brand and domain monitoring (D1–D4).

Requires no mailbox access at all, which is why Guard is free forever and why
this is the pre-sales demo (PRD S12).

Permutations are used to *filter* the CT and zone-file streams, never to
brute-force lookups — the permutation space is enormous and has a poor signal
ratio on its own (PRD D1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from envelock.core.enums import AlertTier
from envelock.util.domains import classify_lookalike, label, registrable_domain

_TLD_SWAPS = (
    "com", "net", "org", "co", "io", "biz", "info", "online", "site", "shop",
    "ng", "com.ng", "tw", "com.tw", "sg", "com.sg", "co.uk", "us", "cn", "com.cn",
)

#: The founding brief's a→e, l→I, g→q space, plus the rest that matter.
_CHAR_SWAPS = {
    "a": "e4@", "e": "a3", "i": "l1!", "l": "i1", "o": "0", "s": "5$",
    "g": "q9", "q": "g", "m": "n", "n": "m", "u": "v", "v": "u", "b": "68",
    "c": "k", "k": "c", "t": "7", "d": "b", "p": "q", "r": "n",
}


def permutations(domain: str, *, limit: int = 4000) -> set[str]:
    """Candidate lookalikes. Used as a filter set, not a lookup list."""
    reg = registrable_domain(domain)
    name = label(reg)
    suffix = reg.partition(".")[2]
    if not name:
        return set()

    out: set[str] = set()

    for tld in _TLD_SWAPS:
        if tld != suffix:
            out.add(f"{name}.{tld}")

    for i, char in enumerate(name):
        # Character substitution
        for replacement in _CHAR_SWAPS.get(char, ""):
            out.add(f"{name[:i]}{replacement}{name[i + 1:]}.{suffix}")
        # Omission
        if len(name) > 3:
            out.add(f"{name[:i]}{name[i + 1:]}.{suffix}")
        # Duplication
        out.add(f"{name[:i]}{char}{char}{name[i + 1:]}.{suffix}")
        # Transposition
        if i + 1 < len(name):
            out.add(f"{name[:i]}{name[i + 1]}{name[i]}{name[i + 2:]}.{suffix}")

    # rn/m confusion renders identically at small sizes
    if "m" in name:
        out.add(f"{name.replace('m', 'rn', 1)}.{suffix}")
    if "rn" in name:
        out.add(f"{name.replace('rn', 'm', 1)}.{suffix}")

    # Cousin domains — decoration around the real brand
    for word in ("invoice", "invoices", "billing", "pay", "payments", "accounts",
                 "secure", "support", "mail", "group"):
        out.add(f"{name}-{word}.{suffix}")
        out.add(f"{word}-{name}.{suffix}")

    out.discard(reg)
    return set(list(out)[:limit])


@dataclass(frozen=True, slots=True)
class LookalikeHit:
    candidate: str
    protected: str
    technique: str
    similarity: float
    has_mx: bool
    has_web: bool
    registered_at: datetime | None
    tier: AlertTier

    @property
    def is_armed(self) -> bool:
        """A lookalike with MX configured is weaponised (PRD D4)."""
        return self.has_mx


def score_candidate(
    candidate: str,
    protected: str,
    *,
    has_mx: bool = False,
    has_web: bool = False,
    registered_at: datetime | None = None,
) -> LookalikeHit | None:
    """Weaponisation scoring is what makes D1 usable instead of a firehose."""
    result = classify_lookalike(candidate, protected)
    if result is None:
        return None
    technique, similarity = result

    # MX present means it can send mail as the brand — that is the alert.
    if has_mx:
        tier = AlertTier.HIGH
    elif has_web:
        tier = AlertTier.MEDIUM
    else:
        tier = AlertTier.LOW

    if similarity >= 0.95 and has_mx:
        tier = AlertTier.HIGH

    return LookalikeHit(
        candidate=registrable_domain(candidate),
        protected=registrable_domain(protected),
        technique=technique,
        similarity=round(similarity, 3),
        has_mx=has_mx,
        has_web=has_web,
        registered_at=registered_at,
        tier=tier,
    )


def match_stream_entry(
    observed_domain: str, protected_domains: frozenset[str]
) -> tuple[str, str, float] | None:
    """Filter a CT-log or zone-file entry against the protected set.

    This is the hot path: it runs on every certificate issued worldwide, so it
    must stay allocation-light and must not do any I/O.
    """
    reg = registrable_domain(observed_domain)
    if not reg or reg in protected_domains:
        return None
    for protected in protected_domains:
        result = classify_lookalike(reg, protected)
        if result is not None:
            technique, similarity = result
            return (protected, technique, similarity)
    return None
