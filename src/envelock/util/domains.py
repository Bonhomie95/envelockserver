"""Domain normalisation and similarity.

Public Suffix List handling matters more here than anywhere else in the codebase:
naive splitting would break every `.co.uk`, `.com.tw`, `.com.au` and `.co.jp`
customer — i.e. exactly our target markets (PRD §12.7).
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

try:  # optional at import time so the module is testable without the PSL cache
    import tldextract

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _EXTRACT = None

#: Confusable pairs we normalise before comparison. Covers the founding brief's
#: "a to e, I to l, l to I, g to q" plus the Unicode homoglyphs that matter.
_SKELETON_MAP = str.maketrans(
    {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
        "8": "b", "9": "g", "|": "l", "!": "i",
        "і": "i", "І": "i",  # Cyrillic
        "е": "e", "Е": "e",
        "а": "a", "А": "a",
        "о": "o", "О": "o",
        "с": "c", "С": "c",
        "р": "p", "Р": "p",
        "ѕ": "s", "ԛ": "q", "ԁ": "d", "һ": "h", "ѵ": "v", "х": "x",
        "ɡ": "g", "ı": "i", "ȷ": "j",
    }
)

_FREE_MAIL = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
        "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
        "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com",
        "qq.com", "163.com", "126.com", "sina.com", "foxmail.com",
        "naver.com", "yandex.com", "rediffmail.com",
    }
)


@lru_cache(maxsize=100_000)
def registrable_domain(domain: str) -> str:
    """eTLD+1. Falls back to a two-label heuristic only if the PSL is missing."""
    d = domain.strip().lower().rstrip(".")
    if not d:
        return ""
    if "@" in d:
        d = d.rpartition("@")[2]
    d = _to_unicode(d)
    if _EXTRACT is not None:
        parsed = _EXTRACT(d)
        if parsed.domain and parsed.suffix:
            return f"{parsed.domain}.{parsed.suffix}"
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def _to_unicode(domain: str) -> str:
    """Punycode-decode so homoglyph comparison sees the real glyphs."""
    if "xn--" not in domain:
        return domain
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def is_free_mail(domain: str) -> bool:
    """Free-mail domains must be excluded from the trial ledger — locking
    `gmail.com` would block every subsequent Gmail signup (PRD §12.7)."""
    return registrable_domain(domain) in _FREE_MAIL


def skeleton(domain: str) -> str:
    """Collapse a domain to its visual skeleton.

    Two domains with the same skeleton render near-identically — this is what
    catches `rn`/`m` and Cyrillic substitution that string distance alone misses.
    """
    d = _to_unicode(domain.lower())
    d = unicodedata.normalize("NFKD", d)
    d = "".join(c for c in d if not unicodedata.combining(c))
    d = d.translate(_SKELETON_MAP)
    return d.replace("rn", "m").replace("vv", "w").replace("-", "")


def label(domain: str) -> str:
    """The registrable domain without its suffix — `acme` from `acme.co.uk`."""
    reg = registrable_domain(domain)
    return reg.partition(".")[0] if reg else ""


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def similarity(a: str, b: str) -> float:
    """0..1 over the registrable label."""
    la, lb = label(a), label(b)
    if not la or not lb:
        return 0.0
    longest = max(len(la), len(lb))
    return 1.0 - (edit_distance(la, lb) / longest)


def classify_lookalike(candidate: str, protected: str) -> tuple[str, float] | None:
    """Return (technique, similarity) if `candidate` impersonates `protected`.

    Ordered most- to least-specific so the reported technique is the tightest
    explanation, which is what the alert shows the user.
    """
    cand_reg, prot_reg = registrable_domain(candidate), registrable_domain(protected)
    if not cand_reg or not prot_reg or cand_reg == prot_reg:
        return None

    cand_label, prot_label = label(cand_reg), label(prot_reg)

    # Same label, different TLD — the founding brief's ".com to .org".
    if cand_label == prot_label:
        return ("tld_swap", 0.95)

    # Renders identically once collapsed to its skeleton (A4).
    if skeleton(cand_label) == skeleton(prot_label):
        return ("homoglyph", 0.98)

    # Contains the brand plus decoration — `acme-invoices.com` (A3 cousin).
    if prot_label in cand_label and len(prot_label) >= 4:
        return ("cousin", 0.85)

    # Typosquat: within a small edit distance, scaled to label length.
    distance = edit_distance(cand_label, prot_label)
    threshold = 1 if len(prot_label) <= 6 else 2
    if distance <= threshold:
        return ("typosquat", 1.0 - distance / max(len(cand_label), len(prot_label)))

    return None
