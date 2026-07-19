"""Extraction of payment identifiers from message text (A1).

Deliberately dependency-free regex + checksum validation: this runs on every
inbound message, so it must be fast and must not call anything metered.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BankIdentifier:
    """A payment identifier found in a message. Defined here rather than in the
    detection framework: payments has no business importing detections, and the
    reverse direction created an import cycle."""

    scheme: str  # iban|swift|ach|sortcode|account|crypto
    identifier: str
    country: str | None = None

_IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4})\b")
#: SWIFT/BIC only counts when explicitly labelled. An unlabelled 8-letter
#: uppercase token matches ordinary words — "ATTACHED" parses as a structurally
#: valid BIC (bank ATTA, country CH, location ED) and would fire A1 on a routine
#: invoice. Real remittance details always carry the label.
_SWIFT_RE = re.compile(
    r"\b(?:SWIFT|BIC|SWIFT[\s/-]*BIC)\b\s*(?:CODE)?\s*[:\-]?\s*"
    r"([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"
)
_SORTCODE_RE = re.compile(r"\b(\d{2}[-\s]?\d{2}[-\s]?\d{2})\b")
_ACH_RE = re.compile(r"\b(\d{9})\b")
_ACCOUNT_RE = re.compile(r"\b(\d{8,17})\b")
_BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

#: Presence of these near an identifier is what makes it a *payment instruction*
#: rather than an incidental number. Drives A1 precision.
PAYMENT_CONTEXT = re.compile(
    r"\b(bank|account|acct|iban|swift|bic|routing|sort\s?code|beneficiary|"
    r"remit|remittance|wire|transfer|payment|invoice|payable|deposit)\b",
    re.IGNORECASE,
)

#: A14 — urgency and pressure. Weak alone, strong as a multiplier on A1.
URGENCY = re.compile(
    r"\b(urgent|immediately|asap|today|right away|expedite|"
    r"confidential|do not (?:tell|inform|discuss)|keep this between|"
    r"new account|updated? (?:bank|account|payment)|changed? our bank)\b",
    re.IGNORECASE,
)

_MOD97 = {c: str(i + 10) for i, c in enumerate(string.ascii_uppercase)}

#: ISO 3166-1 alpha-2. Positions 5-6 of a BIC must be a real country.
ISO_COUNTRIES = frozenset((
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT",
    "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
    "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
    "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
    "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK",
    "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
    "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR",
    "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
    "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
    "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
    "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
    "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF",
    "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW",
    "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
))


def valid_iban(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if len(v) < 15 or len(v) > 34:
        return False
    rearranged = v[4:] + v[:4]
    digits = "".join(_MOD97.get(c, c) for c in rearranged)
    if not digits.isdigit():
        return False
    return int(digits) % 97 == 1


def _normalise(value: str) -> str:
    return re.sub(r"[\s-]", "", value).upper()


def extract_bank_identifiers(text: str) -> list[BankIdentifier]:
    """Pull every plausible payment identifier out of a body or attachment.

    Returns normalised identifiers so `NG12ABCD...` and `NG12 ABCD ...` compare
    equal — otherwise a reformatted invoice would look like a bank change.
    """
    if not text:
        return []

    found: dict[str, BankIdentifier] = {}

    for match in _IBAN_RE.finditer(text.upper()):
        raw = match.group(1)
        if valid_iban(raw):
            norm = _normalise(raw)
            found[norm] = BankIdentifier("iban", norm, country=norm[:2])

    for match in _SWIFT_RE.finditer(text.upper()):
        norm = _normalise(match.group(1))
        # Avoid re-capturing the leading segment of an IBAN we already have.
        if any(norm in k for k in found):
            continue
        if norm[4:6] not in ISO_COUNTRIES:
            continue
        found.setdefault(norm, BankIdentifier("swift", norm, country=norm[4:6]))

    for match in _BTC_RE.finditer(text):
        found.setdefault(match.group(1), BankIdentifier("crypto", match.group(1)))
    for match in _ETH_RE.finditer(text):
        norm = match.group(1).lower()
        found.setdefault(norm, BankIdentifier("crypto", norm))

    # Bare account/routing numbers only count with payment context nearby,
    # otherwise every order number and phone number becomes a false positive.
    if PAYMENT_CONTEXT.search(text):
        for match in _SORTCODE_RE.finditer(text):
            norm = _normalise(match.group(1))
            if len(norm) == 6:
                found.setdefault(norm, BankIdentifier("sortcode", norm))
        for match in _ACH_RE.finditer(text):
            found.setdefault(match.group(1), BankIdentifier("ach", match.group(1)))
        for match in _ACCOUNT_RE.finditer(text):
            norm = match.group(1)
            if norm not in found and len(norm) >= 10:
                found.setdefault(norm, BankIdentifier("account", norm))

    return list(found.values())


def has_payment_context(text: str) -> bool:
    return bool(text) and bool(PAYMENT_CONTEXT.search(text))


def urgency_score(text: str) -> int:
    """0..3. A14."""
    return min(3, len(URGENCY.findall(text or "")))
