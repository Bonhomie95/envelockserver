"""Group B — content safety, plus the remaining Group A behavioural detections.

The attachment cascade (B4–B6) is free-first: hash cache → static triage →
reputation → detonation. Only the fall-through reaches a metered provider
(PRD §12.12A).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier, MailDirection
from envelock.detections.base import DetectionContext, FindingResult, register
from envelock.util.domains import registrable_domain
from envelock.util.payments import extract_bank_identifiers, has_payment_context

_INBOUND = frozenset({Capability.READ_INBOUND})
_HISTORY = frozenset({Capability.READ_INBOUND, Capability.READ_HISTORY})
_OUTBOUND = frozenset({Capability.READ_INBOUND, Capability.READ_OUTBOUND})


def _body(ctx: DetectionContext) -> str:
    mail = ctx.mail
    if mail is None:
        return ""
    parts = [mail.subject, mail.body_text, mail.body_html]
    return " ".join(filter(None, parts))


def _external(ctx: DetectionContext) -> bool:
    mail = ctx.mail
    return (
        mail is not None
        and mail.direction is MailDirection.INBOUND
        and registrable_domain(mail.sender.domain) not in ctx.owned_domains
    )


# ─────────────────────────────────────────────────────────────────────────────
# Group A — remaining behavioural detections
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class _A2BankRegistry:
    """Vendor bank registry: flags a counterparty with no verified callback
    number, because A1's guidance is worthless without one."""

    service: str = "A2"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        cp = ctx.counterparty
        if cp is None or not _external(ctx):
            return []
        if not has_payment_context(_body(ctx)) or not extract_bank_identifiers(_body(ctx)):
            return []
        if cp.verified_phone:
            return []
        return [
            FindingResult(
                service="A2",
                tier=AlertTier.MEDIUM,
                score=35,
                summary=(
                    f"No verified phone number on file for {cp.registrable_domain}. "
                    f"Add one so payment changes can be checked out of band."
                ),
                evidence={
                    "counterparty": cp.registrable_domain,
                    "has_bank_records": bool(cp.known_bank_ids),
                },
            )
        ]


@dataclass(frozen=True)
class _A4Homoglyph:
    """Split out from A3 so coverage reporting can name it individually."""

    service: str = "A4"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        from envelock.util.domains import skeleton

        mail = ctx.mail
        if mail is None or not _external(ctx):
            return []
        sender = registrable_domain(mail.sender.domain)
        comparison = set(ctx.owned_domains) | set(ctx.known_counterparties)
        comparison.discard(sender)

        for protected in comparison:
            if sender != protected and skeleton(sender) == skeleton(protected):
                return [
                    FindingResult(
                        service="A4",
                        tier=AlertTier.HIGH,
                        score=90,
                        summary=(
                            f"{sender} renders identically to {protected} — "
                            f"character substitution."
                        ),
                        evidence={
                            "sender_domain": sender,
                            "resembles": protected,
                            "skeleton": skeleton(sender),
                        },
                    )
                ]
        return []


@dataclass(frozen=True)
class _A5DisplayNameSpoof:
    service: str = "A5"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx) or not mail.sender.display:
            return []
        display = mail.sender.display.strip().lower()
        sender = registrable_domain(mail.sender.domain)
        comparison = set(ctx.owned_domains) | set(ctx.known_counterparties)

        for known in comparison:
            brand = known.partition(".")[0]
            if len(brand) >= 4 and brand in display and sender != known:
                from envelock.util.domains import is_free_mail

                free = is_free_mail(sender)
                return [
                    FindingResult(
                        service="A5",
                        tier=AlertTier.HIGH if free else AlertTier.MEDIUM,
                        score=70,
                        summary=(
                            f'Display name "{mail.sender.display}" claims {known} '
                            f"but the message came from {sender}."
                        ),
                        evidence={
                            "display_name": mail.sender.display,
                            "claims": known,
                            "actual_domain": sender,
                            "free_mail": free,
                        },
                    )
                ]
        return []


@dataclass(frozen=True)
class _A9Stylometry:
    """Writing-style drift against a per-sender baseline."""

    service: str = "A9"
    requires: frozenset[Capability] = _HISTORY

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail, cp = ctx.mail, ctx.counterparty
        if mail is None or cp is None or not _external(ctx):
            return []
        baseline = ctx.sender_baseline
        if not baseline or cp.message_count < 10:
            return []

        current = style_features(mail.body_text or "")
        if not current:
            return []

        drift = style_distance(baseline, current)
        if drift < 0.45:
            return []

        payment = has_payment_context(_body(ctx))
        return [
            FindingResult(
                service="A9",
                tier=AlertTier.HIGH if payment else AlertTier.MEDIUM,
                score=int(min(95, drift * 100)),
                summary=(
                    f"Writing style from {cp.registrable_domain} differs markedly "
                    f"from their {cp.message_count} previous messages."
                ),
                evidence={
                    "counterparty": cp.registrable_domain,
                    "drift": round(drift, 3),
                    "baseline_samples": cp.message_count,
                    "payment_context": payment,
                },
            )
        ]


@dataclass(frozen=True)
class _A11Dormancy:
    service: str = "A11"
    requires: frozenset[Capability] = _INBOUND

    DORMANT_DAYS = 90

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail, cp = ctx.mail, ctx.counterparty
        if mail is None or cp is None or not _external(ctx):
            return []
        if cp.last_seen_at is None or not mail.in_reply_to:
            return []

        now = ctx.now or datetime.now(UTC)
        gap = now - cp.last_seen_at
        if gap < timedelta(days=self.DORMANT_DAYS):
            return []
        if not has_payment_context(_body(ctx)):
            return []

        return [
            FindingResult(
                service="A11",
                tier=AlertTier.HIGH,
                score=75,
                summary=(
                    f"A thread dormant for {gap.days} days was revived with a "
                    f"payment request."
                ),
                evidence={"counterparty": cp.registrable_domain, "dormant_days": gap.days},
            )
        ]


@dataclass(frozen=True)
class _A12StallDetection:
    """Counterparty silence past their own baseline during a payment thread."""

    service: str = "A12"
    requires: frozenset[Capability] = _OUTBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail, cp = ctx.mail, ctx.counterparty
        if mail is None or cp is None:
            return []
        # Fires on our own outbound message awaiting a reply.
        if mail.direction is not MailDirection.OUTBOUND:
            return []
        if not cp.median_reply_seconds or not has_payment_context(_body(ctx)):
            return []

        now = ctx.now or datetime.now(UTC)
        waiting = (now - mail.occurred_at).total_seconds()
        threshold = cp.median_reply_seconds * 3
        if waiting < threshold:
            return []

        return [
            FindingResult(
                service="A12",
                tier=AlertTier.MEDIUM,
                score=45,
                summary=(
                    f"{cp.registrable_domain} has not replied in "
                    f"{int(waiting / 3600)}h — well past their usual "
                    f"{int(cp.median_reply_seconds / 3600)}h. Verify by phone."
                ),
                evidence={
                    "counterparty": cp.registrable_domain,
                    "waiting_seconds": int(waiting),
                    "usual_seconds": cp.median_reply_seconds,
                    "callback_phone": cp.verified_phone,
                },
            )
        ]


_INVOICE_RE = re.compile(r"\b(?:invoice|inv|bill)\s*#?\s*([A-Z0-9][A-Z0-9\-/]{2,20})\b", re.I)
_AMOUNT_RE = re.compile(
    r"(?:USD|EUR|GBP|NGN|TWD|SGD|CNY|\$|€|£|₦)\s?([\d,]+(?:\.\d{2})?)", re.I
)


@dataclass(frozen=True)
class _A13InvoiceAnomaly:
    """Catches fraud with no domain or identity signal at all."""

    service: str = "A13"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail, cp = ctx.mail, ctx.counterparty
        if mail is None or cp is None or not _external(ctx):
            return []
        text = _body(ctx)
        invoices = {m.group(1).upper() for m in _INVOICE_RE.finditer(text)}
        if not invoices:
            return []

        findings: list[FindingResult] = []
        duplicate = invoices & cp.seen_invoice_numbers
        if duplicate:
            findings.append(
                FindingResult(
                    service="A13",
                    tier=AlertTier.HIGH,
                    score=70,
                    summary=f"Invoice {', '.join(sorted(duplicate))} has been billed before.",
                    evidence={"duplicate_invoices": sorted(duplicate)},
                )
            )

        amounts = [
            float(m.group(1).replace(",", "")) for m in _AMOUNT_RE.finditer(text)
        ]
        if amounts and cp.typical_amount:
            largest = max(amounts)
            if largest > cp.typical_amount * 5:
                findings.append(
                    FindingResult(
                        service="A13",
                        tier=AlertTier.MEDIUM,
                        score=50,
                        summary=(
                            f"Amount {largest:,.2f} is far above the usual "
                            f"{cp.typical_amount:,.2f} for this vendor."
                        ),
                        evidence={"amount": largest, "typical": cp.typical_amount},
                    )
                )
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Group B — content safety
# ─────────────────────────────────────────────────────────────────────────────
_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
     "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
)

_BRAND_BAIT = re.compile(
    r"\b(microsoft|office\s?365|outlook|onedrive|sharepoint|docusign|dropbox|"
    r"paypal|netflix|apple\s?id|amazon|linkedin|whatsapp)\b",
    re.I,
)


@dataclass(frozen=True)
class _B1PhishingUrls:
    service: str = "B1"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx) or not mail.urls:
            return []

        sender = registrable_domain(mail.sender.domain)
        suspicious: list[dict] = []
        for url in mail.urls:
            host = _host_of(url)
            reg = registrable_domain(host)
            reasons = []
            if reg in _SHORTENERS:
                reasons.append("link shortener hides the destination")
            if reg in ctx.malicious_domains:
                reasons.append("on a threat feed")
            if _BRAND_BAIT.search(url) and reg != sender:
                reasons.append("brand name in a URL not owned by that brand")
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                reasons.append("bare IP address instead of a hostname")
            if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
                reasons.append("credentials embedded in the URL")
            if reasons:
                suspicious.append({"url": url[:200], "reasons": reasons})

        if not suspicious:
            return []
        feed_hit = any("threat feed" in r for s in suspicious for r in s["reasons"])
        return [
            FindingResult(
                service="B1",
                tier=AlertTier.HIGH if feed_hit else AlertTier.MEDIUM,
                score=80 if feed_hit else 45,
                summary=f"{len(suspicious)} suspicious link(s) in this message.",
                evidence={"urls": suspicious[:10]},
            )
        ]


def _host_of(url: str) -> str:
    without_scheme = url.split("//", 1)[-1]
    return without_scheme.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0].lower()


@dataclass(frozen=True)
class _B2TimeOfClick:
    """Links weaponised after delivery are the standard evasion, so rewriting
    requires the ability to modify the message."""

    service: str = "B2"
    requires: frozenset[Capability] = frozenset(
        {Capability.READ_INBOUND, Capability.MODIFY_MESSAGE}
    )

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx) or not mail.urls:
            return []
        return [
            FindingResult(
                service="B2",
                tier=AlertTier.LOW,
                score=5,
                summary=f"{len(mail.urls)} link(s) rewritten for re-checking at click time.",
                evidence={"rewritten": len(mail.urls)},
            )
        ]


@dataclass(frozen=True)
class _B3QrPhishing:
    """Rising fast and missed by most gateways."""

    service: str = "B3"
    requires: frozenset[Capability] = _INBOUND

    _IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image")

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx):
            return []
        images = [
            a
            for a in mail.attachments
            if (a.detected_mime or a.declared_mime or "").startswith(self._IMAGE_TYPES)
        ]
        if not images:
            return []
        # A QR code plus payment language is the quishing pattern; the decoded
        # target is checked by B1 once the worker resolves it.
        if not has_payment_context(_body(ctx)) and not _BRAND_BAIT.search(_body(ctx)):
            return []
        return [
            FindingResult(
                service="B3",
                tier=AlertTier.MEDIUM,
                score=45,
                summary=(
                    f"{len(images)} image attachment(s) alongside payment or "
                    f"sign-in language — queued for QR decoding."
                ),
                evidence={"images": [a.filename for a in images][:5]},
            )
        ]


_MACRO_EXT = (".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm")
_RISKY_EXT = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
              ".vbs", ".wsf", ".hta", ".lnk", ".iso", ".img", ".vhd", ".one")


@dataclass(frozen=True)
class _B4AttachmentMalware:
    service: str = "B4"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not mail.attachments:
            return []
        findings: list[FindingResult] = []
        for att in mail.attachments:
            verdict = ctx.attachment_verdicts.get(att.sha256)
            if verdict == "malicious":
                findings.append(
                    FindingResult(
                        service="B4",
                        tier=AlertTier.CRITICAL,
                        score=100,
                        summary=f"{att.filename} is known malware.",
                        evidence={"filename": att.filename, "sha256": att.sha256},
                    )
                )
            elif att.filename.lower().endswith(_RISKY_EXT):
                findings.append(
                    FindingResult(
                        service="B4",
                        tier=AlertTier.HIGH,
                        score=75,
                        summary=f"{att.filename} is an executable or script type.",
                        evidence={"filename": att.filename, "reason": "risky extension"},
                    )
                )
        return findings


@dataclass(frozen=True)
class _B5Archives:
    service: str = "B5"
    requires: frozenset[Capability] = _INBOUND

    _PASSWORD_HINT = re.compile(
        r"\b(password|passcode|pwd)\b[\s:is]*([A-Za-z0-9!@#$%^&*]{3,})", re.I
    )

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None:
            return []
        archives = [a for a in mail.attachments if a.is_archive]
        if not archives:
            return []

        findings: list[FindingResult] = []
        password_in_body = bool(self._PASSWORD_HINT.search(_body(ctx)))
        for arch in archives:
            if arch.is_encrypted or password_in_body:
                findings.append(
                    FindingResult(
                        service="B5",
                        tier=AlertTier.HIGH,
                        score=80,
                        summary=(
                            f"{arch.filename} is a password-protected archive with "
                            f"the password in the message — a standard way to evade "
                            f"scanning."
                        ),
                        evidence={"filename": arch.filename, "password_in_body": password_in_body},
                    )
                )
            elif arch.archive_depth > 2:
                findings.append(
                    FindingResult(
                        service="B5",
                        tier=AlertTier.MEDIUM,
                        score=50,
                        summary=f"{arch.filename} is nested {arch.archive_depth} levels deep.",
                        evidence={"filename": arch.filename, "depth": arch.archive_depth},
                    )
                )
        return findings


@dataclass(frozen=True)
class _B6ExtensionAbuse:
    """Macro documents, type mismatches, HTML smuggling."""

    service: str = "B6"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None:
            return []
        findings: list[FindingResult] = []
        for att in mail.attachments:
            name = att.filename.lower()
            if att.detected_mime and att.declared_mime:
                declared = att.declared_mime.split("/")[0]
                detected = att.detected_mime.split("/")[0]
                if detected == "application" and declared == "image":
                    findings.append(
                        FindingResult(
                            service="B6",
                            tier=AlertTier.HIGH,
                            score=80,
                            summary=(
                                f"{att.filename} claims to be an image but its "
                                f"contents are {att.detected_mime}."
                            ),
                            evidence={
                                "filename": att.filename,
                                "declared": att.declared_mime,
                                "detected": att.detected_mime,
                            },
                        )
                    )
            if name.endswith(_MACRO_EXT):
                findings.append(
                    FindingResult(
                        service="B6",
                        tier=AlertTier.MEDIUM,
                        score=45,
                        summary=f"{att.filename} is a macro-capable Office format.",
                        evidence={"filename": att.filename},
                    )
                )
            if name.endswith((".html", ".htm")) and att.size_bytes > 50_000:
                findings.append(
                    FindingResult(
                        service="B6",
                        tier=AlertTier.HIGH,
                        score=70,
                        summary=(
                            f"{att.filename} is a large HTML attachment — "
                            f"consistent with HTML smuggling."
                        ),
                        evidence={"filename": att.filename, "size": att.size_bytes},
                    )
                )
        return findings


@dataclass(frozen=True)
class _B7SenderReputation:
    service: str = "B7"
    requires: frozenset[Capability] = _INBOUND

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx):
            return []
        sender = registrable_domain(mail.sender.domain)
        if sender not in ctx.malicious_domains:
            return []
        return [
            FindingResult(
                service="B7",
                tier=AlertTier.HIGH,
                score=85,
                summary=f"{sender} appears on a threat-intelligence feed.",
                evidence={"sender_domain": sender},
            )
        ]


@dataclass(frozen=True)
class _B9NewSenderDomain:
    service: str = "B9"
    requires: frozenset[Capability] = _INBOUND

    NEW_DAYS = 30

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]:
        mail = ctx.mail
        if mail is None or not _external(ctx) or ctx.sender_domain_age_days is None:
            return []
        if ctx.sender_domain_age_days > self.NEW_DAYS:
            return []
        payment = has_payment_context(_body(ctx))
        return [
            FindingResult(
                service="B9",
                tier=AlertTier.HIGH if payment else AlertTier.MEDIUM,
                score=70 if payment else 40,
                summary=(
                    f"{registrable_domain(mail.sender.domain)} was registered "
                    f"{ctx.sender_domain_age_days} days ago."
                ),
                evidence={
                    "age_days": ctx.sender_domain_age_days,
                    "payment_context": payment,
                },
            )
        ]


# ── Stylometry helpers (A9) ──────────────────────────────────────────────────
_FUNCTION_WORDS = (
    "the", "and", "to", "of", "a", "in", "that", "is", "for", "please",
    "kindly", "regards", "thanks", "we", "our", "your",
)


def style_features(text: str) -> dict[str, float]:
    """Lightweight stylometry: no model, no inference cost, runs on every message."""
    words = re.findall(r"[A-Za-z']+", text.lower())
    if len(words) < 20:
        return {}
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    features = {
        "avg_word_len": sum(len(w) for w in words) / len(words),
        "avg_sentence_len": len(words) / max(len(sentences), 1),
        "exclamation_rate": text.count("!") / len(sentences or [1]),
        "uppercase_rate": sum(1 for c in text if c.isupper()) / max(len(text), 1),
    }
    for word in _FUNCTION_WORDS:
        features[f"fw_{word}"] = words.count(word) / len(words)
    return features


def style_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Normalised distance in 0..1 over shared features."""
    keys = set(a) & set(b)
    if not keys:
        return 0.0
    total = 0.0
    for k in keys:
        scale = max(abs(a[k]), abs(b[k]), 1e-6)
        total += min(abs(a[k] - b[k]) / scale, 1.0)
    return total / len(keys)


A2 = register(_A2BankRegistry())
A4 = register(_A4Homoglyph())
A5 = register(_A5DisplayNameSpoof())
A9 = register(_A9Stylometry())
A11 = register(_A11Dormancy())
A12 = register(_A12StallDetection())
A13 = register(_A13InvoiceAnomaly())
B1 = register(_B1PhishingUrls())
B2 = register(_B2TimeOfClick())
B3 = register(_B3QrPhishing())
B4 = register(_B4AttachmentMalware())
B5 = register(_B5Archives())
B6 = register(_B6ExtensionAbuse())
B7 = register(_B7SenderReputation())
B9 = register(_B9NewSenderDomain())
