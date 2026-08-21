"""Work out a mailbox's IMAP settings instead of asking the customer to.

Typing a hostname, a port and a TLS mode correctly is the step people get wrong,
and a wrong guess is indistinguishable from a wrong password once the connection
fails. So we discover the settings the way a mail client does, in confidence
order, and hand the caller a ladder of candidates to try:

1. **RFC 6186 SRV records** — `_imaps._tcp.<domain>` / `_imap._tcp.<domain>`.
   Authoritative when present: the domain owner published them for exactly this.
2. **Autoconfig (Thunderbird/ISPDB)** — the provider-maintained XML at
   `autoconfig.<domain>`, `<domain>/.well-known/autoconfig/…` and Mozilla's
   central database. Covers most consumer and hosted providers.
3. **Autodiscover (Microsoft)** — for Exchange/on-prem estates.
4. **Our own provider registry**, matched from MX records.
5. **Conventional host names** — `imap.<domain>`, `mail.<domain>`, the MX host
   itself — on both 993/SSL and 143/STARTTLS.

Everything is best-effort: any step that fails is skipped, and the conventional
names always remain as a floor, so discovery degrades to today's behaviour
rather than erroring.

Nothing here connects to a mail server — `imap_probe` does that. Keeping
discovery pure (DNS/HTTP in, candidate list out) makes the ordering testable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass
from xml.etree import ElementTree

logger = logging.getLogger("envelock.imap.discovery")

#: Ports we will ever dial. Anything else is a typo or an SSRF probe.
ALLOWED_PORTS = frozenset({143, 993, 1143, 2143, 8993})

_SECURITY_BY_PORT = {993: "ssl", 143: "starttls", 1143: "starttls", 2143: "starttls"}


@dataclass(frozen=True, slots=True)
class Candidate:
    """One (host, port, security) worth trying, plus where it came from."""

    host: str
    port: int
    security: str
    source: str
    #: Higher wins. Used only for ordering, never shown to the customer.
    confidence: int = 0

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.host.lower(), self.port, self.security)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "security": self.security,
            "source": self.source,
        }


def _valid_host(host: str) -> bool:
    host = (host or "").strip().rstrip(".")
    if not host or len(host) > 253 or " " in host:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", host))


def _add(out: list[Candidate], seen: set, cand: Candidate) -> None:
    if not _valid_host(cand.host) or cand.port not in ALLOWED_PORTS:
        return
    if cand.security not in {"ssl", "starttls", "none"}:
        return
    if cand.key in seen:
        return
    seen.add(cand.key)
    out.append(cand)


# ── 1. RFC 6186 SRV ──────────────────────────────────────────────────────────
async def _srv(domain: str) -> list[Candidate]:
    try:
        import dns.asyncresolver
    except ImportError:  # pragma: no cover — dnspython is a hard dep in practice
        return []

    found: list[Candidate] = []
    seen: set = set()
    for service, security, confidence in (
        ("_imaps._tcp", "ssl", 100),
        ("_imap._tcp", "starttls", 90),
    ):
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 4.0
            answer = await resolver.resolve(f"{service}.{domain}", "SRV")
        except Exception as exc:  # noqa: BLE001 — absent SRV is the normal case
            logger.debug("srv lookup %s.%s failed: %s", service, domain, exc)
            continue
        for record in sorted(answer, key=lambda r: (r.priority, -r.weight)):
            host = str(record.target).rstrip(".")
            # RFC 6186: target "." means the service is explicitly not offered.
            if host in ("", "."):
                continue
            _add(found, seen, Candidate(host, int(record.port), security, "dns-srv", confidence))
    return found


# ── 2. Autoconfig (Mozilla ISPDB + provider-hosted) ──────────────────────────
_AUTOCONFIG_URLS = (
    "https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}",
    "https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={email}",
    "https://autoconfig.thunderbird.net/v1.1/{domain}",
)


def parse_autoconfig(xml_text: str) -> list[Candidate]:
    """Extract IMAP servers from a Thunderbird autoconfig document.

    Split out from the fetch so the (fiddly) XML shape is unit-testable.
    """
    out: list[Candidate] = []
    seen: set = set()
    try:
        root = ElementTree.fromstring(xml_text)  # noqa: S314 — provider XML, no entities used
    except ElementTree.ParseError:
        return []
    for server in root.iter("incomingServer"):
        if (server.get("type") or "").lower() != "imap":
            continue
        host = (server.findtext("hostname") or "").strip()
        port_text = (server.findtext("port") or "").strip()
        socket_type = (server.findtext("socketType") or "").strip().upper()
        try:
            port = int(port_text)
        except ValueError:
            port = 993 if socket_type == "SSL" else 143
        security = {"SSL": "ssl", "STARTTLS": "starttls", "PLAIN": "none"}.get(
            socket_type, _SECURITY_BY_PORT.get(port, "ssl")
        )
        _add(out, seen, Candidate(host, port, security, "autoconfig", 80))
    return out


async def _autoconfig(domain: str, email: str) -> list[Candidate]:
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return []

    found: list[Candidate] = []
    seen: set = set()
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
        for template in _AUTOCONFIG_URLS:
            url = template.format(domain=domain, email=email)
            try:
                response = await client.get(url)
            except Exception as exc:  # noqa: BLE001 — most domains publish nothing
                logger.debug("autoconfig %s failed: %s", url, exc)
                continue
            if response.status_code != 200 or "xml" not in (
                response.headers.get("content-type", "") + response.text[:100]
            ):
                continue
            for candidate in parse_autoconfig(response.text):
                _add(found, seen, candidate)
            if found:
                break
    return found


# ── 3. Microsoft Autodiscover (Exchange / on-prem) ───────────────────────────
async def _autodiscover(domain: str) -> list[Candidate]:
    """Only the cheap DNS half: an `autodiscover.<domain>` CNAME pointing at
    Microsoft tells us this estate is Exchange Online, whose IMAP host is fixed.
    The full SOAP POST needs the password, which discovery deliberately never
    holds."""
    try:
        import dns.asyncresolver
    except ImportError:  # pragma: no cover
        return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        answer = await resolver.resolve(f"autodiscover.{domain}", "CNAME")
    except Exception:  # noqa: BLE001
        return []
    target = " ".join(str(r.target).rstrip(".").lower() for r in answer)
    if "outlook.com" in target or "microsoft" in target:
        return [Candidate("outlook.office365.com", 993, "ssl", "autodiscover", 70)]
    return []


# ── 4/5. MX + provider registry + conventional names ─────────────────────────
async def _mx_hosts(domain: str) -> list[str]:
    try:
        import dns.asyncresolver
    except ImportError:  # pragma: no cover
        return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        answer = await resolver.resolve(domain, "MX")
    except Exception:  # noqa: BLE001
        return []
    records = sorted(answer, key=lambda r: r.preference)
    return [str(r.exchange).rstrip(".").lower() for r in records]


def conventional_candidates(domain: str, mx_hosts: list[str]) -> list[Candidate]:
    """The floor: names virtually every small host uses, both TLS modes."""
    from envelock.connect.advisor import identify, imap_host_guess

    out: list[Candidate] = []
    seen: set = set()

    provider = identify(list(mx_hosts))
    if provider.imap_host:
        _add(out, seen, Candidate(provider.imap_host, provider.imap_port, "ssl", "provider", 60))

    guess = imap_host_guess(provider, domain, list(mx_hosts))
    if guess:
        _add(out, seen, Candidate(guess, 993, "ssl", "provider-guess", 50))

    for name in (f"imap.{domain}", f"mail.{domain}", f"imap.mail.{domain}", f"secure.{domain}"):
        _add(out, seen, Candidate(name, 993, "ssl", "convention", 40))

    # The MX host itself is often the mail server for small/cPanel hosting.
    for host in mx_hosts[:2]:
        _add(out, seen, Candidate(host, 993, "ssl", "mx", 30))
        # `mx1.acme.com` → `mail.acme.com` is the other common shape.
        if host.startswith(("mx.", "mx1.", "mx01.")):
            _add(out, seen, Candidate(re.sub(r"^mx0?1?\.", "mail.", host), 993, "ssl", "mx", 30))

    # STARTTLS on 143 for everything we listed on 993 — the mismatch between
    # these two is the most common misconfiguration we see.
    for candidate in list(out):
        _add(
            out,
            seen,
            Candidate(candidate.host, 143, "starttls", candidate.source, candidate.confidence - 25),
        )
    return out


# ── Public entry point ───────────────────────────────────────────────────────
async def discover(email: str, *, preferred: Candidate | None = None) -> list[Candidate]:
    """Every setting worth trying for `email`, best-first.

    `preferred` (what the customer typed, if anything) always goes first — we
    never silently ignore an explicit choice, we just have somewhere to fall back
    to when it does not work.
    """
    domain = (email.rsplit("@", 1)[-1] if "@" in email else email).strip().lower()
    if not _valid_host(domain):
        return list(filter(None, [preferred]))

    srv, autoconfig, autodiscover, mx = await asyncio.gather(
        _srv(domain),
        _autoconfig(domain, email),
        _autodiscover(domain),
        _mx_hosts(domain),
        return_exceptions=True,
    )

    def ok(value) -> list:  # noqa: ANN001 — gather may hand back an exception
        return value if isinstance(value, list) else []

    out: list[Candidate] = []
    seen: set = set()
    if preferred is not None:
        _add(out, seen, preferred)
    for group in (ok(srv), ok(autoconfig), ok(autodiscover)):
        for candidate in group:
            _add(out, seen, candidate)
    for candidate in conventional_candidates(domain, ok(mx)):
        _add(out, seen, candidate)

    # Stable ordering: explicit choice, then confidence, then discovery order.
    head = out[:1] if preferred is not None else []
    tail = sorted(out[len(head):], key=lambda c: -c.confidence)
    return head + tail


async def discover_safely(email: str, *, preferred: Candidate | None = None) -> list[Candidate]:
    """`discover` that never raises — used on request paths."""
    with contextlib.suppress(Exception):
        return await discover(email, preferred=preferred)
    return list(filter(None, [preferred]))


__all__ = [
    "ALLOWED_PORTS",
    "Candidate",
    "conventional_candidates",
    "discover",
    "discover_safely",
    "parse_autoconfig",
]
