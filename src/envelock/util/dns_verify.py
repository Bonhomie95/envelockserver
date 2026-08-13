"""Domain-control verification via DNS (PRD signup funnel).

A tenant must prove they control a domain before we connect a mailbox on it —
otherwise anyone could sign up with someone else's company address and start
receiving that company's fraud alerts (or map their coverage). Two proofs, both
standard:

* **TXT** — add `_envelock.<domain>  TXT  "envelock-verify=<token>"`.
* **CNAME** — point `_envelock.<domain>  CNAME  <token>.verify.envelock.io`.

The check is a live DNS resolution; nothing here trusts anything the client sends.
"""

from __future__ import annotations

import logging

from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.dnsverify")

_TXT_PREFIX = "envelock-verify="
_VERIFY_HOST = "verify.envelock.io"


def txt_record_value(token: str) -> str:
    return f"{_TXT_PREFIX}{token}"


def challenge_host(domain: str) -> str:
    return f"_envelock.{registrable_domain(domain) or domain}"


def cname_target(token: str) -> str:
    return f"{token}.{_VERIFY_HOST}"


def _resolve(host: str, rdtype: str) -> list[str]:
    """Resolve a DNS record. Returns [] on any failure (NXDOMAIN, timeout, no
    resolver) rather than raising — an unverifiable domain is simply not verified."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0
        answers = resolver.resolve(host, rdtype)
        out: list[str] = []
        for rdata in answers:
            if rdtype == "TXT":
                # TXT rdata is one or more quoted chunks; join them.
                out.append(b"".join(rdata.strings).decode("utf-8", "ignore"))
            elif hasattr(rdata, "target"):
                out.append(str(rdata.target).rstrip("."))
            else:
                out.append(str(rdata))
        return out
    except Exception as exc:  # noqa: BLE001
        logger.debug("dns resolve %s/%s failed: %s", host, rdtype, exc)
        return []


def verify_txt(domain: str, token: str) -> bool:
    want = txt_record_value(token)
    host = challenge_host(domain)
    return any(want == v.strip().strip('"') for v in _resolve(host, "TXT"))


def verify_cname(domain: str, token: str) -> bool:
    want = cname_target(token).lower()
    host = challenge_host(domain)
    return any(v.lower().rstrip(".") == want for v in _resolve(host, "CNAME"))


def verify(domain: str, token: str, *, method: str = "txt") -> bool:
    """Confirm the tenant controls `domain`. Accepts either proof regardless of the
    stated method, so a customer who added the wrong record type still passes."""
    if not token:
        return False
    return verify_txt(domain, token) or verify_cname(domain, token)


__all__ = [
    "challenge_host",
    "cname_target",
    "txt_record_value",
    "verify",
    "verify_cname",
    "verify_txt",
]
