"""Try IMAP settings until one works, and say precisely why the rest didn't.

`imap_discovery` produces a ladder of candidate settings; this module walks it.
Two rules make the ladder behave the way a person expects:

* A **transport** failure (wrong host, blocked port, TLS mismatch) means "this
  candidate is wrong" → try the next one.
* An **authentication** failure means "this candidate is *right* and the
  credential is wrong" → stop immediately and report that, because trying five
  more hosts with a password the server already refused only risks tripping the
  provider's lockout.

Two authentication mechanisms are supported, which is the other half of "IMAP
won't connect": `LOGIN` with a password, and `XOAUTH2` with an OAuth access
token. Microsoft has switched password authentication off for IMAP entirely, so
for those mailboxes XOAUTH2 is not an optimisation, it is the only way in.

Everything is blocking (stdlib `imaplib`); callers use `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import imaplib
import ipaddress
import logging
import socket
from dataclasses import dataclass, field

from envelock.channels.mail.imap_discovery import ALLOWED_PORTS, Candidate, discover_safely
from envelock.channels.mail.imap_errors import (
    ImapErrorCode,
    ImapFailure,
    classify_connect_failure,
    classify_login_failure,
)

logger = logging.getLogger("envelock.imap.probe")

#: Per-candidate connect+login budget. Short, because we may try several: a
#: whole ladder must still fit inside a request the customer is waiting on.
DEFAULT_CANDIDATE_TIMEOUT = 8.0

#: Ceiling on how many candidates one probe will dial, so a hostile or badly
#: configured domain cannot turn a single request into a port scan.
MAX_CANDIDATES = 8


# ── SSRF guard ───────────────────────────────────────────────────────────────
def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "loopback"
    # Link-local before private: 169.254.0.0/16 satisfies both, and naming the
    # cloud metadata range explicitly is what makes the refusal legible.
    if ip.is_link_local:
        return "a link-local address (the cloud metadata range)"
    if ip.is_private:
        return "a private network"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "a reserved range"
    return None


def check_host_allowed(host: str, port: int) -> ImapFailure | None:
    """Refuse to dial our own infrastructure on a customer's say-so.

    The host and port come straight from a form, so without this the connect
    test is a blind port scanner pointed at whatever is reachable from the API —
    including 169.254.169.254, the cloud metadata service. Returns `None` when
    the target is fine, or the failure to report.
    """
    from envelock.config import get_settings

    settings = get_settings()
    if settings.imap_allow_private_hosts:
        # The operator has explicitly opted into internal targets (self-hosted
        # mail on the LAN, or the test suite's loopback server), which also means
        # non-standard ports are theirs to choose.
        return None

    allowed = ALLOWED_PORTS | settings.imap_extra_port_set
    if port not in allowed:
        return ImapFailure(
            ImapErrorCode.BLOCKED_HOST,
            f"Port {port} is not an IMAP port.",
            "IMAP servers listen on 993 (SSL/TLS) or 143 (STARTTLS). If yours "
            "really is on another port, ask us to allow it.",
        )

    host = (host or "").strip().rstrip(".")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return classify_connect_failure(exc, host=host, port=port, security="ssl")

    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            continue
        reason = _blocked(ip)
        if reason is not None:
            return ImapFailure(
                ImapErrorCode.BLOCKED_HOST,
                f"“{host}” resolves to {reason}, which we will not connect to.",
                "Use the mail server's public hostname. If this really is an "
                "internal mail server, it has to be reachable publicly (or "
                "forward a copy of your mail to us instead).",
            )
    return None


# ── One attempt ──────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class Attempt:
    candidate: Candidate
    username: str
    ok: bool
    failure: ImapFailure | None = None

    def as_dict(self) -> dict:
        out = self.candidate.as_dict() | {"username": self.username, "ok": self.ok}
        if self.failure is not None:
            out["error"] = self.failure.as_dict()
        return out


@dataclass(slots=True)
class ProbeResult:
    ok: bool
    candidate: Candidate | None = None
    username: str | None = None
    failure: ImapFailure | None = None
    attempts: list[Attempt] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "settings": self.candidate.as_dict() if self.candidate else None,
            "username": self.username,
            "error": self.failure.as_dict() if self.failure else None,
            "attempts": [a.as_dict() for a in self.attempts],
        }


def xoauth2_string(username: str, access_token: str) -> str:
    """The SASL XOAUTH2 initial response, base64-encoded (Google/Microsoft)."""
    raw = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode()).decode()


def _connect(candidate: Candidate, timeout: float) -> imaplib.IMAP4:
    if candidate.security == "ssl":
        return imaplib.IMAP4_SSL(candidate.host, candidate.port, timeout=timeout)
    client = imaplib.IMAP4(candidate.host, candidate.port, timeout=timeout)
    if candidate.security == "starttls":
        # NOT best-effort. Silently continuing in plaintext when STARTTLS fails
        # would put the mailbox password on the wire in the clear — exactly the
        # failure a security product must never have.
        client.starttls()
    return client


def try_login(
    candidate: Candidate,
    *,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    timeout: float = DEFAULT_CANDIDATE_TIMEOUT,
) -> Attempt:
    """One connect + authenticate, reported rather than raised.

    Supply either `password` (IMAP LOGIN) or `access_token` (SASL XOAUTH2).
    """
    blocked = check_host_allowed(candidate.host, candidate.port)
    if blocked is not None:
        return Attempt(candidate, username, ok=False, failure=blocked)

    client: imaplib.IMAP4 | None = None
    try:
        client = _connect(candidate, timeout)
    except Exception as exc:  # noqa: BLE001 — every transport failure is a candidate miss
        return Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_connect_failure(
                exc, host=candidate.host, port=candidate.port, security=candidate.security
            ),
        )

    try:
        if access_token is not None:
            typ, data = client.authenticate(
                "XOAUTH2", lambda _: xoauth2_string(username, access_token).encode()
            )
        else:
            typ, data = client.login(username, password or "")
        if typ != "OK":
            return Attempt(
                candidate,
                username,
                ok=False,
                failure=classify_login_failure(_text(data), host=candidate.host),
            )
        return Attempt(candidate, username, ok=True)
    except imaplib.IMAP4.abort as exc:
        # The server hung up mid-exchange: not a credential verdict.
        return Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_connect_failure(
                exc, host=candidate.host, port=candidate.port, security=candidate.security
            ),
        )
    except imaplib.IMAP4.error as exc:
        return Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_login_failure(str(exc), host=candidate.host),
        )
    except Exception as exc:  # noqa: BLE001
        return Attempt(
            candidate,
            username,
            ok=False,
            failure=classify_connect_failure(
                exc, host=candidate.host, port=candidate.port, security=candidate.security
            ),
        )
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def _text(data) -> str:  # noqa: ANN001 — imaplib hands back list[bytes] | bytes | None
    if isinstance(data, list | tuple):
        return " ".join(_text(d) for d in data)
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data or "")


def _usernames(email: str, explicit: str | None) -> list[str]:
    """Username shapes to try. Some hosts want the full address, some the local
    part; getting this wrong looks identical to a wrong password."""
    if explicit:
        return [explicit.strip()]
    out = [email.strip()]
    if "@" in email:
        local = email.split("@", 1)[0].strip()
        if local and local not in out:
            out.append(local)
    return out


def probe_sync(
    candidates: list[Candidate],
    *,
    email: str,
    username: str | None = None,
    password: str | None = None,
    access_token: str | None = None,
    timeout: float = DEFAULT_CANDIDATE_TIMEOUT,
    max_candidates: int = MAX_CANDIDATES,
) -> ProbeResult:
    """Walk the ladder. Stops on the first success, or on the first *terminal*
    failure (one where the server has spoken and more hosts cannot help)."""
    attempts: list[Attempt] = []
    first_failure: ImapFailure | None = None
    names = _usernames(email, username)

    for candidate in candidates[:max_candidates]:
        for index, name in enumerate(names):
            attempt = try_login(
                candidate,
                username=name,
                password=password,
                access_token=access_token,
                timeout=timeout,
            )
            attempts.append(attempt)
            if attempt.ok:
                return ProbeResult(True, candidate, name, None, attempts)
            failure = attempt.failure
            if failure is None:
                continue
            if first_failure is None or failure.terminal:
                first_failure = failure
            if failure.terminal:
                # An auth verdict on the *first* username shape is worth one
                # retry with the alternative shape; after that, believe it.
                if failure.code is ImapErrorCode.AUTH_FAILED and index + 1 < len(names):
                    continue
                return ProbeResult(False, candidate, name, failure, attempts)
            break  # transport failure → this host is wrong, next candidate

    return ProbeResult(
        False,
        None,
        None,
        first_failure
        or ImapFailure(
            ImapErrorCode.DNS_NOT_FOUND,
            "We could not find an IMAP server for this address.",
            "Ask your mail provider for their IMAP server name and port, then "
            "enter them manually.",
        ),
        attempts,
    )


async def probe(
    *,
    email: str,
    password: str | None = None,
    access_token: str | None = None,
    username: str | None = None,
    preferred: Candidate | None = None,
    timeout: float = DEFAULT_CANDIDATE_TIMEOUT,  # noqa: ASYNC109 — per-candidate socket budget, not a task deadline
    max_candidates: int = MAX_CANDIDATES,
) -> ProbeResult:
    """Try the settings we were given, then discovered alternatives.

    Deliberately lazy: when the customer's own settings work — the common case —
    we never run discovery at all, so the happy path costs one connection rather
    than a fan-out of DNS and HTTP lookups.
    """

    async def run(candidates: list[Candidate], budget: int) -> ProbeResult:
        return await asyncio.to_thread(
            probe_sync,
            candidates,
            email=email,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            max_candidates=budget,
        )

    attempts: list[Attempt] = []
    if preferred is not None:
        first = await run([preferred], 1)
        attempts.extend(first.attempts)
        if first.ok or (first.failure is not None and first.failure.terminal):
            first.attempts = attempts
            return first

    candidates = [
        c
        for c in await discover_safely(email)
        if preferred is None or c.key != preferred.key
    ]
    if not candidates:
        return ProbeResult(
            False,
            None,
            None,
            (attempts[-1].failure if attempts else None)
            or ImapFailure(
                ImapErrorCode.DNS_NOT_FOUND,
                "We could not work out the IMAP server for this address.",
                "Enter the server name and port from your mail provider.",
            ),
            attempts,
        )

    result = await run(candidates, max_candidates)
    result.attempts = attempts + result.attempts
    return result


__all__ = [
    "Attempt",
    "ProbeResult",
    "check_host_allowed",
    "probe",
    "probe_sync",
    "try_login",
    "xoauth2_string",
]
