"""Real IMAP fetch + quarantine (Tier 3).

This is the socket-level counterpart to the pure `ImapBroker` scheduler: the
broker decides *when* a mailbox is due, this module does the actual IMAP work —
select the inbox, pull the UIDs we have not seen, and (for Protected mailboxes)
move a flagged message out of the inbox.

Everything here is synchronous (``imapclient`` wraps the stdlib ``imaplib``,
which is blocking); callers run it with ``asyncio.to_thread`` so one slow server
never blocks the event loop. The IMAP client is injected via ``client_factory``
so the fetch/quarantine logic is unit-testable without a live server.

Credentials are only ever handed to this module in the broker/worker process,
decrypted immediately before the connection and never persisted in the clear
(PRD §5.2).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

#: Folder a Protected mailbox's flagged mail is moved into. Created on demand.
QUARANTINE_FOLDER = "Envelock Quarantine"

#: Never pull an unbounded backlog in one poll — protects memory and latency.
DEFAULT_LIMIT = 200

#: First-connect look-back when there is no cursor yet: we do not want to ingest
#: a decade of history, only recent mail. Backfill of older mail is a separate,
#: explicit action (PRD E11).
FIRST_SYNC_TAIL = 50


class ImapClientLike(Protocol):
    """The slice of ``imapclient.IMAPClient`` this module uses. Declared as a
    Protocol so tests can inject a fake with the same surface."""

    def login(self, username: str, password: str) -> Any: ...
    def oauth2_login(self, username: str, access_token: str) -> Any: ...
    def starttls(self) -> Any: ...
    def select_folder(self, folder: str, readonly: bool = False) -> dict: ...
    def search(self, criteria: Any) -> list[int]: ...
    def fetch(self, messages: Any, data: Any) -> dict: ...
    def folder_exists(self, folder: str) -> bool: ...
    def create_folder(self, folder: str) -> Any: ...
    def move(self, messages: Any, folder: str) -> Any: ...
    def copy(self, messages: Any, folder: str) -> Any: ...
    def delete_messages(self, messages: Any) -> Any: ...
    def expunge(self, messages: Any = None) -> Any: ...
    def capabilities(self) -> tuple: ...
    def logout(self) -> Any: ...


ClientFactory = Callable[..., ImapClientLike]


@dataclass(frozen=True, slots=True)
class FetchedMessage:
    uid: int
    raw: bytes


@dataclass(slots=True)
class FetchResult:
    messages: list[FetchedMessage] = field(default_factory=list)
    uidvalidity: int | None = None
    highest_uid: int | None = None
    ok: bool = True
    error: str | None = None
    #: True when the failure was the server rejecting the credentials (not a
    #: transient network/TLS error) — the caller uses this to prompt a reconnect
    #: rather than retrying a password the server will keep refusing.
    auth_failed: bool = False


class _AuthError(Exception):
    """Raised inside ``_open`` when the server rejects the login, so ``fetch_new``
    can distinguish a bad password from a transient connection failure."""


def _default_client_factory(
    *, host: str, port: int, security: str, timeout: float
) -> ImapClientLike:
    """Real ``imapclient.IMAPClient``. Imported lazily so the module (and the
    tests that inject a fake) do not require the dependency at import time."""
    from imapclient import IMAPClient

    ssl = security == "ssl"
    return IMAPClient(host, port=port, ssl=ssl, timeout=timeout, use_uid=True)


class _BlockedHostError(Exception):
    """The target resolves somewhere we refuse to dial (see imap_probe)."""


def _open(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    timeout: float,
    client_factory: ClientFactory | None,
) -> ImapClientLike:
    """Connect and authenticate. `password` uses IMAP LOGIN; `access_token` uses
    SASL XOAUTH2 — the only way in for providers that have switched password
    authentication off (Microsoft 365)."""
    if client_factory is None:
        # Only guard real connections; an injected factory is a test double.
        from envelock.channels.mail.imap_probe import check_host_allowed

        blocked = check_host_allowed(host, port)
        if blocked is not None:
            raise _BlockedHostError(blocked.message)

    factory = client_factory or _default_client_factory
    client = factory(host=host, port=port, security=security, timeout=timeout)
    if security == "starttls":
        # Deliberately NOT suppressed. Falling through to a plaintext session
        # would put the mailbox password on the wire in the clear.
        client.starttls()
    try:
        if access_token is not None:
            client.oauth2_login(username, access_token)
        else:
            client.login(username, password or "")
    except Exception as exc:  # noqa: BLE001
        # imapclient raises LoginError on a rejected credential; match by name so
        # we do not hard-depend on its exception class here.
        name = type(exc).__name__.lower()
        if "login" in name or "auth" in name:
            with contextlib.suppress(Exception):
                client.logout()
            raise _AuthError(str(exc)) from exc
        raise
    return client


def fetch_new(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    since_uid: int | None = None,
    uidvalidity: int | None,
    folder: str = "INBOX",
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    access_token: str | None = None,
) -> FetchResult:
    """Pull messages newer than ``since_uid`` from ``folder``.

    Returns every new message plus the server's current UIDVALIDITY and the
    highest UID seen (the caller persists both as the next cursor). Any socket,
    TLS, or auth failure comes back as ``ok=False`` with a reason rather than an
    exception, so one broken mailbox never aborts a whole poll cycle.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host,
            port=port,
            security=security,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            client_factory=client_factory,
        )
        info = client.select_folder(folder, readonly=False)
        server_uidvalidity = _as_int(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY"))

        # A UIDVALIDITY change invalidates every stored UID (RFC 3501): the server
        # has renumbered the folder, so our cursor is meaningless. Restart from the
        # recent tail rather than trusting a stale, now-ambiguous UID.
        cursor = since_uid
        if uidvalidity is not None and server_uidvalidity != uidvalidity:
            cursor = None

        if cursor is None:
            all_uids = sorted(_as_int_list(client.search(["ALL"])))
            wanted = all_uids[-FIRST_SYNC_TAIL:]
        else:
            # ``cursor:*`` always returns at least the highest message even when
            # none are strictly greater, so filter to strictly-new UIDs ourselves.
            candidates = sorted(_as_int_list(client.search(["UID", f"{cursor + 1}:*"])))
            wanted = [u for u in candidates if u > cursor]

        wanted = wanted[-limit:]
        if not wanted:
            highest = since_uid if cursor is not None else None
            return FetchResult(
                messages=[], uidvalidity=server_uidvalidity, highest_uid=highest, ok=True
            )

        raw_by_uid = client.fetch(wanted, ["RFC822"])
        messages: list[FetchedMessage] = []
        for uid in wanted:
            entry = raw_by_uid.get(uid) or {}
            raw = entry.get(b"RFC822") or entry.get("RFC822")
            if raw:
                messages.append(FetchedMessage(uid=int(uid), raw=bytes(raw)))

        highest_uid = max((m.uid for m in messages), default=since_uid)
        return FetchResult(
            messages=messages,
            uidvalidity=server_uidvalidity,
            highest_uid=highest_uid,
            ok=True,
        )
    except _AuthError as exc:
        return FetchResult(ok=False, error=f"login rejected: {exc}", auth_failed=True)
    except _BlockedHostError as exc:
        return FetchResult(ok=False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 — any failure is a poll failure, reported not raised
        return FetchResult(ok=False, error=_reason(exc))
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def fetch_since(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    since_date=None,  # noqa: ANN001 — datetime.date
    folder: str = "INBOX",
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
) -> FetchResult:
    """Pull messages received on or after ``since_date`` — onboarding backfill (E11).

    Distinct from ``fetch_new``: it searches by date rather than a UID cursor, so it
    can reach back over history the day a mailbox is connected. The caller runs each
    returned message through the pipeline to seed A9 stylometry and A12 baselines,
    then does NOT advance the live cursor from this (a subsequent poll owns that).
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host, port=port, security=security, username=username,
            password=password, access_token=access_token,
            timeout=timeout, client_factory=client_factory,
        )
        info = client.select_folder(folder, readonly=True)
        server_uidvalidity = _as_int(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY"))
        # IMAP SINCE takes a date; the server returns everything on/after it.
        criteria = ["SINCE", since_date.strftime("%d-%b-%Y")]
        wanted = sorted(_as_int_list(client.search(criteria)))[-limit:]
        if not wanted:
            return FetchResult(messages=[], uidvalidity=server_uidvalidity, ok=True)
        raw_by_uid = client.fetch(wanted, ["RFC822"])
        messages: list[FetchedMessage] = []
        for uid in wanted:
            entry = raw_by_uid.get(uid) or {}
            raw = entry.get(b"RFC822") or entry.get("RFC822")
            if raw:
                messages.append(FetchedMessage(uid=int(uid), raw=bytes(raw)))
        return FetchResult(messages=messages, uidvalidity=server_uidvalidity, ok=True)
    except _AuthError as exc:
        return FetchResult(ok=False, error=f"login rejected: {exc}", auth_failed=True)
    except Exception as exc:  # noqa: BLE001
        return FetchResult(ok=False, error=_reason(exc))
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def quarantine_message(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    uid: int = 0,
    folder: str = "INBOX",
    quarantine_folder: str = QUARANTINE_FOLDER,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
) -> bool:
    """Move a single message out of the inbox into the quarantine folder.

    Uses IMAP MOVE where the server advertises it, else COPY + delete + EXPUNGE —
    the fallback works on servers as old as 1998, which is the whole point of the
    Tier 3 path. Returns True only if the message actually left the inbox.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host,
            port=port,
            security=security,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            client_factory=client_factory,
        )
        client.select_folder(folder, readonly=False)
        if not client.folder_exists(quarantine_folder):
            with contextlib.suppress(Exception):
                client.create_folder(quarantine_folder)

        caps = ()
        with contextlib.suppress(Exception):
            caps = client.capabilities()
        has_move = any(_cap_eq(c, "MOVE") for c in caps)

        if has_move:
            client.move([uid], quarantine_folder)
        else:
            client.copy([uid], quarantine_folder)
            client.delete_messages([uid])
            client.expunge([uid])
        return True
    except Exception:  # noqa: BLE001 — quarantine failure is reported by the caller, never fatal
        return False
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


# ── helpers ───────────────────────────────────────────────────────────────────
def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_int_list(values: Any) -> list[int]:
    out: list[int] = []
    for v in values or []:
        iv = _as_int(v)
        if iv is not None:
            out.append(iv)
    return out


def _cap_eq(cap: Any, name: str) -> bool:
    if isinstance(cap, bytes):
        cap = cap.decode("ascii", "ignore")
    return str(cap).upper() == name


def _reason(exc: Exception) -> str:
    name = type(exc).__name__
    text = str(exc).strip()
    return f"{name}: {text}" if text else name


__all__ = [
    "QUARANTINE_FOLDER",
    "fetch_since",
    "FetchedMessage",
    "FetchResult",
    "fetch_new",
    "quarantine_message",
]
