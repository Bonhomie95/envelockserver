"""End-to-end over a real TCP socket: connect → fetch → detect → quarantine.

Every other IMAP test injects a fake client, which proves the logic but not the
wire. This one runs a minimal but genuine IMAP4rev1 server on a loopback port
and drives the real `imapclient`/`imaplib` code paths against it, so a protocol
mistake (a missing tag, a bad UID SEARCH, an untagged response we mis-parse)
fails here rather than at a customer's mail host.
"""

from __future__ import annotations

import os
import socket
import threading
from uuid import uuid4

import pytest

#: The tiny server's fixed credential. Not a secret — it never leaves this file.
SERVER_PW = "the-app-password"  # noqa: S105

MESSAGE = (
    b"From: \"Gemini Accounts\" <billing@gemini-invoices.net>\r\n"
    b"To: pay@socketco.example\r\n"
    b"Subject: URGENT: updated bank details for invoice 4471\r\n"
    b"Date: Mon, 1 Sep 2025 09:00:00 +0000\r\n"
    b"Message-ID: <inv-4471@gemini-invoices.net>\r\n"
    b"\r\n"
    b"Our bank has changed. Please remit to IBAN GB33BUKB20201555555555,\r\n"
    b"account 55555555, sort code 20-20-15. Same day please.\r\n"
)


class TinyImapServer(threading.Thread):
    """Just enough IMAP4rev1 for a poll: LOGIN, SELECT, UID SEARCH, UID FETCH,
    UID MOVE, LOGOUT. Records what the client asked for so the test can assert
    the quarantine actually happened on the wire."""

    daemon = True

    def __init__(self, *, password: str) -> None:
        super().__init__()
        self.password = password
        self.moved: list[int] = []
        self.created_folders: list[str] = []
        self.logins: list[tuple[str, str]] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        with_suppress = getattr(self._sock, "close", lambda: None)
        with_suppress()

    def run(self) -> None:  # noqa: C901 — a protocol dispatch table reads best flat
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:  # noqa: C901
        send = lambda line: conn.sendall(line.encode() + b"\r\n")  # noqa: E731
        send("* OK [CAPABILITY IMAP4rev1 MOVE] TinyIMAP ready")
        buffer = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                while b"\r\n" in buffer:
                    raw, buffer = buffer.split(b"\r\n", 1)
                    line = raw.decode("utf-8", "replace")
                    if not line:
                        continue
                    tag, _, rest = line.partition(" ")
                    command, _, args = rest.partition(" ")
                    command = command.upper()

                    if command == "CAPABILITY":
                        send("* CAPABILITY IMAP4rev1 MOVE")
                        send(f"{tag} OK CAPABILITY done")
                    elif command == "LOGIN":
                        user, _, pw = args.partition(" ")
                        user, pw = user.strip('"'), pw.strip('"')
                        self.logins.append((user, pw))
                        if pw == self.password:
                            send(f"{tag} OK LOGIN completed")
                        else:
                            send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")
                    elif command in ("SELECT", "EXAMINE"):
                        send("* 1 EXISTS")
                        send("* OK [UIDVALIDITY 42] UIDs valid")
                        send("* OK [UIDNEXT 1002] Predicted next UID")
                        send(f"{tag} OK [READ-WRITE] SELECT completed")
                    elif command == "UID" and args.upper().startswith("SEARCH"):
                        send("* SEARCH 1001")
                        send(f"{tag} OK UID SEARCH completed")
                    elif command == "UID" and args.upper().startswith("FETCH"):
                        send(f"* 1 FETCH (UID 1001 RFC822 {{{len(MESSAGE)}}}")
                        conn.sendall(MESSAGE + b")\r\n")
                        send(f"{tag} OK UID FETCH completed")
                    elif command == "LIST":
                        send('* LIST (\\HasNoChildren) "/" "INBOX"')
                        send(f"{tag} OK LIST completed")
                    elif command == "CREATE":
                        self.created_folders.append(args.strip('"'))
                        send(f"{tag} OK CREATE completed")
                    elif command == "UID" and args.upper().startswith("MOVE"):
                        parts = args.split()
                        self.moved.append(int(parts[1]))
                        send(f"{tag} OK UID MOVE completed")
                    elif command == "LOGOUT":
                        send("* BYE logging out")
                        send(f"{tag} OK LOGOUT completed")
                        return
                    elif command == "NOOP":
                        send(f"{tag} OK NOOP completed")
                    else:
                        send(f"{tag} OK {command} ignored")
        except OSError:
            return


@pytest.fixture
def imap_server() -> TinyImapServer:
    server = TinyImapServer(password=SERVER_PW)
    server.start()
    # Loopback is refused by the SSRF guard in normal operation; a self-hosted
    # deployment turns this on, and so does this test.
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "true"
    from envelock.config import get_settings

    get_settings.cache_clear()
    yield server
    server.stop()
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "false"
    get_settings.cache_clear()


def test_probe_signs_in_over_a_real_socket(imap_server: TinyImapServer) -> None:
    from envelock.channels.mail.imap_discovery import Candidate
    from envelock.channels.mail.imap_probe import probe_sync

    candidate = Candidate("127.0.0.1", imap_server.port, "none", "test", 10)
    result = probe_sync(
        [candidate], email="pay@socketco.example", password=SERVER_PW
    )
    assert result.ok, result.failure
    assert imap_server.logins[-1] == ("pay@socketco.example", "the-app-password")


def test_a_wrong_password_is_classified_from_the_real_server_response(
    imap_server: TinyImapServer,
) -> None:
    from envelock.channels.mail.imap_discovery import Candidate
    from envelock.channels.mail.imap_errors import ImapErrorCode
    from envelock.channels.mail.imap_probe import probe_sync

    candidate = Candidate("127.0.0.1", imap_server.port, "none", "test", 10)
    result = probe_sync(
        [candidate], email="pay@socketco.example", password="wrong"  # noqa: S106
    )
    assert not result.ok
    assert result.failure is not None
    assert result.failure.code is ImapErrorCode.AUTH_FAILED
    assert result.failure.terminal


def test_fetch_new_reads_the_message_off_the_wire(imap_server: TinyImapServer) -> None:
    from envelock.channels.mail import imap_sync

    result = imap_sync.fetch_new(
        host="127.0.0.1",
        port=imap_server.port,
        security="none",
        username="pay@socketco.example",
        password=SERVER_PW,
        since_uid=None,
        uidvalidity=None,
    )
    assert result.ok, result.error
    assert [m.uid for m in result.messages] == [1001]
    assert b"GB33BUKB20201555555555" in result.messages[0].raw
    assert result.uidvalidity == 42


def test_quarantine_moves_the_message_on_the_real_server(
    imap_server: TinyImapServer,
) -> None:
    from envelock.channels.mail import imap_sync

    moved = imap_sync.quarantine_message(
        host="127.0.0.1",
        port=imap_server.port,
        security="none",
        username="pay@socketco.example",
        password=SERVER_PW,
        uid=1001,
    )
    assert moved is True
    assert imap_server.moved == [1001]


async def test_the_worker_fetches_detects_and_quarantines_over_a_socket(
    db: None, imap_server: TinyImapServer
) -> None:
    """The whole product in one pass: poll a real IMAP server, run the message
    through the detection pipeline, raise the alert, pull the mail out of the
    inbox, and advance the cursor so the next poll sees nothing new."""
    from envelock.core.enums import MailboxClass, SourceMechanism
    from envelock.db import get_sessionmaker
    from envelock.models import Domain, Mailbox, MailboxCredential, Tenant
    from envelock.security.crypto import seal
    from envelock.workers.imap_fetch import sync_mailbox

    tenant_id, mailbox_id = uuid4(), uuid4()
    async with get_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name="SocketCo"))
        await session.flush()  # the tenant row must exist before its children
        session.add(
            Domain(
                id=uuid4(),
                tenant_id=tenant_id,
                name="socketco.example",
                registrable_domain="socketco.example",
                verification_token="tok",  # noqa: S106 — a DNS proof token, not a credential
            )
        )
        session.add(
            Mailbox(
                id=mailbox_id,
                tenant_id=tenant_id,
                address="pay@socketco.example",
                mailbox_class=MailboxClass.PROTECTED.value,
                sources=[SourceMechanism.IMAP_IDLE.value],
                is_active=True,
            )
        )
        sealed = seal(SERVER_PW.encode(), aad=str(mailbox_id).encode())
        session.add(
            MailboxCredential(
                mailbox_id=mailbox_id,
                tenant_id=tenant_id,
                kind="imap_password",
                imap_host="127.0.0.1",
                imap_port=imap_server.port,
                imap_security="none",
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
        await session.commit()

    async with get_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        summary = await sync_mailbox(session, mailbox)

    assert summary["ok"], summary
    assert summary["fetched"] == 1
    assert summary["alerted"] == 1, "a bank-detail change from a lookalike must alert"
    assert summary["quarantined"] == 1
    assert imap_server.moved == [1001]

    # The cursor advanced, so a second poll is a no-op rather than a re-alert.
    async with get_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        second = await sync_mailbox(session, mailbox)
    assert second["ok"] and second["fetched"] == 0


def test_a_dead_port_reports_a_connection_failure_not_a_bad_password() -> None:
    """A closed port must never read as "wrong password" — that sends the
    customer to reset a credential that was fine."""
    from envelock.channels.mail.imap_discovery import Candidate
    from envelock.channels.mail.imap_errors import ImapErrorCode
    from envelock.channels.mail.imap_probe import probe_sync

    # Bind and immediately close, so the port is almost certainly free.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()

    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "true"
    from envelock.config import get_settings

    get_settings.cache_clear()
    try:
        result = probe_sync(
            [Candidate("127.0.0.1", dead_port, "none", "test", 10)],
            email="pay@socketco.example",
            password="anything",  # noqa: S106
        )
    finally:
        os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "false"
        get_settings.cache_clear()

    assert not result.ok
    assert result.failure is not None
    assert result.failure.code in (
        ImapErrorCode.CONNECTION_REFUSED,
        ImapErrorCode.TIMEOUT,
        ImapErrorCode.NETWORK_UNREACHABLE,
    )
    assert not result.failure.terminal


