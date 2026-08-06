"""Re-encrypt every stored credential when the master key rotates.

Rotating ``ENVELOCK_CREDENTIAL_MASTER_KEY`` without this step silently bricks
every connected mailbox: the ciphertext can no longer be opened, so the mailbox
reads as "connected" but is never read (this is exactly the incident that flagged
the gap — see the mailbox `needs_reconnect` signal).

Runbook for a planned rotation:
  1. Keep the CURRENT key value at hand — export it as the OLD key.
  2. Set ``ENVELOCK_CREDENTIAL_MASTER_KEY`` in the environment to the NEW key.
  3. Run this tool. It decrypts each credential under the OLD key and re-seals it
     under the NEW key, in place, and clears any stale ``needs_reconnect`` flag.

    ENVELOCK_OLD_CREDENTIAL_MASTER_KEY=<old> \
    ENVELOCK_CREDENTIAL_MASTER_KEY=<new> \
        python -m envelock.security.rotate_credentials

Add ``--dry-run`` to report what would change without writing.
"""

from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import select

from envelock.config import get_settings
from envelock.db import get_sessionmaker
from envelock.models import Mailbox, MailboxCredential
from envelock.security.crypto import CryptoError, SealedSecret, rekey


async def rotate(*, old_key: str, new_key: str, dry_run: bool = False) -> dict:
    """Re-seal every MailboxCredential from old_key to new_key. Returns a summary.

    Credentials already sealed under the new key are skipped (idempotent), and one
    that cannot be opened under the old key is reported, not fatal — so a single
    bad row never blocks the rest of the rotation.
    """
    from envelock.security.crypto import _kek_from, _key_id_from

    new_key_id = _key_id_from(_kek_from(new_key))
    summary = {"total": 0, "rotated": 0, "already_new": 0, "failed": 0}
    async with get_sessionmaker()() as session:
        creds = (await session.execute(select(MailboxCredential))).scalars().all()
        summary["total"] = len(creds)
        for cred in creds:
            if cred.key_id == new_key_id:
                summary["already_new"] += 1
                continue
            sealed = SealedSecret(
                ciphertext=cred.ciphertext,
                wrapped_dek=cred.wrapped_dek,
                key_id=cred.key_id or "",
            )
            try:
                resealed = rekey(
                    sealed,
                    aad=str(cred.mailbox_id).encode(),
                    old_master_key=old_key,
                    new_master_key=new_key,
                )
            except CryptoError:
                summary["failed"] += 1
                continue
            if not dry_run:
                cred.ciphertext = resealed.ciphertext
                cred.wrapped_dek = resealed.wrapped_dek
                cred.key_id = resealed.key_id
                mailbox = await session.get(Mailbox, cred.mailbox_id)
                if mailbox is not None and mailbox.needs_reconnect:
                    mailbox.needs_reconnect = False
                    mailbox.connection_error = None
            summary["rotated"] += 1
        if not dry_run:
            await session.commit()
    return summary


def main() -> None:
    old_key = os.environ.get("ENVELOCK_OLD_CREDENTIAL_MASTER_KEY", "")
    new_key = get_settings().credential_master_key.get_secret_value()
    dry_run = "--dry-run" in sys.argv
    if not old_key:
        print("ERROR: set ENVELOCK_OLD_CREDENTIAL_MASTER_KEY to the previous key.")
        raise SystemExit(2)
    if not new_key:
        print("ERROR: ENVELOCK_CREDENTIAL_MASTER_KEY (the new key) is not set.")
        raise SystemExit(2)
    summary = asyncio.run(rotate(old_key=old_key, new_key=new_key, dry_run=dry_run))
    tag = " (dry run)" if dry_run else ""
    print(
        f"credential rotation{tag}: {summary['rotated']} rotated, "
        f"{summary['already_new']} already current, {summary['failed']} failed, "
        f"of {summary['total']} total."
    )
    if summary["failed"]:
        print(
            "  failed rows could not be opened under the old key — those mailboxes "
            "must be reconnected by the customer."
        )


if __name__ == "__main__":
    main()
