"""Re-encrypt every stored credential when the credential key changes.

Rotating the key without this step silently bricks every connected mailbox: the
ciphertext can no longer be opened, so the mailbox reads as "connected" but is
never read (this is exactly the incident that flagged the gap — see the mailbox
`needs_reconnect` signal).

Two jobs, both run from the process that CAN decrypt (the worker deployment —
never the API, which in production holds only the sealing key):

**Migrating to real key custody** (`local` → `x25519` / KMS). This is the one
that matters: it is how a deployment stops holding its master key in an
environment variable readable by the web process.

    ENVELOCK_CREDENTIAL_MASTER_KEY=<the existing local key, so old rows open> \
    ENVELOCK_CREDENTIAL_KEY_PROVIDER=x25519 \
    ENVELOCK_CREDENTIAL_PUBLIC_KEY=<new public> \
    ENVELOCK_CREDENTIAL_PRIVATE_KEY=<new private> \
        python -m envelock.security.rotate_credentials --migrate

    Once it reports 0 remaining on the old provider, drop
    ENVELOCK_CREDENTIAL_MASTER_KEY entirely and redeploy.

**Rotating the development master key in place** (`local` → `local`):

    ENVELOCK_OLD_CREDENTIAL_MASTER_KEY=<old> \
    ENVELOCK_CREDENTIAL_MASTER_KEY=<new> \
        python -m envelock.security.rotate_credentials

Add ``--dry-run`` to either to report what would change without writing.
"""

from __future__ import annotations

import asyncio
import os
import sys

from sqlalchemy import select

from envelock.config import get_settings
from envelock.db import get_sessionmaker
from envelock.models import Mailbox, MailboxCredential
from envelock.security.crypto import CryptoError, SealedSecret, rekey, reseal


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


async def migrate(*, dry_run: bool = False) -> dict:
    """Re-wrap every credential under the key provider this process is configured
    with, whatever provider sealed it.

    Unlike `rotate`, this crosses providers: it is the local-key → KMS/public-key
    migration. Old key material must still be configured so the old rows can be
    opened; `provider_for_key_id` routes each record to whichever provider sealed
    it, so the store is readable throughout and nothing goes dark mid-run.
    """
    from envelock.security.keys import active_provider

    target = active_provider()
    if not target.can_unwrap:
        raise SystemExit(
            "This process holds no decryption key, so it cannot migrate anything. "
            "Run the migration from the worker deployment (the one with the "
            "private key / Decrypt permission)."
        )

    summary = {"total": 0, "migrated": 0, "already_current": 0, "failed": 0, "by_key": {}}
    async with get_sessionmaker()() as session:
        creds = (await session.execute(select(MailboxCredential))).scalars().all()
        summary["total"] = len(creds)
        for cred in creds:
            summary["by_key"][cred.key_id or "?"] = (
                summary["by_key"].get(cred.key_id or "?", 0) + 1
            )
            if cred.key_id == target.key_id:
                summary["already_current"] += 1
                continue
            sealed = SealedSecret(
                ciphertext=cred.ciphertext,
                wrapped_dek=cred.wrapped_dek,
                key_id=cred.key_id or "",
            )
            try:
                resealed = reseal(sealed, aad=str(cred.mailbox_id).encode())
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
            summary["migrated"] += 1
        if not dry_run:
            await session.commit()
    return summary


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    tag = " (dry run)" if dry_run else ""

    if "--migrate" in sys.argv:
        from envelock.security.keys import custody_summary

        custody = custody_summary()
        print(f"target key custody: {custody.get('key_id')} ({custody.get('mode')})")
        summary = asyncio.run(migrate(dry_run=dry_run))
        print(
            f"credential migration{tag}: {summary['migrated']} re-wrapped, "
            f"{summary['already_current']} already current, {summary['failed']} failed, "
            f"of {summary['total']} total."
        )
        for key_id, count in sorted(summary["by_key"].items()):
            print(f"  before: {count:>5}  {key_id}")
        if summary["failed"]:
            print(
                "  failed rows could not be opened — keep the previous key material "
                "configured, or those mailboxes must be reconnected."
            )
        return

    old_key = os.environ.get("ENVELOCK_OLD_CREDENTIAL_MASTER_KEY", "")
    new_key = get_settings().credential_master_key.get_secret_value()
    if not old_key:
        print(
            "ERROR: set ENVELOCK_OLD_CREDENTIAL_MASTER_KEY to the previous key, "
            "or pass --migrate to move to a different key provider."
        )
        raise SystemExit(2)
    if not new_key:
        print("ERROR: ENVELOCK_CREDENTIAL_MASTER_KEY (the new key) is not set.")
        raise SystemExit(2)
    summary = asyncio.run(rotate(old_key=old_key, new_key=new_key, dry_run=dry_run))
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
