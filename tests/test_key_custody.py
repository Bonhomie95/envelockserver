"""Credential key custody (PRD §5.2).

We hold hundreds of businesses' mailbox passwords. The property that matters is
not "the secrets are encrypted" — they always were — but **which process can
decrypt them**. Before this, the same environment variable that sealed a
credential was loaded in the API process, so one compromised web pod read the
whole store. These tests pin the separation.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from envelock.config import get_settings
from envelock.security import crypto, keys
from envelock.security.keygen import generate

MAILBOX = b"9f1f2b3c-0000-4000-8000-000000000001"


@pytest.fixture
def key_env() -> Iterator[dict[str, str]]:
    """Restore the process's key configuration after each case."""
    saved = {
        k: os.environ.get(k)
        for k in (
            "ENVELOCK_CREDENTIAL_KEY_PROVIDER",
            "ENVELOCK_CREDENTIAL_PUBLIC_KEY",
            "ENVELOCK_CREDENTIAL_PRIVATE_KEY",
            "ENVELOCK_CREDENTIAL_MASTER_KEY",
            "ENVELOCK_KMS_KEY_ID",
            "ENVELOCK_KMS_PROVIDER",
        )
    }
    yield saved
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()
    keys.reset_provider()


def _configure(**env: str | None) -> None:
    for key, value in env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()
    keys.reset_provider()


def test_the_api_can_seal_a_credential_it_cannot_read(key_env: dict) -> None:
    """The whole point of the split: a compromised web process holds only the
    public half, so it can accept a new mailbox password and is structurally
    incapable of reading any password it has already stored."""
    public, private = generate()

    # API deployment: public key only.
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=None,
    )
    assert crypto.can_decrypt() is False
    sealed = crypto.seal(b"the-app-password", aad=MAILBOX)
    assert sealed.key_id.startswith("x25519:")
    assert b"the-app-password" not in sealed.ciphertext

    with pytest.raises(crypto.CryptoError) as raised:
        crypto.open_secret(sealed, aad=MAILBOX)
    assert "cannot decrypt" in str(raised.value)

    # Worker deployment: both halves. Same ciphertext, now readable.
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=private,
    )
    assert crypto.can_decrypt() is True
    assert crypto.open_secret(sealed, aad=MAILBOX) == b"the-app-password"


def test_a_wrapped_key_cannot_be_replayed_onto_another_mailbox(key_env: dict) -> None:
    """The mailbox id is bound into the wrap, so lifting a row's ciphertext onto
    a different mailbox does not yield its password."""
    public, private = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=private,
    )
    sealed = crypto.seal(b"secret", aad=MAILBOX)
    with pytest.raises(crypto.CryptoError):
        crypto.open_secret(sealed, aad=b"a-different-mailbox-id")


def test_a_mismatched_key_pair_is_caught_at_boot_not_at_3am(key_env: dict) -> None:
    """A private key that doesn't match the public one would seal happily and
    fail to open weeks later, after the plaintext is gone."""
    public, _ = generate()
    _, other_private = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=other_private,
    )
    with pytest.raises(keys.KeyProviderError) as raised:
        keys.build_provider()
    assert "does not match" in str(raised.value)


def test_tampering_with_the_ciphertext_is_detected(key_env: dict) -> None:
    public, private = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=private,
    )
    sealed = crypto.seal(b"secret", aad=MAILBOX)
    flipped = crypto.SealedSecret(
        ciphertext=sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 0x01]),
        wrapped_dek=sealed.wrapped_dek,
        key_id=sealed.key_id,
    )
    with pytest.raises(crypto.CryptoError):
        crypto.open_secret(flipped, aad=MAILBOX)


def test_secrets_sealed_under_the_old_local_key_stay_readable_during_migration(
    key_env: dict,
) -> None:
    """Migrating providers must not black-hole the store. A record stamped
    `local:` is routed to the local reader while the new provider is active, so
    mailboxes keep working until `rotate_credentials --migrate` has run."""
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="local",
        ENVELOCK_CREDENTIAL_MASTER_KEY="the-original-development-master-key",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=None,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=None,
    )
    legacy = crypto.seal(b"legacy-password", aad=MAILBOX)
    assert legacy.key_id.startswith("local:")

    public, private = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=private,
        # The old key stays configured for the duration of the migration.
        ENVELOCK_CREDENTIAL_MASTER_KEY="the-original-development-master-key",
    )
    assert crypto.open_secret(legacy, aad=MAILBOX) == b"legacy-password"

    # And re-sealing moves it onto the new provider without the plaintext ever
    # reaching the caller.
    migrated = crypto.reseal(legacy, aad=MAILBOX)
    assert migrated.key_id.startswith("x25519:")
    assert crypto.open_secret(migrated, aad=MAILBOX) == b"legacy-password"


def test_dropping_the_old_key_after_migration_is_reported_clearly(key_env: dict) -> None:
    """If someone removes the old key material before migrating, they get a
    sentence telling them what to do — not an opaque decrypt failure."""
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="local",
        ENVELOCK_CREDENTIAL_MASTER_KEY="the-original-development-master-key",
    )
    legacy = crypto.seal(b"legacy-password", aad=MAILBOX)

    public, private = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=private,
        ENVELOCK_CREDENTIAL_MASTER_KEY="",
    )
    with pytest.raises(crypto.CryptoError) as raised:
        crypto.open_secret(legacy, aad=MAILBOX)
    assert "rotate_credentials" in str(raised.value)


def test_custody_summary_reports_the_truth(key_env: dict) -> None:
    """The admin security page shows this, so it must not flatter the deployment."""
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="local",
        ENVELOCK_CREDENTIAL_MASTER_KEY="a-development-key",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=None,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=None,
    )
    local = keys.custody_summary()
    assert local["mode"] == "local"
    assert local["separated"] is False
    assert local["hardware_backed"] is False

    public, _ = generate()
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="x25519",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=public,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=None,
    )
    split = keys.custody_summary()
    assert split["separated"] is True
    assert split["can_decrypt"] is False


def test_a_kms_key_id_alone_no_longer_looks_configured(key_env: dict) -> None:
    """The old production validator accepted ENVELOCK_KMS_KEY_ID on its own and
    then raised at the first mailbox connect, because no key material was set —
    a deployment that started cleanly and could not store a single credential."""
    _configure(
        ENVELOCK_CREDENTIAL_KEY_PROVIDER="auto",
        ENVELOCK_CREDENTIAL_MASTER_KEY="",
        ENVELOCK_CREDENTIAL_PUBLIC_KEY=None,
        ENVELOCK_CREDENTIAL_PRIVATE_KEY=None,
        ENVELOCK_KMS_KEY_ID="arn:aws:kms:eu-west-1:1:key/abc",
        ENVELOCK_KMS_PROVIDER=None,  # named nowhere → falls back to local, unset
    )
    with pytest.raises(keys.KeyProviderError):
        keys.build_provider()
