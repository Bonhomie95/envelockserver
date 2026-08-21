"""Envelope encryption for stored secrets (PRD §5.2).

Mailbox passwords and OAuth refresh tokens are the crown jewels — a store of them
across hundreds of businesses is a bigger liability than the threat we sell
against. Every secret is sealed under a fresh per-secret data key (DEK), and that
DEK is wrapped by a key provider (`security/keys.py`): a KMS, a public key whose
private half lives only in the worker, or — in development — a key derived from
an environment variable.

Two properties matter and are enforced here rather than documented:

* **The DEK is never stored in the clear.** Only its wrapped form is persisted.
* **Sealing does not imply opening.** In a production deployment the API process
  holds only the sealing half, so `open_secret` there raises a clear error
  instead of returning a credential. That is the whole point of the split.

The wire format carries its provenance: `key_id` records which provider and key
sealed each record, so migrating providers leaves existing secrets readable while
`rotate_credentials` re-wraps them in the background.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from envelock.security.keys import (
    KeyProviderError,
    active_provider,
    provider_for_key_id,
)


class CryptoError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SealedSecret:
    ciphertext: bytes
    wrapped_dek: bytes
    key_id: str


def _context(aad: bytes | None) -> str:
    """The encryption context bound into the wrap. The caller's `aad` is the
    mailbox id, so a wrapped DEK cannot be replayed onto another row."""
    return (aad or b"").decode("utf-8", "replace")


def seal(plaintext: bytes, *, aad: bytes | None = None) -> SealedSecret:
    """Encrypt `plaintext` under a fresh DEK, then wrap the DEK with the provider.

    `aad` binds the ciphertext to a context (e.g. the mailbox id) so a sealed
    secret cannot be lifted and replayed against a different record.
    """
    try:
        provider = active_provider()
    except KeyProviderError as exc:
        raise CryptoError(str(exc)) from exc

    dek = AESGCM.generate_key(bit_length=256)
    dek_nonce = os.urandom(12)
    ciphertext = dek_nonce + AESGCM(dek).encrypt(dek_nonce, plaintext, aad)
    try:
        wrapped = provider.wrap(dek, context=_context(aad))
    except KeyProviderError as exc:
        raise CryptoError(f"could not wrap the data key — {exc}") from exc
    return SealedSecret(ciphertext=ciphertext, wrapped_dek=wrapped, key_id=provider.key_id)


def open_secret(sealed: SealedSecret, *, aad: bytes | None = None) -> bytes:
    """Unwrap the DEK, then decrypt. Raises `CryptoError` on any tamper — or when
    this process deliberately holds no decryption key."""
    try:
        provider = provider_for_key_id(sealed.key_id)
    except KeyProviderError as exc:
        raise CryptoError(str(exc)) from exc

    if not provider.can_unwrap:
        raise CryptoError(
            "this process cannot decrypt stored credentials by design — the "
            "decryption key lives only in the worker/broker deployment"
        )
    try:
        dek = provider.unwrap(sealed.wrapped_dek, context=_context(aad))
        nonce, body = sealed.ciphertext[:12], sealed.ciphertext[12:]
        return AESGCM(dek).decrypt(nonce, body, aad)
    except KeyProviderError as exc:
        raise CryptoError(str(exc)) from exc
    except Exception as exc:  # cryptography raises InvalidTag, among others
        raise CryptoError("could not open sealed secret — wrong key or tampered") from exc


def can_decrypt() -> bool:
    """Whether this process holds a key that can open stored credentials.

    Used at boot to refuse to start a worker that would silently fail every poll,
    and on the admin security page to show the custody split honestly.
    """
    try:
        return active_provider().can_unwrap
    except KeyProviderError:
        return False


# ── Rotation ─────────────────────────────────────────────────────────────────
def reseal(sealed: SealedSecret, *, aad: bytes | None) -> SealedSecret:
    """Open a secret with whichever provider sealed it and re-seal under the
    provider this process is configured with.

    This is how a deployment migrates from the development `local` key to a KMS
    or public-key provider: run `rotate_credentials` with both sets of key
    material present, and every credential moves without the customer noticing.
    """
    plaintext = open_secret(sealed, aad=aad)
    return seal(plaintext, aad=aad)


def _kek_from(raw: str) -> bytes:
    """Kept for the `local` → `local` master-key rotation path."""
    import hashlib

    if not raw:
        raise CryptoError("empty master key")
    return hashlib.sha256(raw.encode()).digest()


def _key_id_from(kek: bytes) -> str:
    import hashlib

    return "local:" + hashlib.sha256(kek).hexdigest()[:16]


def rekey(
    sealed: SealedSecret,
    *,
    aad: bytes | None,
    old_master_key: str,
    new_master_key: str,
) -> SealedSecret:
    """Re-seal a `local`-provider secret under a new master key.

    Rotating `ENVELOCK_CREDENTIAL_MASTER_KEY` otherwise silently bricks every
    stored credential (the mailbox reads as connected but can't be read). For a
    move to a *different provider*, use `reseal` instead.
    """
    old_kek = _kek_from(old_master_key)
    try:
        kek_nonce, wrapped = sealed.wrapped_dek[:12], sealed.wrapped_dek[12:]
        dek = AESGCM(old_kek).decrypt(kek_nonce, wrapped, None)
        nonce, body = sealed.ciphertext[:12], sealed.ciphertext[12:]
        plaintext = AESGCM(dek).decrypt(nonce, body, aad)
    except Exception as exc:
        raise CryptoError("could not open under the old key — wrong old key?") from exc

    new_kek = _kek_from(new_master_key)
    new_dek = AESGCM.generate_key(bit_length=256)
    dek_nonce = os.urandom(12)
    ciphertext = dek_nonce + AESGCM(new_dek).encrypt(dek_nonce, plaintext, aad)
    kek_nonce = os.urandom(12)
    wrapped = kek_nonce + AESGCM(new_kek).encrypt(kek_nonce, new_dek, None)
    return SealedSecret(ciphertext=ciphertext, wrapped_dek=wrapped, key_id=_key_id_from(new_kek))


__all__ = [
    "CryptoError",
    "SealedSecret",
    "can_decrypt",
    "open_secret",
    "rekey",
    "reseal",
    "seal",
]
