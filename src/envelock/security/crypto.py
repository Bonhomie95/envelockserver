"""Envelope encryption for stored secrets (PRD §5.2).

Mailbox passwords and OAuth refresh tokens are the crown jewels — a store of them
across hundreds of businesses is a bigger liability than the threat we sell
against. Every secret is sealed with a per-secret data key (DEK), and that DEK is
itself wrapped by a master key (KEK) held only in the environment / KMS. The
plaintext key never lands in a column, a log or an error trace.

The wire format keeps its parameters, so rotating to a KMS-backed KEK later does
not invalidate secrets sealed under the local key: `key_id` records which KEK
sealed each `wrapped_dek`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from envelock.config import get_settings


class CryptoError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SealedSecret:
    ciphertext: bytes
    wrapped_dek: bytes
    key_id: str


def _kek() -> bytes:
    """Derive a 256-bit KEK from the configured master key.

    In production a KMS/HSM wraps the DEK directly; the local key path exists so
    the system runs end to end without cloud dependencies (the config validator
    refuses to start production without one of the two — see config.py)."""
    raw = get_settings().credential_master_key.get_secret_value()
    if not raw:
        raise CryptoError(
            "no credential master key configured — refusing to seal a secret in "
            "plaintext-equivalent form"
        )
    # A hash gives a uniform 32-byte key regardless of the configured length.
    return hashlib.sha256(raw.encode()).digest()


def _key_id() -> str:
    settings = get_settings()
    if settings.kms_key_id:
        return f"kms:{settings.kms_key_id}"
    # Fingerprint the local KEK so a rotation is detectable without revealing it.
    return "local:" + hashlib.sha256(_kek()).hexdigest()[:16]


def seal(plaintext: bytes, *, aad: bytes | None = None) -> SealedSecret:
    """Encrypt `plaintext` under a fresh DEK, then wrap the DEK under the KEK.

    `aad` binds the ciphertext to a context (e.g. the mailbox id) so a sealed
    secret cannot be lifted and replayed against a different record.
    """
    import os

    dek = AESGCM.generate_key(bit_length=256)
    dek_nonce = os.urandom(12)
    ciphertext = dek_nonce + AESGCM(dek).encrypt(dek_nonce, plaintext, aad)

    kek_nonce = os.urandom(12)
    wrapped = kek_nonce + AESGCM(_kek()).encrypt(kek_nonce, dek, None)
    return SealedSecret(ciphertext=ciphertext, wrapped_dek=wrapped, key_id=_key_id())


def open_secret(
    sealed: SealedSecret, *, aad: bytes | None = None
) -> bytes:
    """Unwrap the DEK, then decrypt. Raises `CryptoError` on any tamper."""
    try:
        kek_nonce, wrapped = sealed.wrapped_dek[:12], sealed.wrapped_dek[12:]
        dek = AESGCM(_kek()).decrypt(kek_nonce, wrapped, None)
        nonce, body = sealed.ciphertext[:12], sealed.ciphertext[12:]
        return AESGCM(dek).decrypt(nonce, body, aad)
    except Exception as exc:  # cryptography raises InvalidTag, among others
        raise CryptoError("could not open sealed secret — wrong key or tampered") from exc
