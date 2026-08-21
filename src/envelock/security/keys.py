"""Where the key that protects every stored mailbox password actually lives.

We hold hundreds of businesses' mailbox credentials. §5.2 promises envelope
encryption with a KMS/HSM-backed key; what existed was `sha256(<env var>)`, and
that same key was loaded in the API process so a single compromised web pod
could decrypt every credential we hold. This module is the fix: a key *provider*
that wraps and unwraps the per-secret DEK, with four implementations and one
hard rule — **the process that seals does not have to be the process that can
open**.

    ┌───────────────┐  wrap(DEK)          ┌──────────────┐
    │  API process  │ ──────────────────► │   provider   │
    │ (seal only)   │                     │ KMS / pubkey │
    └───────────────┘                     └──────────────┘
    ┌───────────────┐  unwrap(blob)               ▲
    │ worker process│ ────────────────────────────┘
    │ (can open)    │      only this side holds the private half
    └───────────────┘

Providers, in ascending order of custody strength:

* ``local``  — AES-GCM under `sha256(ENVELOCK_CREDENTIAL_MASTER_KEY)`. What we
  had. Development only: the key is in the environment of every process.
* ``x25519`` — public-key wrapping. The API is given only the **public** key and
  literally cannot decrypt anything it has stored; the worker holds the private
  key. Real custody separation with no cloud dependency, which is what makes it
  the recommended production default for a self-hosted deployment.
* ``aws``    — AWS KMS `Encrypt`/`Decrypt`. The key never leaves KMS; the API's
  IAM role is granted `kms:Encrypt` only and the worker's `kms:Decrypt`.
* ``gcp``    — Cloud KMS `encrypt`/`decrypt`, same split via IAM.

Every provider stamps a `key_id` onto the sealed record, and `open` routes on
that stamp — so a deployment can migrate from one provider to another with old
secrets still readable, and `rotate_credentials` can re-wrap them in the
background instead of bricking every connected mailbox.

Encryption context (the mailbox id) is bound into the wrap on the providers that
support it, so a wrapped DEK lifted from one row cannot be unwrapped for another.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("envelock.keys")


class KeyProviderError(Exception):
    """Configuration or provider-call failure. Never carries key material."""


class KeyProvider(Protocol):
    """Wrap and unwrap a 32-byte data key."""

    #: Stamped onto every sealed record; `provider_for_key_id` routes on its prefix.
    key_id: str

    #: False when this process holds only the sealing half (public key / Encrypt-only
    #: IAM). `open_secret` turns that into a clear error instead of a crypto failure.
    can_unwrap: bool

    def wrap(self, dek: bytes, *, context: str) -> bytes: ...

    def unwrap(self, blob: bytes, *, context: str) -> bytes: ...


# ── local (development) ──────────────────────────────────────────────────────
class LocalKeyProvider:
    """AES-GCM under a key derived from an environment variable.

    Kept because it makes the whole system runnable with no cloud account, and
    because every secret sealed before this refactor is in this format. It is not
    a custody boundary: any process with the env var can read every credential.
    """

    def __init__(self, master_key: str) -> None:
        if not master_key:
            raise KeyProviderError(
                "no credential master key configured — refusing to seal a secret "
                "in plaintext-equivalent form"
            )
        self._kek = hashlib.sha256(master_key.encode()).digest()
        self.key_id = "local:" + hashlib.sha256(self._kek).hexdigest()[:16]
        self.can_unwrap = True

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        nonce = os.urandom(12)
        # `context` is deliberately NOT bound here: records sealed by the previous
        # implementation have no context in their wrap, and binding it now would
        # make every one of them unopenable.
        return nonce + AESGCM(self._kek).encrypt(nonce, dek, None)

    def unwrap(self, blob: bytes, *, context: str) -> bytes:
        return AESGCM(self._kek).decrypt(blob[:12], blob[12:], None)


# ── x25519 public-key wrapping (recommended self-hosted production) ──────────
_X25519_INFO = b"envelock/dek-wrap/v1"


class X25519KeyProvider:
    """ECIES-style wrapping: anyone with the public key can seal, only the holder
    of the private key can open.

    This is the cheapest way to get the property that matters — a compromised API
    process cannot read the credential store — because the API is deployed with
    *only* `ENVELOCK_CREDENTIAL_PUBLIC_KEY` set.

    Wrapped blob = ephemeral public key (32) ‖ nonce (12) ‖ AES-GCM ciphertext.
    The mailbox id is bound as AAD, so a wrapped DEK cannot be replayed onto a
    different row.
    """

    def __init__(self, *, public_key_b64: str, private_key_b64: str | None) -> None:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        try:
            public_raw = base64.b64decode(public_key_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError(
                "ENVELOCK_CREDENTIAL_PUBLIC_KEY is not valid base64 — generate a "
                "pair with `python -m envelock.security.keygen`"
            ) from exc
        if len(public_raw) != 32:
            raise KeyProviderError(
                "ENVELOCK_CREDENTIAL_PUBLIC_KEY must be a 32-byte X25519 key"
            )
        self._public = X25519PublicKey.from_public_bytes(public_raw)

        self._private = None
        if private_key_b64:
            try:
                private_raw = base64.b64decode(private_key_b64, validate=True)
                self._private = X25519PrivateKey.from_private_bytes(private_raw)
            except Exception as exc:  # noqa: BLE001
                raise KeyProviderError(
                    "ENVELOCK_CREDENTIAL_PRIVATE_KEY is not a valid 32-byte X25519 key"
                ) from exc
            # A private key that doesn't match the public one would seal fine and
            # fail to open later — catch it at boot, not at 3am.
            derived = self._private.public_key().public_bytes_raw()
            if derived != public_raw:
                raise KeyProviderError(
                    "ENVELOCK_CREDENTIAL_PRIVATE_KEY does not match "
                    "ENVELOCK_CREDENTIAL_PUBLIC_KEY"
                )

        self.key_id = "x25519:" + hashlib.sha256(public_raw).hexdigest()[:16]
        self.can_unwrap = self._private is not None

    @staticmethod
    def _derive(shared: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_X25519_INFO + ephemeral_public + recipient_public,
        ).derive(shared)

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes_raw()
        recipient_public = self._public.public_bytes_raw()
        key = self._derive(
            ephemeral.exchange(self._public), ephemeral_public, recipient_public
        )
        nonce = os.urandom(12)
        sealed = AESGCM(key).encrypt(nonce, dek, context.encode())
        return ephemeral_public + nonce + sealed

    def unwrap(self, blob: bytes, *, context: str) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        if self._private is None:
            raise KeyProviderError(
                "this process holds only the public credential key, by design — "
                "decryption happens in the worker, which holds the private half"
            )
        ephemeral_public, nonce, sealed = blob[:32], blob[32:44], blob[44:]
        shared = self._private.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_public)
        )
        key = self._derive(
            shared, ephemeral_public, self._private.public_key().public_bytes_raw()
        )
        return AESGCM(key).decrypt(nonce, sealed, context.encode())


# ── AWS KMS ──────────────────────────────────────────────────────────────────
class AwsKmsProvider:
    """AWS KMS `Encrypt`/`Decrypt`. The key material never leaves KMS.

    Custody split is by IAM: grant the API role `kms:Encrypt` only and the worker
    role `kms:Decrypt`. `can_unwrap` cannot be known without calling, so it is
    declared from `ENVELOCK_CREDENTIAL_CAN_DECRYPT` — a deployment statement, not
    a guess.
    """

    def __init__(self, *, key_id: str, region: str | None, can_unwrap: bool) -> None:
        if not key_id:
            raise KeyProviderError("ENVELOCK_KMS_KEY_ID is required for the aws provider")
        self._key = key_id
        self._region = region
        self.key_id = f"awskms:{key_id}"
        self.can_unwrap = can_unwrap

    def _client(self):  # noqa: ANN202 — boto3 client
        try:
            import boto3  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — optional dependency
            raise KeyProviderError(
                "the aws key provider needs boto3 — install the 'kms-aws' extra"
            ) from exc
        if self._region:
            return boto3.client("kms", region_name=self._region)
        return boto3.client("kms")

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        try:
            out = self._client().encrypt(
                KeyId=self._key,
                Plaintext=dek,
                EncryptionContext={"envelock": context},
            )
        except Exception as exc:  # noqa: BLE001 — botocore raises many shapes
            raise KeyProviderError(f"KMS encrypt failed: {type(exc).__name__}") from exc
        return bytes(out["CiphertextBlob"])

    def unwrap(self, blob: bytes, *, context: str) -> bytes:
        if not self.can_unwrap:
            raise KeyProviderError(
                "this process is configured Encrypt-only against KMS, by design"
            )
        try:
            out = self._client().decrypt(
                CiphertextBlob=blob,
                EncryptionContext={"envelock": context},
                KeyId=self._key,
            )
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError(f"KMS decrypt failed: {type(exc).__name__}") from exc
        return bytes(out["Plaintext"])


# ── Google Cloud KMS ─────────────────────────────────────────────────────────
class GcpKmsProvider:
    """Cloud KMS `encrypt`/`decrypt` over REST, authenticated with the ambient
    service-account credentials (`google-auth` is already a dependency, so this
    needs no extra install). Custody split is by IAM role, as with AWS.

    `key_id` is the full resource name:
    `projects/P/locations/L/keyRings/R/cryptoKeys/K`.
    """

    _BASE = "https://cloudkms.googleapis.com/v1"

    def __init__(self, *, key_id: str, can_unwrap: bool) -> None:
        if not key_id or key_id.count("/") < 7:
            raise KeyProviderError(
                "the gcp key provider needs the full crypto-key resource name in "
                "ENVELOCK_KMS_KEY_ID (projects/…/cryptoKeys/…)"
            )
        self._key = key_id
        self.key_id = f"gcpkms:{key_id}"
        self.can_unwrap = can_unwrap

    def _token(self) -> str:
        try:
            import google.auth  # noqa: PLC0415
            from google.auth.transport.requests import Request  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise KeyProviderError("the gcp key provider needs google-auth") from exc
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloudkms"]
        )
        credentials.refresh(Request())
        return credentials.token

    def _call(self, verb: str, payload: dict) -> dict:
        import httpx  # noqa: PLC0415

        try:
            response = httpx.post(
                f"{self._BASE}/{self._key}:{verb}",
                headers={"Authorization": f"Bearer {self._token()}"},
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
        except KeyProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise KeyProviderError(f"Cloud KMS {verb} failed: {type(exc).__name__}") from exc

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        body = self._call(
            "encrypt",
            {
                "plaintext": base64.b64encode(dek).decode(),
                "additionalAuthenticatedData": base64.b64encode(context.encode()).decode(),
            },
        )
        return base64.b64decode(body["ciphertext"])

    def unwrap(self, blob: bytes, *, context: str) -> bytes:
        if not self.can_unwrap:
            raise KeyProviderError(
                "this process is configured encrypt-only against Cloud KMS, by design"
            )
        body = self._call(
            "decrypt",
            {
                "ciphertext": base64.b64encode(blob).decode(),
                "additionalAuthenticatedData": base64.b64encode(context.encode()).decode(),
            },
        )
        return base64.b64decode(body["plaintext"])


# ── Selection ────────────────────────────────────────────────────────────────
_ACTIVE: KeyProvider | None = None


def build_provider(settings=None) -> KeyProvider:  # noqa: ANN001 — config.Settings
    """The provider this process should use, from configuration.

    `settings` is passed explicitly by the production start-up validator, which
    runs *during* `Settings()` construction: calling `get_settings()` from there
    re-enters the constructor and recurses until the stack blows. Every other
    caller leaves it None and gets the cached settings.
    """
    if settings is None:
        from envelock.config import get_settings

        settings = get_settings()
    mode = (settings.credential_key_provider or "").strip().lower()

    if not mode or mode == "auto":
        # Infer, so an existing deployment keeps working and a new one only has to
        # set the key material rather than also naming the mode.
        if settings.credential_public_key:
            mode = "x25519"
        elif settings.kms_key_id and settings.kms_provider:
            mode = settings.kms_provider.strip().lower()
        else:
            mode = "local"

    if mode == "local":
        return LocalKeyProvider(settings.credential_master_key.get_secret_value())
    if mode == "x25519":
        private = settings.credential_private_key
        return X25519KeyProvider(
            public_key_b64=settings.credential_public_key or "",
            private_key_b64=private.get_secret_value() if private else None,
        )
    if mode == "aws":
        return AwsKmsProvider(
            key_id=settings.kms_key_id or "",
            region=settings.kms_region,
            can_unwrap=settings.credential_can_decrypt,
        )
    if mode == "gcp":
        return GcpKmsProvider(
            key_id=settings.kms_key_id or "",
            can_unwrap=settings.credential_can_decrypt,
        )
    raise KeyProviderError(
        f"unknown credential key provider '{mode}' — use local, x25519, aws or gcp"
    )


def active_provider() -> KeyProvider:
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = build_provider()
    return _ACTIVE


def reset_provider() -> None:
    """Drop the cached provider — used by tests and after a config change."""
    global _ACTIVE
    _ACTIVE = None


def provider_for_key_id(key_id: str) -> KeyProvider:
    """The provider that can open a record stamped `key_id`.

    Routing on the stamp is what makes migrating providers safe: secrets sealed
    under the old one stay readable while `rotate_credentials` re-wraps them.
    """
    provider = active_provider()
    if not key_id or key_id == provider.key_id:
        return provider

    prefix = key_id.split(":", 1)[0]
    if prefix == provider.key_id.split(":", 1)[0]:
        # Same provider family, different key version — the provider handles it
        # (KMS decodes the key from the blob; local/x25519 will fail cleanly if
        # the material really has rotated, which is what rotate_credentials is for).
        return provider

    from envelock.config import get_settings

    settings = get_settings()
    if prefix == "local" and settings.credential_master_key.get_secret_value():
        # The commonest migration: local → x25519/KMS. Keep the old reader alive
        # so nothing goes dark mid-rotation.
        return LocalKeyProvider(settings.credential_master_key.get_secret_value())

    raise KeyProviderError(
        f"no key provider configured that can open a secret sealed as '{prefix}' — "
        "keep the previous key material set until rotate_credentials has run"
    )


def custody_summary() -> dict:
    """What custody this process actually has. Surfaced on the admin security
    page and logged at boot, because "we use a KMS" must be checkable."""
    try:
        provider = active_provider()
    except KeyProviderError as exc:
        return {"ok": False, "mode": "unconfigured", "can_decrypt": False, "error": str(exc)}
    mode = provider.key_id.split(":", 1)[0]
    return {
        "ok": True,
        "mode": mode,
        "key_id": provider.key_id,
        "can_decrypt": provider.can_unwrap,
        "separated": mode in {"x25519", "awskms", "gcpkms"} and not provider.can_unwrap,
        "hardware_backed": mode in {"awskms", "gcpkms"},
    }


__all__ = [
    "AwsKmsProvider",
    "GcpKmsProvider",
    "KeyProvider",
    "KeyProviderError",
    "LocalKeyProvider",
    "X25519KeyProvider",
    "active_provider",
    "build_provider",
    "custody_summary",
    "provider_for_key_id",
    "reset_provider",
]
