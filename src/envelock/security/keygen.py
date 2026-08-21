"""Generate the credential key pair for a production deployment.

    python -m envelock.security.keygen

Prints an X25519 pair. The split is the point:

* the **API** deployment gets `ENVELOCK_CREDENTIAL_PUBLIC_KEY` only — it can seal
  a new mailbox credential and is structurally incapable of reading any of them;
* the **worker/broker** deployment gets both, and is the only thing that can
  decrypt a credential in order to connect to a mail server.

Losing the private key means every stored credential is unrecoverable and every
customer must reconnect their mailboxes — back it up in your secret manager
before you deploy.
"""

from __future__ import annotations

import base64


def generate() -> tuple[str, str]:
    """`(public_b64, private_b64)`."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    private = X25519PrivateKey.generate()
    return (
        base64.b64encode(private.public_key().public_bytes_raw()).decode(),
        base64.b64encode(private.private_bytes_raw()).decode(),
    )


def main() -> None:
    public, private = generate()
    print("# Credential key pair (X25519). Store the private key in a secret manager.")
    print("#")
    print("# API / web deployment — public key ONLY, so a compromised web process")
    print("# cannot decrypt a single stored mailbox password:")
    print("ENVELOCK_CREDENTIAL_KEY_PROVIDER=x25519")
    print(f"ENVELOCK_CREDENTIAL_PUBLIC_KEY={public}")
    print()
    print("# Worker / broker deployment — both halves:")
    print("ENVELOCK_CREDENTIAL_KEY_PROVIDER=x25519")
    print(f"ENVELOCK_CREDENTIAL_PUBLIC_KEY={public}")
    print(f"ENVELOCK_CREDENTIAL_PRIVATE_KEY={private}")


if __name__ == "__main__":
    main()
