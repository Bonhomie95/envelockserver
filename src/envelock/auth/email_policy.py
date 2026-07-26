"""Signup email policy — reject disposable / throwaway addresses.

A security product's accounts must be reachable: out-of-band alerts, recovery and
billing all assume a real inbox. Disposable providers (10-minute mailboxes) defeat
that and are a favourite of trial-abuse and account-farming, so we refuse them at
signup. The list is intentionally curated (the worst offenders) rather than
exhaustive; extend it with `ENVELOCK_DISPOSABLE_EMAIL_DOMAINS` (comma-separated) or
a newline-delimited file at `ENVELOCK_DISPOSABLE_EMAIL_FILE` without a code change.
"""

from __future__ import annotations

import os
from functools import lru_cache

from envelock.util.domains import registrable_domain

# The most common disposable / temporary-mail domains. Curated, not exhaustive.
_BUILTIN_DISPOSABLE: frozenset[str] = frozenset(
    {
        "mailinator.com", "guerrillamail.com", "guerrillamail.info", "grr.la",
        "sharklasers.com", "10minutemail.com", "10minutemail.net", "20minutemail.com",
        "temp-mail.org", "tempmail.com", "tempmailo.com", "tempmail.net",
        "throwawaymail.com", "throwaway.email", "getnada.com", "nada.email",
        "maildrop.cc", "mailnesia.com", "mohmal.com", "dispostable.com",
        "yopmail.com", "yopmail.net", "trashmail.com", "trashmail.de", "trash-mail.com",
        "fakeinbox.com", "fakemailgenerator.com", "emailondeck.com", "mailcatch.com",
        "spamgourmet.com", "mailtemp.org", "tempinbox.com", "tempr.email",
        "mytemp.email", "moakt.com", "burnermail.io", "spam4.me", "discard.email",
        "einrot.com", "getairmail.com", "harakirimail.com", "inboxkitten.com",
        "mail-temp.com", "mailhog.io", "mintemail.com", "mvrht.com", "no-spam.ws",
        "spambox.us", "tmail.ws", "tmpmail.org", "tmpmail.net", "vomoto.com",
        "wegwerfemail.de", "33mail.com", "anonaddy.com", "anonaddy.me", "byom.de",
        "correotemporal.org", "cuvox.de", "dayrep.com", "emailfake.com", "fakemail.net",
        "gishpuppy.com", "guerrillamailblock.com", "incognitomail.com", "jetable.org",
        "kasmail.com", "mailexpire.com", "meltmail.com", "mytrashmail.com",
        "nospam.ze.tc", "pjjkp.com", "rppkn.com", "spamavert.com", "spambog.com",
        "tempemail.co", "tempemail.net", "temporaryemail.net", "trbvm.com", "wh4f.org",
    }
)


@lru_cache(maxsize=1)
def _disposable_domains() -> frozenset[str]:
    extra: set[str] = set()
    env = os.environ.get("ENVELOCK_DISPOSABLE_EMAIL_DOMAINS", "")
    extra.update(d.strip().lower() for d in env.split(",") if d.strip())
    path = os.environ.get("ENVELOCK_DISPOSABLE_EMAIL_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            extra.update(line.strip().lower() for line in fh if line.strip())
    return _BUILTIN_DISPOSABLE | frozenset(extra)


def is_disposable_email(email: str) -> bool:
    """True if the address is from a known disposable / throwaway provider.

    Matched on the registrable domain (eTLD+1), so subdomains and MX-equivalent
    hosts of a blocked provider are caught too.
    """
    domain = email.rsplit("@", 1)[-1].strip().lower() if "@" in email else ""
    if not domain:
        return False
    reg = registrable_domain(domain) or domain
    disposable = _disposable_domains()
    return domain in disposable or reg in disposable
