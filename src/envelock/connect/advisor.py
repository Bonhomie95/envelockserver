"""Connection advisor — tells an IT team exactly how to connect their mail.

PRD §5: "Determine a prospect's tier automatically by MX lookup at signup." This
module is that. Given a domain, it identifies the mail provider from MX records
and returns the specific setup path for it.

Every provider is supported. What differs is *how* the connection is made and
which of the identity-side detections come from the provider versus the client
sensor — never whether the fraud detection itself works, which it does everywhere
(PRD §2, Channel 1 always has a fallback).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from envelock.core.enums import IntegrationTier, SourceMechanism


@dataclass(frozen=True, slots=True)
class Method:
    """One way to connect. Ordered best-first per provider."""

    id: str
    name: str
    tier: IntegrationTier
    source: SourceMechanism
    effort: str
    """What the customer actually has to do, in one phrase."""

    who: str
    """Who performs it — admin or the mailbox owner."""

    steps: tuple[str, ...]
    remediation: bool
    """Whether we can quarantine a message on this path."""

    identity_from: str
    """Where Channel 2 telemetry comes from on this path."""


@dataclass(frozen=True, slots=True)
class Provider:
    id: str
    name: str
    aliases: tuple[str, ...] = ()
    mx_patterns: tuple[str, ...] = ()
    imap_host: str | None = None
    imap_port: int = 993
    notes: str | None = None
    methods: tuple[Method, ...] = field(default_factory=tuple)


# ── Reusable connection methods ──────────────────────────────────────────────

_OAUTH_MS = Method(
    id="oauth_microsoft",
    name="Microsoft 365 admin consent",
    tier=IntegrationTier.FULL_API,
    source=SourceMechanism.GRAPH_API,
    effort="One click",
    who="Global admin",
    steps=(
        "Sign in to Envelock as a Microsoft 365 global admin.",
        "Choose Connect → Microsoft 365 and approve the consent screen.",
        "Select which mailboxes are Protected; the rest are Monitored automatically.",
        "Historical mail is backfilled so detection works on day one.",
    ),
    remediation=True,
    identity_from="Microsoft sign-in logs (client sensor optional)",
)

_OAUTH_GOOGLE = Method(
    id="oauth_google",
    name="Google Workspace admin consent",
    tier=IntegrationTier.FULL_API,
    source=SourceMechanism.GMAIL_API,
    effort="One click",
    who="Super admin",
    steps=(
        "Sign in to Envelock as a Google Workspace super admin.",
        "Choose Connect → Google Workspace and approve the consent screen.",
        "Select which mailboxes are Protected; the rest are Monitored automatically.",
        "Historical mail is backfilled so detection works on day one.",
    ),
    remediation=True,
    identity_from="Google Admin audit logs (client sensor optional)",
)

_ADMIN_API = Method(
    id="admin_api",
    name="Admin API key",
    tier=IntegrationTier.ADMIN_API,
    source=SourceMechanism.ADMIN_API,
    effort="Paste one key",
    who="Mail administrator",
    steps=(
        "Create a service account or API key in your mail admin console.",
        "Paste it into Envelock under Connect → Admin API.",
        "Choose the mailboxes to protect.",
        "Roll out the browser extension or Outlook add-in for session monitoring.",
    ),
    remediation=True,
    identity_from="Client sensor",
)


def _imap(host: str | None, port: int = 993) -> Method:
    return Method(
        id="imap",
        name="Direct mailbox connection",
        tier=IntegrationTier.IMAP,
        source=SourceMechanism.IMAP_IDLE,
        effort="One credential per mailbox",
        who="Mailbox owner or admin",
        steps=(
            "In Envelock choose Connect → Direct mailbox.",
            f"Server details are prefilled{f' ({host}:{port})' if host else ''}; "
            "confirm them with your provider if they differ.",
            "Use an app-specific password where your provider offers one.",
            "Credentials are encrypted with a key we cannot read in bulk and are "
            "only ever decrypted inside the isolated connection service.",
            "Install the browser extension or Outlook add-in to enable session and "
            "silent-access monitoring.",
        ),
        remediation=True,
        identity_from="Client sensor",
    )


_FORWARD = Method(
    id="forward",
    name="Forwarding rule",
    tier=IntegrationTier.FORWARDING,
    source=SourceMechanism.FORWARD_INGEST,
    effort="One rule, no credentials",
    who="Mailbox owner or admin",
    steps=(
        "Envelock gives you a private ingest address for your organisation.",
        "Create a server-side rule forwarding a copy of inbound mail to it.",
        "Allowlist the ingest address in your gateway — an external forward is "
        "exactly the kind of rule we normally flag as Critical.",
        "Install the browser extension or Outlook add-in for session monitoring.",
    ),
    remediation=False,
    identity_from="Client sensor",
)

_JOURNAL = Method(
    id="journal",
    name="Journaling rule",
    tier=IntegrationTier.FORWARDING,
    source=SourceMechanism.JOURNAL,
    effort="One journal rule",
    who="Exchange administrator",
    steps=(
        "Create a journal rule in Exchange targeting the Envelock ingest address.",
        "Journaling captures outbound as well as inbound mail.",
        "Install the Outlook add-in for session monitoring.",
    ),
    remediation=False,
    identity_from="Client sensor",
)


def _standard(imap_host: str | None, port: int = 993) -> tuple[Method, ...]:
    return (_imap(imap_host, port), _FORWARD)


# ── Provider registry ────────────────────────────────────────────────────────
PROVIDERS: tuple[Provider, ...] = (
    Provider(
        id="microsoft365",
        name="Microsoft 365",
        aliases=("Exchange Online", "Office 365", "Outlook.com business"),
        mx_patterns=("mail.protection.outlook.com", "outlook.com", "office365.com"),
        imap_host="outlook.office365.com",
        methods=(_OAUTH_MS, _imap("outlook.office365.com"), _FORWARD),
    ),
    Provider(
        id="google",
        name="Google Workspace",
        aliases=("Gmail", "G Suite"),
        mx_patterns=("google.com", "googlemail.com", "aspmx.l.google.com"),
        imap_host="imap.gmail.com",
        methods=(_OAUTH_GOOGLE, _imap("imap.gmail.com"), _FORWARD),
    ),
    Provider(
        id="hinet",
        name="HiNet hiBox",
        aliases=("Chunghwa Telecom", "hibox"),
        mx_patterns=("hinet.net", "hibox.hinet.net", "msa.hinet.net"),
        imap_host="imap.hinet.net",
        notes="Chunghwa requires TLS on submission; our connector uses it by default.",
        methods=_standard("imap.hinet.net"),
    ),
    Provider(
        id="net263",
        name="263 Enterprise Mail",
        aliases=("263.net", "263 网络通信"),
        mx_patterns=("263.net", "263xmail.com"),
        imap_host="imap.263.net",
        notes="Mainland China — data residency review required before onboarding.",
        methods=_standard("imap.263.net"),
    ),
    Provider(
        id="singnet",
        name="SingNet",
        aliases=("Singtel",),
        mx_patterns=("singnet.com.sg", "singtel.com"),
        imap_host="imap.singnet.com.sg",
        methods=_standard("imap.singnet.com.sg"),
    ),
    Provider(
        id="tencent",
        name="Tencent Exmail",
        aliases=("QQ Mail", "腾讯企业邮箱"),
        mx_patterns=("qq.com", "exmail.qq.com"),
        imap_host="imap.exmail.qq.com",
        methods=_standard("imap.exmail.qq.com"),
    ),
    Provider(
        id="netease",
        name="NetEase Mail",
        aliases=("163.com", "126.com", "yeah.net"),
        mx_patterns=("163.com", "126.com", "netease.com", "ym.163.com"),
        imap_host="imap.ym.163.com",
        methods=_standard("imap.ym.163.com"),
    ),
    Provider(
        id="alibaba",
        name="Alibaba Mail",
        aliases=("Aliyun", "阿里邮箱"),
        mx_patterns=("alibaba-inc.com", "mxhichina.com", "aliyun.com"),
        imap_host="imap.qiye.aliyun.com",
        methods=(_ADMIN_API, _imap("imap.qiye.aliyun.com"), _FORWARD),
    ),
    Provider(
        id="zoho",
        name="Zoho Mail",
        mx_patterns=("zoho.com", "zohomail.com", "zoho.eu"),
        imap_host="imap.zoho.com",
        methods=(_ADMIN_API, _imap("imap.zoho.com"), _FORWARD),
    ),
    Provider(
        id="zimbra",
        name="Zimbra",
        mx_patterns=("zimbra",),
        imap_host=None,
        methods=(_ADMIN_API, _imap(None), _FORWARD),
    ),
    Provider(
        id="fastmail",
        name="Fastmail",
        mx_patterns=("messagingengine.com", "fastmail.com"),
        imap_host="imap.fastmail.com",
        methods=(_ADMIN_API, _imap("imap.fastmail.com"), _FORWARD),
    ),
    Provider(
        id="rackspace",
        name="Rackspace Email",
        mx_patterns=("emailsrvr.com", "rackspace.com"),
        imap_host="secure.emailsrvr.com",
        methods=(_ADMIN_API, _imap("secure.emailsrvr.com"), _FORWARD),
    ),
    Provider(
        id="titan",
        name="Titan Mail",
        mx_patterns=("titan.email", "mx1.titan.email"),
        imap_host="imap.titan.email",
        methods=_standard("imap.titan.email"),
    ),
    Provider(
        id="yandex",
        name="Yandex 360",
        mx_patterns=("yandex.net", "yandex.ru", "mx.yandex.net"),
        imap_host="imap.yandex.com",
        methods=_standard("imap.yandex.com"),
    ),
    Provider(
        id="ionos",
        name="IONOS",
        aliases=("1&1",),
        mx_patterns=("ionos.com", "1and1.com", "kundenserver.de", "perfora.net"),
        imap_host="imap.ionos.com",
        methods=_standard("imap.ionos.com"),
    ),
    Provider(
        id="ovh",
        name="OVHcloud Email",
        mx_patterns=("ovh.net", "ovh.com", "mail.ovh.net"),
        imap_host="ssl0.ovh.net",
        methods=_standard("ssl0.ovh.net"),
    ),
    Provider(
        id="godaddy",
        name="GoDaddy Email",
        aliases=("Secureserver",),
        mx_patterns=("secureserver.net", "godaddy.com"),
        imap_host="imap.secureserver.net",
        methods=_standard("imap.secureserver.net"),
    ),
    Provider(
        id="namecheap",
        name="Namecheap Private Email",
        mx_patterns=("privateemail.com", "registrar-servers.com"),
        imap_host="mail.privateemail.com",
        methods=_standard("mail.privateemail.com"),
    ),
    Provider(
        id="hostinger",
        name="Hostinger Mail",
        aliases=("Hostinger Titan",),
        mx_patterns=("hostinger.com", "hostinger.in"),
        imap_host="imap.hostinger.com",
        methods=_standard("imap.hostinger.com"),
    ),
    Provider(
        id="cpanel",
        name="cPanel / Dovecot hosting",
        aliases=("Bluehost", "SiteGround", "HostGator", "shared hosting"),
        mx_patterns=("cpanel", "bluehost.com", "siteground", "hostgator", "websitewelcome"),
        imap_host=None,
        notes="Usually mail.yourdomain.com — the advisor prefills it from your MX record.",
        methods=_standard(None),
    ),
    Provider(
        id="proton",
        name="Proton Mail",
        mx_patterns=("protonmail.ch", "proton.me"),
        imap_host="127.0.0.1",
        imap_port=1143,
        notes="Requires Proton Bridge for IMAP; forwarding works without it.",
        methods=(_FORWARD, _imap("127.0.0.1", 1143)),
    ),
    Provider(
        id="exchange_onprem",
        name="Exchange on-premises",
        aliases=("Exchange 2016", "Exchange 2019", "hybrid"),
        mx_patterns=(),
        imap_host=None,
        methods=(_JOURNAL, _imap(None), _FORWARD),
    ),
    Provider(
        id="rediff",
        name="Rediffmail Pro",
        mx_patterns=("rediffmail.com", "rediffmailpro.com"),
        imap_host="imap.rediffmailpro.com",
        methods=_standard("imap.rediffmailpro.com"),
    ),
    Provider(
        id="mailru",
        name="VK / Mail.ru for Business",
        mx_patterns=("mail.ru", "emx.mail.ru"),
        imap_host="imap.mail.ru",
        methods=_standard("imap.mail.ru"),
    ),
    Provider(
        id="naver",
        name="Naver Works",
        aliases=("Worksmobile",),
        mx_patterns=("naver.com", "worksmobile.com"),
        imap_host="imap.worksmobile.com",
        methods=_standard("imap.worksmobile.com"),
    ),
)

#: Fallback when MX records match nothing known. Not a lesser tier — the same
#: universal methods every provider supports.
GENERIC = Provider(
    id="generic",
    name="Your mail provider",
    imap_host=None,
    notes="We could not match these MX records to a provider we have on file, "
    "which changes nothing about coverage — direct connection and forwarding "
    "work on every mail system.",
    methods=_standard(None),
)

_BY_ID = {p.id: p for p in PROVIDERS}


def identify(mx_hosts: list[str]) -> Provider:
    """Match MX records to a provider. Longest pattern wins, so
    `mail.protection.outlook.com` beats a bare `outlook.com`."""
    blob = " ".join(h.lower().rstrip(".") for h in mx_hosts)
    best: tuple[int, Provider] | None = None
    for provider in PROVIDERS:
        for pattern in provider.mx_patterns:
            if pattern in blob and (best is None or len(pattern) > best[0]):
                best = (len(pattern), provider)
    return best[1] if best else GENERIC


def by_id(provider_id: str) -> Provider | None:
    return _BY_ID.get(provider_id)


def imap_host_guess(provider: Provider, domain: str, mx_hosts: list[str]) -> str | None:
    """Best guess at an IMAP host when the provider has no fixed one."""
    if provider.imap_host:
        return provider.imap_host
    if mx_hosts:
        first = mx_hosts[0].lower().rstrip(".")
        # `mail.acme.com` style MX usually means IMAP on the same host.
        if first.startswith(("mail.", "imap.", "mx.")):
            return first.replace("mx.", "mail.", 1)
    return f"mail.{domain}"
