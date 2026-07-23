# Getting your `.env` values

Every key in `.env.example`: what it is, whether you need it now, where to get
it, and what it costs.

**Nothing here blocks local development.** Two generated secrets and the Docker
datastores are enough to run the whole app. Everything else switches on a
specific detection, and an unset provider disables that detection visibly rather
than breaking anything (PRD P4).

```bash
cp .env.example .env
```

**Priority key:** 🔴 needed now · 🟡 needed before launch · ⚪ optional / later

---

## 1. Generate yourself — 🔴 two minutes, no accounts

| Key | Command |
|---|---|
| `ENVELOCK_SECRET_KEY` | `openssl rand -hex 32` |
| `ENVELOCK_CREDENTIAL_MASTER_KEY` | `openssl rand -hex 32` |

The credential master key envelope-encrypts tenant mailbox passwords. **In
production, replace it with `ENVELOCK_KMS_KEY_ID`** pointing at AWS KMS, GCP KMS
or Azure Key Vault — a literal key in an env var is for local development only.
The app refuses to start in production without one or the other.

`ENVELOCK_VAPID_PUBLIC_KEY` / `ENVELOCK_VAPID_PRIVATE_KEY` — 🟡 free, self-hosted
browser push (ladder rung L1). Generate with:

```bash
pip install py-vapid && vapid --gen && vapid --applicationServerKey
```

---

## 2. Datastores — 🔴 free, already configured

`docker compose up -d` starts Postgres, Redis, ClickHouse, Redpanda and ClamAV.
The DSNs in `.env.example` already point at them; change nothing locally.

For production use managed equivalents (RDS/Cloud SQL, ElastiCache, ClickHouse
Cloud, Redpanda Cloud) and paste their connection strings.

---

## 3. Free intelligence sources — 🟡 the free-first cascade (PRD §12.12)

These replace $500–5,000/month of commercial feeds. Get them before launch.

### ICANN CZDS — gTLD zone files
**Free. Application required, approval takes days to weeks — start early.**

1. Register at <https://czds.icann.org>
2. Request access per TLD (`.com`, `.net`, `.org` at minimum). Each registry approves separately.
3. State the purpose honestly: brand-protection monitoring for customers.
4. Set `ENVELOCK_CZDS_USERNAME` / `ENVELOCK_CZDS_PASSWORD`.

> ccTLDs (`.ng`, `.tw`, `.sg`, `.co.uk`) are **not** in CZDS. Certificate
> Transparency covers them instead, which is why CT is the primary sensor.

### Certificate Transparency — 🟡 free, no signup
`ENVELOCK_CERTSTREAM_URL` defaults to the public certstream feed. Run your own
if you need reliability guarantees — the public one has no SLA.

### RDAP — 🟡 free, no signup
`ENVELOCK_RDAP_BOOTSTRAP_URL` defaults to `rdap.org`. This is the modern
replacement for WHOIS. Nothing to configure.

### Google Safe Browsing — 🟡 free, biggest single win
1. Create a project at <https://console.cloud.google.com>
2. Enable **Safe Browsing API**
3. APIs & Services → Credentials → Create API key
4. Set `ENVELOCK_SAFEBROWSING_API_KEY`

The Update API is fully free. Generous quota.

### URLhaus — 🟡 free, no key
`ENVELOCK_URLHAUS_ENABLED=true`. Malware URL feed from abuse.ch.

> ⚠️ **Audit the licence of every feed before production.** Several "free" feeds
> prohibit commercial use — **Spamhaus** most commonly. That is a legal exposure,
> not just a cost question.

---

## 4. Mail provider connections — 🟡 free, needed for Tier 1

### Microsoft 365 (Graph)
1. <https://portal.azure.com> → Microsoft Entra ID → App registrations → New
2. Multitenant: **Accounts in any organizational directory**
3. Redirect URI (Web): `https://yourdomain/api/v1/connect/microsoft/callback`
4. Certificates & secrets → New client secret → copy immediately, it is shown once
5. API permissions → Microsoft Graph → **Application** permissions:
   `Mail.Read`, `Mail.ReadWrite`, `MailboxSettings.Read`, `AuditLog.Read.All`, `Directory.Read.All`
6. Grant admin consent
7. Set `ENVELOCK_MS_CLIENT_ID`, `ENVELOCK_MS_CLIENT_SECRET`, `ENVELOCK_MS_REDIRECT_URI`

`ENVELOCK_MS_WEBHOOK_URL` must be a **public HTTPS** URL — Graph will not deliver
to localhost. Use a tunnel (`ngrok`, `cloudflared`) in development.

> Customer-side licensing matters (PRD §11.4): sign-in log API access needs Entra
> ID P1/P2, and `MailItemsAccessed` needs E5. Confirm what your prospects hold.

### Google Workspace
1. <https://console.cloud.google.com> → new project
2. Enable **Gmail API**, **Admin SDK API**, **Cloud Pub/Sub API**
3. OAuth consent screen → External → add scopes:
   `gmail.readonly`, `gmail.modify`, `admin.reports.audit.readonly`
4. Credentials → OAuth client ID → Web application → add your redirect URI
5. Create a Pub/Sub topic, grant `gmail-api-push@system.gserviceaccount.com` the Publisher role
6. Set `ENVELOCK_GOOGLE_CLIENT_ID`, `ENVELOCK_GOOGLE_CLIENT_SECRET`, `ENVELOCK_GOOGLE_REDIRECT_URI`, `ENVELOCK_GOOGLE_PUBSUB_TOPIC`

Publishing the consent screen requires Google verification — **allow weeks**, and
a security assessment because these are restricted scopes. Start it early.

### Tier 3 / Tier 4 — nothing to obtain
IMAP and forwarding need no provider registration. `ENVELOCK_INGEST_DOMAIN` is
a subdomain you own with MX pointing at your ingest listener.

---

## 5. IP intelligence — ⚪ paid, has free tiers

| Provider | Free tier | Where |
|---|---|---|
| **ipinfo.io** | 50k requests/month | <https://ipinfo.io/signup> → `ENVELOCK_IPINFO_TOKEN` |
| **IPQualityScore** | 5k requests/month | <https://www.ipqualityscore.com> → `ENVELOCK_IPQS_API_KEY` |

Powers VPN/proxy/hosting classification (C6–C10). Either alone is fine; register
both and rotate on quota (PRD §12.12D).

---

## 6. Attachment analysis — ⚪ defer until revenue

Layers 0–1 of the cascade are free and self-hosted, and resolve the large
majority of attachments:

- **ClamAV** — already in `docker-compose.yml`
- **YARA rules** — free: `git clone https://github.com/Yara-Rules/rules rules/yara`

Keep `ENVELOCK_DETONATION_ENABLED=false` until the free layers are proven and the
fall-through rate is measured. Detonation is the biggest per-unit cost in the
product (PRD §12.10).

| When ready | Where | Cost |
|---|---|---|
| VirusTotal (hash lookup ≠ detonation) | <https://virustotal.com/gui/my-apikey> | Free tier: 4 req/min |
| OPSWAT MetaDefender | <https://www.opswat.com> | Sales |
| Hatching Triage | <https://tria.ge> | Free research tier |

---

## 7. Outbound email — 🟡 needed for alerts

**Self-hosting is a privacy decision, not a cost saving** (PRD §8.3). The risk is
deliverability: our alerts must land at HiNet, 263 and Gmail — the exact
providers we monitor. A cold IP puts Critical fraud alerts in spam.

Set `ENVELOCK_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM` for your own server, and
generate a DKIM keypair:

```bash
openssl genrsa -out dkim-private.pem 2048
openssl rsa -in dkim-private.pem -pubout -outform der | openssl base64 -A
```

Publish the public half as a TXT record at `envelock._domainkey.yourdomain`, and
point `ENVELOCK_SMTP_DKIM_PRIVATE_KEY_PATH` at the private half.

**Set `ENVELOCK_SMTP_RELAY_FALLBACK_DSN` from day one** — a warmed relay
(Amazon SES, Postmark) for Critical alerts if your own reputation degrades.
SES is ~$0.10 per 1,000 emails.

---

## 8. SMS — ⚪ escalation only, low volume

Fires only when a Critical goes unacknowledged (ladder rung L3), so volume is
small by design.

| Provider | Best for | Where |
|---|---|---|
| **Twilio** | Global / North America | <https://twilio.com> |
| **Vonage** | Europe / global | <https://developer.vonage.com> |
| **MessageBird** | Europe / global | <https://messagebird.com> |
| **AWS SNS** | Low-cost default | <https://aws.amazon.com/sns> |

Set `ENVELOCK_SMS_ENABLED=true`, `ENVELOCK_SMS_PROVIDER`, `ENVELOCK_SMS_API_KEY`.
Sender IDs need pre-registration in several markets (parts of Asia and Europe) —
**allow one to two weeks**.

---

## 9. Payments — 🟡 needed to charge anyone

**One acquirer per region keeps conversion independent of geography** (PRD §12.8).
Stripe is primary; the regional rails cover markets it serves less well.

| Provider | Market | Where | Fee |
|---|---|---|---|
| **Stripe** | North America + global cards | <https://dashboard.stripe.com/apikeys> | 2.9% + 30¢ |
| **Adyen** | Europe / global enterprise | <https://ca-test.adyen.com> | interchange++ |
| **Mercado Pago** | Latin America | <https://mercadopago.com/developers> | ~3.5% |
| **Razorpay** | Asia (India + neighbours) | <https://dashboard.razorpay.com> | ~2% |
| **PayPal** | Global fallback | <https://developer.paypal.com> | ~3.5% |

Each requires business verification — company registration, bank account, and
often a director's ID. **This is the longest lead time on the list; start it
before you need it.**

---

## Minimum to run locally

```bash
ENVELOCK_SECRET_KEY=<openssl rand -hex 32>
ENVELOCK_CREDENTIAL_MASTER_KEY=<openssl rand -hex 32>
# plus docker compose up -d
```

That is genuinely all. The domain scanner, detection sandbox, pricing engine and
connection advisor all work with no third-party keys, because Channel 3 runs on
public infrastructure.

## Start-early checklist

These have lead times measured in weeks and will gate launch if left late:

- [ ] **CZDS access** — per-registry approval
- [ ] **Google OAuth verification** — restricted scopes, security assessment
- [ ] **Payment provider verification** — business documents
- [ ] **SMS sender ID registration** — several Asian and European markets
- [ ] **SOC 2 Type II observation window** — 6–12 months *before* the report exists (PRD §11.2)
