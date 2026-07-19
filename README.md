# Envelock — server

Email fraud and account-takeover protection. Python / FastAPI backend.

**[`../PRD.md`](../PRD.md) is the specification and the source of truth.** This README
covers how to run and extend the service; the PRD covers what it does and why. If code
and PRD disagree, that is a bug in one of them — say which, don't silently diverge.

---

## Quick start

```bash
cd server

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# Generate the two required secrets:
#   openssl rand -hex 32   -> ENVELOCK_SECRET_KEY
#   openssl rand -hex 32   -> ENVELOCK_CREDENTIAL_MASTER_KEY

docker compose up -d          # postgres, redis, clickhouse, redpanda, clamav

uvicorn envelock.main:app --reload --app-dir src
```

Then:

```bash
curl localhost:8010/health
open http://localhost:8010/docs
```

Tests, lint, types:

```bash
pytest
ruff check src tests
mypy src
```

> Only `ENVELOCK_SECRET_KEY` and the datastore DSNs are needed to boot. Every provider
> integration is optional and unset by default — see [Graceful degradation](#graceful-degradation).

---

## Architecture

Three independent channels feed one normalised event stream (PRD §2, §10).

```
CHANNEL 1 — MAIL (content)          ┐
  Graph API · Gmail API             │
  Admin API / JMAP                  │
  IMAP IDLE / IMAP poll             ├──▶ normaliser ──▶ Redpanda ──▶ detections ──▶ risk ──▶ alerts
  Forwarding / journal ingest       │      (core/events.py)              │
                                    │                                    │
CHANNEL 2 — IDENTITY (who/where)    │                              A · B · C · D
  Entra logs · Google Reports       │                                    │
  Client sensor (ext / add-in)      │                                    ▼
  IMAP \Seen divergence             │                          notification ladder
                                    │                             L0 → L1 → L2 → L3
CHANNEL 3 — EXTERNAL (domain)       │                                    │
  CT logs · CZDS · RDAP · DMARC RUA ┘                                    ▼
                                                              remediation (Graph / IMAP MOVE)
```

Coverage is universal because **each channel has a fallback that works everywhere**:
every mail system supports forwarding; the client sensor runs on the device rather than
the server; Channel 3 needs no mailbox access at all.

### Layout

```
src/envelock/
├── config.py           # settings; mirrors .env.example one-for-one
├── main.py             # FastAPI app factory
├── core/
│   ├── enums.py        # shared vocabulary, named to match the PRD
│   ├── events.py       # ★ the unified event schema — build against this
│   └── capabilities.py # ★ what each mechanism can do; derives protection level
├── channels/
│   ├── mail/           # Channel 1 ingest → MailEvent
│   ├── identity/       # Channel 2 ingest → IdentityEvent
│   └── external/       # Channel 3 ingest → ExternalEvent
├── detections/         # A/B/C/D services; consume events, emit findings
├── risk/               # scoring, combination logic, alert tiering
├── notify/             # the L0→L3 ladder
├── billing/            # plans, trial ledger, metering
└── api/
```

---

## The two rules that keep this coherent

### 1. Detections never branch on `source`

`core/events.py` is the critical abstraction. Graph, Gmail, IMAP and forwarding ingest
all emit the **same** `MailEvent`. Detection logic is written once and runs identically
regardless of how the mail arrived.

Without this discipline we end up with four implementations of A1 (bank-detail change)
and they drift apart. Build against the event models; never against a provider SDK.

```python
# WRONG — this is how the codebase rots
if event.source == SourceMechanism.GRAPH_API:
    ...

# RIGHT — declare what you need, let the platform report coverage honestly
if Capability.MODIFY_MESSAGE in mailbox.capabilities:
    await quarantine(event)
```

### 2. Coverage is derived, never declared

`core/capabilities.py` maps each mechanism to what it can actually do, and derives the
mailbox's protection level from that. It is the executable form of the PRD §4 coverage
matrix, and it enforces PRD **P4: never silently degrade**.

A detection that needs a capability the mailbox lacks is reported as *inactive by name*,
not quietly skipped. A customer who believes they have session monitoring and doesn't
will blame us for the breach — correctly.

Consequences already encoded, with tests in `tests/test_capabilities.py`:

| Fact | Why |
|---|---|
| Tier 4 forwarding can never quarantine | The copy arrives post-delivery. `MailEvent.remediable` is False. |
| Tier 3 IMAP **can** quarantine | `IMAP MOVE` works on a 1998 server. This is the Tier 4 → Tier 3 upgrade argument. |
| Tier 3 + sensor reaches Standard, not Full | IMAP cannot read server-side rules (PRD §7.4). Deliberate — do not "fix" it. |
| Channel 3 alone is Limited | No mailbox access. This is Guard, free forever. |

---

## Graceful degradation

Unset provider credentials are normal, not an error. A missing provider disables the
detections that depend on it and downgrades the affected mailboxes' protection level.
Nothing crashes, and nothing pretends to work.

This means you can develop most of the system with only Postgres and Redis running.

---

## Cost discipline

Two design decisions in the config are load-bearing for margin (PRD §12.11, §12.12).
Changing them changes unit economics, so read those sections before touching them.

**Free sources first, paid last, rotated.** Every external lookup is a cascade: shared
verdict cache → self-hosted analysis → free feeds → paid provider. Only the fall-through
reaches a metered API. Instrument the fall-through rate from day one — it is the single
number that predicts COGS.

- Attachments: SHA-256 cache → YARA/ClamAV/oletools → hash reputation → detonation (`ENVELOCK_DETONATION_ENABLED=false` by default, v1.2)
- Domains: CT logs → CZDS zone files → RDAP → paid NRD feed
- URLs: Google Safe Browsing (free) → URLhaus → paid

> **Licensing is a legal exposure, not just a cost question.** Several "free" feeds
> prohibit commercial use — Spamhaus especially. Audit the terms before enabling any
> feed in production.

**Polling strategy is matched to mailbox class.** `PROTECTED` mailboxes hold an IMAP IDLE
connection because quarantine latency is the product. `MONITORED` mailboxes poll every 15
minutes, which needs no persistent connection, so the per-egress-IP concurrency ceiling
stops binding.

This is what makes whole-domain coverage affordable. Both paths must exist from the
start — retrofitting polling into an IDLE-only broker means rewriting it.

> `ENVELOCK_IMAP_MAX_CONNECTIONS_PER_EGRESS_IP` defaults to a conservative 15.
> **Measure the real limit per provider** (HiNet, 263, SingNet) during the Tier 3 build.
> It is the dominant Tier 3 cost driver and it is set by provider policy, not by our
> efficiency.

---

## Security requirements

This service holds mail access — and on Tier 3, **mailbox passwords** — for many
businesses. That makes us a supply-chain target (PRD §11.1). Non-negotiable:

- **Tenant mail credentials are envelope-encrypted** with a KMS/HSM-backed key. `ENVELOCK_CREDENTIAL_MASTER_KEY` as a literal is for local development only; production must use `ENVELOCK_KMS_KEY_ID`. The app refuses to start in production without one of them.
- **Credentials are decrypted only inside the connection broker**, never in the API process, and never appear in logs or error traces.
- **Multi-tenant isolation from commit one** — Postgres row-level security, `tenant_id` on every event, no exceptions. Retrofitting tenancy is a rewrite.
- **Never log message bodies.** Metadata-only mode (E13) must remain a supported path, both for regulated customers and because it is meaningfully cheaper to serve.

---

## Build order

Everything in PRD §9 is v1. Current state:

**Complete**

| Area | Modules |
|---|---|
| Event schema + capability model | `core/` — the normaliser every source emits into |
| Persistence | `models.py`, `db.py`, `types.py`, `migrations/` (Alembic + Postgres RLS) |
| Detections — all 37 in groups A/B/C | `detections/` — impersonation, content, sessions, identity |
| Attachment + URL cascades | `detections/cascade.py` |
| Group D brand protection | `channels/external/` — lookalike, DMARC posture, RDAP, takedown |
| Group E platform | `platform/` — alerts, escalation, graph, remediation, pipeline |
| Channel 1 | `channels/mail/` — parser, IMAP broker (IDLE + poll), providers, ingest |
| Channel 3 workers | `workers/watchers.py` — CT logs, zone files, RDAP, DMARC RUA |
| Notification ladder | `notify/` — L0 in-app, L1 push, L2 SMTP, L3 SMS |
| Auth, retention, export, quality | `auth/`, `governance/` |
| API | `api/` — auth, tenants, channels, governance, v1 |
| Tests | 127, covering unit, pipeline and full HTTP journeys |

**Remaining before production**

1. Replace the in-memory user store in `api/auth.py` with the `users` table — the interface is already isolated.
2. Live provider I/O: the Graph/Gmail/IMAP adapters normalise correctly and are tested, but the network calls inside `fetch()` are not wired.
3. Bind the SMTP listener (`aiosmtpd`) to `ForwardingIngest` — the transport-agnostic core is done and tested.
4. Run the CT-log and CZDS workers as processes; the matching logic is tested against injected streams.
5. Real detonation and reputation providers behind `cascade._reputation` / `_detonate`.
6. Web Push and SMS transport calls inside `notify/senders.py`.

Each of those is an I/O edge behind an interface that is already exercised by
tests — the shape is fixed, only the socket is missing.

## Verifying it works

```bash
pytest                                        # 127 tests
ruff check src tests
alembic upgrade head                          # Postgres schema + RLS
```

The system runs on SQLite with no Docker:

```bash
ENVELOCK_POSTGRES_DSN="sqlite+aiosqlite:///./envelock.db" \
  uvicorn envelock.main:app --app-dir src --port 8010
```

End-to-end, using only the HTTP API:

```bash
# register -> MFA -> tenant -> mailbox -> ingest mail -> alert -> acknowledge
POST /api/v1/auth/register
POST /api/v1/auth/login        -> mfa_token (never an access token)
POST /api/v1/auth/mfa/setup    -> TOTP secret
POST /api/v1/auth/mfa/verify   -> access_token + recovery codes
POST /api/v1/tenants/bootstrap
POST /api/v1/mailboxes
POST /api/v1/ingest            x3 ordinary invoices  (vendor + account learned)
POST /api/v1/ingest            the bank-change fraud -> CRITICAL alert
GET  /api/v1/alerts            -> persisted, with the callback number on file
POST /api/v1/alerts/{id}/acknowledge
GET  /api/v1/audit             -> who raised, who acknowledged
POST /api/v1/simulate          -> 4/4 detected
```
