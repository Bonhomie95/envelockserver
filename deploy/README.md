# Deploying Envelock on a single VPS

Three web surfaces and one API on one box:

| Host | Serves | Talks to the API by |
|---|---|---|
| `api.envelock.org` | the API directly | — |
| `app.envelock.org` | `client/dist` | `VITE_API_BASE_URL`, baked at build |
| `admin.envelock.org` | `admin/dist` | **same-origin `/api`, proxied by nginx** |

The admin console has no configurable API base — it calls `/api/...` relative to
wherever it is served. **Its nginx vhost must proxy `/api` to the API**, or the
console loads and every request 404s.

Files here:

- `nginx/*.conf` — one vhost per surface, with the security headers. The client's
  `vercel.json` headers do **nothing** on nginx; these are what actually apply.
- `envelock-api.service`, `envelock-worker.service` — systemd units. The worker
  unit only matters once you split credential key custody (see below).
- `deploy.sh` — pull, build, **preflight**, restart, verify.

## First-time setup

```bash
sudo cp deploy/nginx/*.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/envelock-{api,app,admin}.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.envelock.org -d app.envelock.org -d admin.envelock.org
```

## Splitting credential key custody (recommended before real customers)

By default one process seals *and* opens mailbox credentials, so a compromised
web process can read every stored password. To separate them:

1. `./.venv/bin/python -m envelock.security.keygen`
2. `envelock-api.service` gets **`ENVELOCK_CREDENTIAL_PUBLIC_KEY` only**.
3. `envelock-worker.service` gets **both keys**, and is the only process that
   polls mailboxes.
4. From the worker's environment:
   `./.venv/bin/python -m envelock.security.rotate_credentials --migrate`

Until step 4 has run, keep `ENVELOCK_CREDENTIAL_MASTER_KEY` set — removing it
before migrating makes every connected mailbox unreadable.

Note that the API process refuses to start its mailbox pollers when it holds no
decryption key, so step 2 without step 3 means **no mail is read at all**. Do
them together.
