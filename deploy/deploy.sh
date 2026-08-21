#!/usr/bin/env bash
# Envelock deploy: pull latest from GitHub for all three repos, rebuild, restart.
#
# The important addition over a plain pull-and-restart is the PREFLIGHT: the new
# server code is imported and its settings are constructed *before* the running
# API is touched. A config error — the class of bug that takes the API down for
# every customer at once — is caught while the old process is still serving.
set -euo pipefail

APPS="/home/ubuntu/apps"
API_BASE="https://api.envelock.org"   # baked into the client build
API_UNIT="envelock-api"
WORKER_UNIT="envelock-worker"         # only exists once key custody is split

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31m!!  %s\033[0m\n' "$*" >&2; exit 1; }

pull() {                              # $1 = repo dir
  local dir="$1" br before after
  br="$(git -C "$dir" rev-parse --abbrev-ref HEAD)"
  before="$(git -C "$dir" rev-parse HEAD)"
  log "$(basename "$dir"): pulling origin/$br"
  # Refuse to deploy on top of uncommitted work: it is either someone debugging
  # on the box (whose changes this would blow away) or a half-finished edit.
  git -C "$dir" diff --quiet || fail "$(basename "$dir") has uncommitted changes — commit or stash first"
  git -C "$dir" pull --ff-only origin "$br"
  after="$(git -C "$dir" rev-parse HEAD)"
  [ "$before" = "$after" ] && echo "   (already up to date)" || echo "   ${before:0:7} → ${after:0:7}"
}

# ---- 1. Server (API) ----
pull "$APPS/server"
log "server: installing deps"
( cd "$APPS/server" && ./.venv/bin/pip install -q . )

log "server: preflight (import + settings + routes)"
# Run it exactly as systemd will — same working directory, same env file — so a
# missing or malformed setting fails here rather than after the restart.
(
  cd "$APPS/server"
  set -a; [ -f .env ] && . ./.env; set +a
  ./.venv/bin/python - <<'PY'
import sys

try:
    from envelock.config import get_settings

    settings = get_settings()          # the production validator runs here
    from envelock.main import app      # every router imports here

    from envelock.security.keys import custody_summary

    custody = custody_summary()
    routes = len(app.openapi()["paths"])
except RecursionError:
    sys.exit("preflight: settings recursed — a validator is re-entering Settings()")
except Exception as exc:
    sys.exit(f"preflight: {type(exc).__name__}: {exc}")

if not custody["ok"]:
    sys.exit(f"preflight: credential key custody unusable — {custody.get('error')}")

print(f"    env={settings.env}  routes={routes}  key custody={custody['key_id']}")
if custody["mode"] == "local" and settings.env == "production":
    print("    WARNING: mailbox passwords are wrapped with a key in an environment")
    print("             variable, readable by this web process. See deploy/README.md.")
PY
) || fail "server preflight failed — NOT restarting; the old build is still serving"

# ---- 2. Client ----
pull "$APPS/client"
# The client has no hardcoded API host: an absent env file means same-origin,
# which would 404 against the static host. Write it before every build.
printf 'VITE_API_BASE_URL=%s\n' "$API_BASE" > "$APPS/client/.env.production"
log "client: building"
( cd "$APPS/client" && { npm ci || npm install; } && npm run build )
[ -f "$APPS/client/dist/index.html" ] || fail "client build produced no index.html"
grep -q "$API_BASE" "$APPS/client"/dist/assets/*.js \
  || fail "client bundle does not reference $API_BASE — the env file was not picked up"

# ---- 3. Admin ----
pull "$APPS/admin"
log "admin: building"
( cd "$APPS/admin" && { npm ci || npm install; } && npm run build )
[ -f "$APPS/admin/dist/index.html" ] || fail "admin build produced no index.html"

# ---- 4. Publish + restart ----
log "making builds readable by nginx + restarting the API"
chmod -R a+rX "$APPS/client/dist" "$APPS/admin/dist"
sudo systemctl restart "$API_UNIT"
# The worker only exists on a split-custody deployment; restart it if it is there.
if systemctl list-unit-files | grep -q "^${WORKER_UNIT}.service"; then
  sudo systemctl restart "$WORKER_UNIT"
fi

# ---- 5. Verify ----
log "health check"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 5 localhost:8010/health >/dev/null 2>&1; then
    curl -fsS localhost:8010/health && echo
    break
  fi
  [ "$attempt" = 10 ] && fail "API did not come up — sudo journalctl -u $API_UNIT -n 50 --no-pager"
  sleep 2
done

# The static sites are served by nginx, not the API, so check them separately —
# a perfectly healthy API with a broken vhost is still an outage for customers.
for host in app.envelock.org admin.envelock.org; do
  code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 "https://$host/" || echo failed)"
  [ "$code" = 200 ] && echo "    $host  ok" || echo "    $host  $code  <-- check nginx"
done
# And the one thing that is easy to get wrong: the admin console calls /api on
# its OWN origin, so this proxy has to work or the console is dead on arrival.
code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 https://admin.envelock.org/api/v1/admin/whoami || true)"
[ "$code" = 404 ] || [ "$code" = 401 ] \
  && echo "    admin /api proxy  ok (auth gate answered $code)" \
  || echo "    admin /api proxy  $code  <-- nginx is not proxying /api to the API"

log "deploy complete."
