#!/usr/bin/env bash
# casky-runner-phase1 smoke test — the checks worth running consistently
# before every push. Two tiers:
#
#   ./scripts/smoke-test.sh          Fast tier (default): Python unit tests
#                                     (casky_pipeline + casky_db, DB-dependent
#                                     ones skip cleanly with no Postgres),
#                                     casky-ui unit tests, typecheck, build.
#                                     No Docker required. Safe to run often.
#
#   ./scripts/smoke-test.sh --full   Everything above, PLUS the real
#                                     end-to-end chain: spin up a throwaway
#                                     Postgres, run casky_db's migrations,
#                                     seed one investigation via
#                                     casky_db.store (the same write path
#                                     harness.py uses), start casky-ui's real
#                                     production server against it, and curl
#                                     authenticated pages to prove the seeded
#                                     data actually renders. Requires Docker.
#
# The --full tier is fully isolated from any real casky-db data: it runs a
# dedicated `docker run --rm` Postgres container with no named volume, on a
# separate port — it never touches the docker-compose `db` service or the
# `casky-box_casky-db-data` volume a real deployment's investigations live
# in. Always torn down via a trap, pass or fail.
#
# Mirrors the style/conventions of tests/run-tests.sh (colored PASS/FAIL,
# a running scorecard) and of claude-skills-security/scripts/smoke-test.sh
# (the sibling closed-repo harness) on purpose.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FULL=false
for arg in "$@"; do
  case "$arg" in
    --full) FULL=true ;;
    *) echo "Unknown flag: $arg (usage: $0 [--full])" >&2; exit 2 ;;
  esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PASS=0
FAIL=0
FAILED_STEPS=()

section() { echo -e "\n${CYAN}${BOLD}--- $* ---${RESET}"; }

# run <label> <dir> <command...> — same segfault-tolerant runner as the
# sibling repo's script (see its comment) — this machine has shown the same
# occasional npx/node subprocess segfault unrelated to code correctness.
run() {
  local label="$1" dir="$2"; shift 2
  section "$label"
  local attempt=1 status=0
  while :; do
    if (cd "$ROOT/$dir" && "$@"); then
      status=0
    else
      status=$?
    fi
    if [ "$status" -eq 139 ] && [ "$attempt" -eq 1 ]; then
      echo -e "${RED}(segfault — retrying once, not code-related)${RESET}"
      attempt=2
      continue
    fi
    break
  done
  if [ "$status" -eq 0 ]; then
    echo -e "${GREEN}PASS${RESET}: $label"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${RESET}: $label"
    FAIL=$((FAIL + 1))
    FAILED_STEPS+=("$label")
  fi
}

echo "casky-runner-phase1 smoke test — $(date -u +%Y-%m-%dT%H:%M:%SZ) $([ "$FULL" = true ] && echo "(--full)")"

# ── Fast tier ───────────────────────────────────────────────────────────

run "casky_pipeline + casky_db — pytest" . bash -c '
  if [ ! -d .venv ]; then
    python3 -m venv .venv
    .venv/bin/pip install --quiet pytest pytest-asyncio anthropic requests pyyaml rich mcp "psycopg[binary]"
  fi
  unset DATABASE_URL
  .venv/bin/python -m pytest casky_pipeline/tests/ casky_db/tests/ -q
'

run "casky-ui — vitest"       casky-ui npx vitest run
run "casky-ui — tsc --noEmit" casky-ui npx tsc --noEmit -p tsconfig.json
run "casky-ui — next build"   casky-ui npm run build

# ── Full tier (--full only) ─────────────────────────────────────────────

if [ "$FULL" = true ]; then
  SMOKE_DB_CONTAINER="casky-smoke-db-$$"
  SMOKE_DB_PORT="${SMOKE_DB_PORT:-55499}"
  SMOKE_UI_PORT="${SMOKE_UI_PORT:-4599}"
  SMOKE_DB_PASSWORD="smoketest"
  UI_PID=""

  cleanup() {
    section "Cleanup"
    [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null
    # Belt-and-suspenders: also kill by port, in case $UI_PID isn't the
    # actual bound process (e.g. it forked) — never leave a smoke-test
    # server listening after this script exits.
    PORT_PID="$(lsof -tiTCP:"${SMOKE_UI_PORT:-4599}" -sTCP:LISTEN 2>/dev/null)"
    [ -n "$PORT_PID" ] && kill -9 $PORT_PID 2>/dev/null
    docker rm -f "$SMOKE_DB_CONTAINER" >/dev/null 2>&1
    rm -f /tmp/casky-ui-smoke-"$$".log /tmp/casky-ui-smoke-"$$".pid
    echo "  torn down: $SMOKE_DB_CONTAINER, casky-ui smoke server"
  }
  trap cleanup EXIT

  section "Full tier — starting isolated Postgres ($SMOKE_DB_CONTAINER)"
  docker run --rm -d --name "$SMOKE_DB_CONTAINER" \
    -e POSTGRES_DB=casky -e POSTGRES_USER=casky -e POSTGRES_PASSWORD="$SMOKE_DB_PASSWORD" \
    -p "127.0.0.1:${SMOKE_DB_PORT}:5432" \
    postgres:16-alpine >/dev/null
  export DATABASE_URL="postgresql://casky:${SMOKE_DB_PASSWORD}@localhost:${SMOKE_DB_PORT}/casky"

  echo -n "  waiting for Postgres to accept connections"
  for _ in $(seq 1 30); do
    docker exec "$SMOKE_DB_CONTAINER" pg_isready -U casky >/dev/null 2>&1 && break
    echo -n "."; sleep 1
  done
  echo ""

  run "full — casky_db migrations" . .venv/bin/python -m casky_db.migrate

  section "full — seed one investigation"
  # PYTHONPATH=. — `python scripts/seed_....py` (a script file, not `-m`)
  # only auto-adds scripts/ itself to sys.path, not the repo root, so
  # casky_db wouldn't otherwise be importable (same reason the Docker image
  # sets PYTHONPATH=/opt/casky-console/lib — see Dockerfile).
  SEED_ID="$(PYTHONPATH=. .venv/bin/python scripts/seed_smoke_investigation.py)"
  if [ -n "$SEED_ID" ]; then
    echo -e "${GREEN}PASS${RESET}: full — seed one investigation ($SEED_ID)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${RESET}: full — seed one investigation"
    FAIL=$((FAIL + 1)); FAILED_STEPS+=("full — seed one investigation")
  fi

  section "full — start casky-ui (production server)"
  UI_LOG="/tmp/casky-ui-smoke-$$.log"
  cp -r casky-ui/.next/static casky-ui/.next/standalone/.next/static 2>/dev/null

  # Free SMOKE_UI_PORT of any stale process first — a curl response alone
  # doesn't prove it's *this run's* server (a leftover process from an
  # earlier, unrelated run holding the same port would answer too, against
  # a different/dead database, and every content check below would then
  # fail confusingly). Kill anything on the port, then confirm the new
  # process's own log — not just "curl got a response" — says it's ready.
  STALE_PID="$(lsof -tiTCP:"$SMOKE_UI_PORT" -sTCP:LISTEN 2>/dev/null)"
  if [ -n "$STALE_PID" ]; then
    echo "  killing stale process(es) already on port $SMOKE_UI_PORT: $STALE_PID"
    kill -9 $STALE_PID 2>/dev/null
    sleep 1
  fi

  ( cd casky-ui && \
    CASKY_UI_ADMIN_PASSWORD="smoketest123" PORT="$SMOKE_UI_PORT" HOSTNAME=127.0.0.1 \
    node .next/standalone/server.js > "$UI_LOG" 2>&1 & echo $! > /tmp/casky-ui-smoke-"$$".pid )
  UI_PID="$(cat /tmp/casky-ui-smoke-"$$".pid 2>/dev/null)"
  echo -n "  waiting for casky-ui to be ready"
  UI_READY=false
  for _ in $(seq 1 20); do
    if grep -q "Ready in" "$UI_LOG" 2>/dev/null; then
      UI_READY=true
      break
    fi
    echo -n "."; sleep 0.5
  done
  echo ""
  if [ "$UI_READY" = false ]; then
    echo -e "${RED}casky-ui did not report ready — log:${RESET}"
    cat "$UI_LOG" 2>/dev/null
  fi

  # createSessionToken() throws until instrumentation.ts's ensureAdminBootstrap()
  # has actually persisted a session secret to runtime_settings — that runs
  # async on server boot, so it can still be in flight right after /login
  # first starts responding. Retry a few times rather than racing it.
  TOKEN=""
  for _ in $(seq 1 10); do
    TOKEN="$(cd casky-ui && npx tsx -e "
      import('./lib/auth.ts').then(async (auth) => {
        process.stdout.write(await auth.createSessionToken());
        process.exit(0);
      }).catch(() => process.exit(1));
    ")"
    [ -n "$TOKEN" ] && break
    sleep 0.5
  done

  check_page() {
    local label="$1" url="$2" want="$3"
    section "full — $label"
    local body
    body="$(curl -s -H "Cookie: casky_ui_session=${TOKEN}" "$url")"
    if echo "$body" | grep -qF "$want"; then
      echo -e "${GREEN}PASS${RESET}: full — $label"
      PASS=$((PASS + 1))
    else
      echo -e "${RED}FAIL${RESET}: full — $label (did not find: $want)"
      FAIL=$((FAIL + 1)); FAILED_STEPS+=("full — $label")
    fi
  }

  check_page "dashboard renders"            "http://127.0.0.1:${SMOKE_UI_PORT}/"                                    "Dashboard"
  check_page "investigation overview tab"   "http://127.0.0.1:${SMOKE_UI_PORT}/investigations/${SEED_ID}?tab=overview" "Confirmed unauthorized EC2 stop"
  check_page "findings tab"                 "http://127.0.0.1:${SMOKE_UI_PORT}/investigations/${SEED_ID}?tab=findings" "Unusual EC2 StopInstances"
  check_page "outcome/memory tab — memory"  "http://127.0.0.1:${SMOKE_UI_PORT}/investigations/${SEED_ID}?tab=outcome"  "warrants escalation unless a change ticket exists"
fi

# ── Summary ───────────────────────────────────────────────────────────────

section "Summary"
echo -e "  ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"
if [ "$FAIL" -gt 0 ]; then
  echo "  Failed steps:"
  for step in "${FAILED_STEPS[@]}"; do
    echo -e "    ${RED}✗${RESET} $step"
  done
  exit 1
fi
echo -e "  ${GREEN}${BOLD}All smoke checks passed.${RESET}"
