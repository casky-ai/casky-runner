#!/usr/bin/env bash
# Casky Box — docker-compose integration test
#
# Tests the full stack (runner + db) and optionally the lab profile.
# Reads credentials from .env.local (copy .env.example → .env.local first).
#
# Usage:
#   ./tests/compose-test.sh              # core services only
#   ./tests/compose-test.sh --lab        # core + lab profile (skill-lab + target)
#   ./tests/compose-test.sh --no-pull    # skip docker pull (use cached images)
#
# Prerequisites: docker, docker compose, curl
set -euo pipefail

# ── args ──────────────────────────────────────────────────────────────────────
RUN_LAB=false
PULL=true
for arg in "$@"; do
  case "$arg" in
    --lab)     RUN_LAB=true ;;
    --no-pull) PULL=false ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env.local"

# ── colour helpers ─────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
section() { echo -e "\n${CYAN}${BOLD}--- $* ---${RESET}"; }
pass()    { echo -e "  ${GREEN}PASS${RESET}: $*"; PASS=$((PASS + 1)); }
fail()    { echo -e "  ${RED}FAIL${RESET}: $*"; FAIL=$((FAIL + 1)); }
PASS=0; FAIL=0

# ── pre-flight ────────────────────────────────────────────────────────────────
section "Pre-flight checks"

if [[ ! -f "$ENV_FILE" ]]; then
  echo -e "${RED}ERROR:${RESET} .env.local not found at $ENV_FILE"
  echo "  Copy .env.example → .env.local and fill in ANTHROPIC_API_KEY at minimum."
  exit 1
fi
pass ".env.local exists"

# Source .env.local so we can check for required keys
set -a; source "$ENV_FILE"; set +a

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo -e "${RED}ERROR:${RESET} ANTHROPIC_API_KEY is not set in .env.local"
  exit 1
fi
pass "ANTHROPIC_API_KEY is set"

for cmd in docker curl; do
  if command -v "$cmd" &>/dev/null; then pass "$cmd is in PATH"
  else echo -e "${RED}ERROR:${RESET} $cmd not found"; exit 1; fi
done

# ── setup / teardown ──────────────────────────────────────────────────────────
COMPOSE="docker compose --env-file $ENV_FILE -f $REPO_ROOT/docker-compose.yml"

cleanup() {
  echo -e "\n${BOLD}Cleaning up…${RESET}"
  $COMPOSE --profile lab down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── pull images ───────────────────────────────────────────────────────────────
section "Image pull"
if $PULL; then
  if $COMPOSE pull --quiet 2>&1 | grep -q "Error\|error"; then
    fail "docker compose pull reported errors"
  else
    pass "images pulled successfully"
  fi
else
  pass "skipped (--no-pull)"
fi

# ── start core services ───────────────────────────────────────────────────────
section "Core services start-up"

$COMPOSE up -d --wait 2>&1 | tail -5

# Give the runner a moment to finish entrypoint (MCP config write)
sleep 3

if $COMPOSE ps --format json 2>/dev/null | grep -q '"casky-runner"'; then
  pass "casky-runner container is up"
else
  # fallback for older compose versions
  if $COMPOSE ps | grep -q "casky-runner"; then
    pass "casky-runner container is up"
  else
    fail "casky-runner container did not start"
  fi
fi

# `docker compose ps` can lag the daemon's actual state by a second or two
# right after `up --wait` returns (observed: db already Running/Healthy per
# `docker inspect`, but the very next `compose ps` call still misses it) —
# retry briefly instead of failing on a single snapshot. `docker inspect`
# talks to the daemon directly rather than through compose's own state cache,
# so it's the more reliable check here.
DB_UP=false
for _ in 1 2 3 4 5; do
  if docker inspect casky-db --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    DB_UP=true
    break
  fi
  sleep 1
done
if $DB_UP; then
  pass "casky-db container is up"
else
  fail "casky-db container did not start"
fi

# ── runner: binary checks ─────────────────────────────────────────────────────
section "Runner — binaries"

exec_runner() { docker exec casky-runner "$@"; }

if exec_runner which claude &>/dev/null; then
  pass "claude CLI is in PATH"
else
  fail "claude CLI missing"
fi

if exec_runner which python3 &>/dev/null; then
  pass "python3 is in PATH"
else
  fail "python3 missing"
fi

if exec_runner which casky &>/dev/null; then
  pass "casky wrapper is in PATH"
else
  fail "casky wrapper missing"
fi

if exec_runner which docker &>/dev/null; then
  pass "docker CLI is in PATH"
else
  fail "docker CLI missing"
fi

# ── runner: CVE MCP registration ──────────────────────────────────────────────
section "Runner — CVE MCP registration"

MCP_CONFIG=$(exec_runner cat /home/casky/.claude/claude_desktop_config.json 2>/dev/null || echo "")

if echo "$MCP_CONFIG" | grep -q "casky-cve"; then
  pass "claude_desktop_config.json contains casky-cve server"
else
  fail "claude_desktop_config.json missing casky-cve entry"
  echo "    got: $MCP_CONFIG"
fi

if echo "$MCP_CONFIG" | grep -q '"/opt/cve-mcp/bin/python3"'; then
  pass "MCP server uses stdio transport (venv python3 command)"
else
  fail "MCP server not configured for stdio transport via venv"
fi

# Verify the cve_mcp module is importable via the venv Python
if exec_runner /opt/cve-mcp/bin/python3 -c "import cve_mcp.server" &>/dev/null; then
  pass "cve_mcp.server module is importable via venv"
else
  fail "cve_mcp.server module not found — venv pip install may have failed"
fi

# ── runner: docker socket access ──────────────────────────────────────────────
section "Runner — Docker socket access"

if exec_runner docker info &>/dev/null; then
  pass "runner can reach Docker daemon via socket"
else
  fail "runner cannot reach Docker daemon"
fi

# ── database: connectivity ────────────────────────────────────────────────────
section "Database — connectivity"

# Check pg_isready via the db container's healthcheck result
DB_STATUS=$(docker inspect casky-db --format '{{.State.Health.Status}}' 2>/dev/null || echo "unknown")
if [[ "$DB_STATUS" == "healthy" ]]; then
  pass "casky-db healthcheck is healthy"
else
  fail "casky-db healthcheck status: $DB_STATUS"
fi

# Runner should be able to reach the db on the internal network
if exec_runner bash -c "python3 -c \"import socket; s=socket.create_connection(('db',5432), timeout=5); s.close()\"" &>/dev/null; then
  pass "runner can connect to db:5432 on casky-internal network"
else
  fail "runner cannot reach db:5432"
fi

# ── runner: casky CLI smoke test ──────────────────────────────────────────────
section "Runner — casky CLI smoke test"

HELP_OUT=$(exec_runner casky help 2>&1 || true)

if echo "$HELP_OUT" | grep -q "casky run"; then
  pass "casky help lists 'run' command"
else
  fail "casky help output missing 'run' — output: $HELP_OUT"
fi

if echo "$HELP_OUT" | grep -q "casky harness"; then
  pass "casky help lists 'harness' command"
else
  fail "casky help output missing 'harness' — output: $HELP_OUT"
fi

if echo "$HELP_OUT" | grep -q "ANTHROPIC_API_KEY"; then
  pass "casky help mentions ANTHROPIC_API_KEY"
else
  fail "casky help does not mention ANTHROPIC_API_KEY"
fi

if echo "$HELP_OUT" | grep -q "CASKY_API_KEY"; then
  pass "casky help mentions CASKY_API_KEY"
else
  fail "casky help does not mention CASKY_API_KEY"
fi

# ── runner: harness binary checks ────────────────────────────────────────────
section "Runner — harness prerequisites"

if exec_runner /opt/casky-console/bin/python3 -c "import rich, requests" &>/dev/null; then
  pass "rich and requests are importable from harness venv"
else
  fail "rich or requests missing from /opt/casky-console venv"
fi

if exec_runner test -f /usr/local/bin/casky-harness &>/dev/null; then
  pass "casky-harness script is installed"
else
  fail "casky-harness script not found at /usr/local/bin/casky-harness"
fi

# ── runner: API key plumbing ──────────────────────────────────────────────────
section "Runner — environment variable plumbing"

RUNNER_KEY=$(exec_runner bash -c 'echo "${ANTHROPIC_API_KEY:-MISSING}"')
if [[ "$RUNNER_KEY" != "MISSING" && -n "$RUNNER_KEY" ]]; then
  pass "ANTHROPIC_API_KEY is available inside the runner container"
else
  fail "ANTHROPIC_API_KEY is not set inside the runner container"
fi

# ── optional: lab profile ─────────────────────────────────────────────────────
if $RUN_LAB; then
  section "Lab profile — skill-lab + target containers"

  $COMPOSE --profile lab up -d --wait 2>&1 | tail -5
  sleep 3

  if $COMPOSE ps | grep -q "skill-lab"; then
    pass "skill-lab container is up"
  else
    fail "skill-lab container did not start"
  fi

  if $COMPOSE ps | grep -q "casky-target"; then
    pass "casky-target container is up"
  else
    fail "casky-target container did not start"
  fi

  # skill-lab should be able to ping target on casky-lab network
  if docker exec skill-lab ping -c1 -W2 casky-target &>/dev/null; then
    pass "skill-lab can reach casky-target on casky-lab network"
  else
    fail "skill-lab cannot reach casky-target"
  fi

  # casky-lab network is internal — skill-lab should NOT reach the internet
  if docker exec skill-lab ping -c1 -W3 8.8.8.8 &>/dev/null; then
    fail "skill-lab has unexpected internet access (casky-lab network should be internal)"
  else
    pass "skill-lab is isolated from the internet (casky-lab network internal:true)"
  fi

  # Runner can exec into skill-lab via Docker socket
  if exec_runner docker exec skill-lab sh -c "echo ok" &>/dev/null; then
    pass "runner can exec into skill-lab via Docker socket"
  else
    fail "runner cannot exec into skill-lab"
  fi
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== Results ===${RESET}"
echo -e "  ${GREEN}PASS${RESET}: $PASS"
if [[ $FAIL -gt 0 ]]; then
  echo -e "  ${RED}FAIL${RESET}: $FAIL"
  exit 1
fi
echo -e "  ${RED}FAIL${RESET}: 0"
echo -e "\n${GREEN}${BOLD}All compose tests passed.${RESET}"
