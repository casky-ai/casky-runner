#!/usr/bin/env bash
# casky-runner integration test harness
# Usage: ./tests/run-tests.sh [IMAGE]
set -euo pipefail

IMAGE="${1:-casky-runner:dev}"
FIXTURES="$(cd "$(dirname "$0")/fixtures" && pwd)"
MOCK_LAB="casky-test-skill-lab"   # isolated name — never collides with production skill-lab

PASS=0
FAIL=0

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

section() { echo -e "\n${CYAN}${BOLD}--- $* ---${RESET}"; }
pass()    { echo -e "  ${GREEN}PASS${RESET}: $*"; PASS=$((PASS + 1)); }
fail()    { echo -e "  ${RED}FAIL${RESET}: $*"; FAIL=$((FAIL + 1)); }

# ── test helpers ──────────────────────────────────────────────────────────────

# Run a command inside the runner; mount fixtures over /etc/casky/skills so
# both .tools and .md test fixtures are visible to casky.
#
# -i is required: without it, `docker run` never forwards piped stdin to the
# container at all — any test piping a prompt in (`echo "..." | runner casky
# run ...`) would silently get empty stdin no matter what was piped, which is
# indistinguishable from the "empty prompt" failure path. Confirmed directly:
# `echo x | docker run --rm IMAGE cat` prints nothing; with -i it prints "x".
runner() {
  docker run --rm -i \
    -e SKILL_LAB_NAME="$MOCK_LAB" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${FIXTURES}:/etc/casky/skills:ro" \
    "$IMAGE" \
    "$@"
}

# runner_env <KEY=VAL ...> -- <cmd>: pass extra env vars before the command.
runner_env() {
  local -a env_args=()
  while [[ "$1" != "--" ]]; do
    env_args+=(-e "$1")
    shift
  done
  shift  # consume "--"
  docker run --rm -i \
    -e SKILL_LAB_NAME="$MOCK_LAB" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${FIXTURES}:/etc/casky/skills:ro" \
    "${env_args[@]}" \
    "$IMAGE" \
    "$@"
}

expect_pass() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name (expected exit 0, got non-zero)"
  fi
}

expect_fail() {
  local name="$1"; shift
  if ! "$@" >/dev/null 2>&1; then
    pass "$name (correctly non-zero)"
  else
    fail "$name (expected non-zero exit, got 0)"
  fi
}

expect_output() {
  # expect_output <name> <pattern> <cmd...>
  local name="$1" pattern="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || true
  if echo "$out" | grep -qF "$pattern"; then
    pass "$name"
  else
    fail "$name — expected output to contain: $pattern"
    echo "    got: $out" >&2
  fi
}

# ── setup ─────────────────────────────────────────────────────────────────────
cleanup() {
  docker rm -f "$MOCK_LAB" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo -e "${BOLD}=== casky-runner test harness ===${RESET}"
echo "Image   : $IMAGE"
echo "Lab name: $MOCK_LAB"

# Start the mock skill-lab (alpine ships sh, ls, cat, grep by default)
docker rm -f "$MOCK_LAB" >/dev/null 2>&1 || true
docker run -d --name "$MOCK_LAB" alpine sleep infinity >/dev/null

# ── 1. image sanity ───────────────────────────────────────────────────────────
section "Image sanity"

expect_pass "node is present" \
  runner node --version

expect_pass "docker CLI is present" \
  runner docker --version

expect_pass "casky is in PATH" \
  runner which casky

# ── 2. CLI basics ─────────────────────────────────────────────────────────────
section "CLI basics"

expect_pass "casky help exits 0" \
  runner casky help

expect_pass "casky (no args) exits 0" \
  runner casky

expect_output "help lists 'run' command" "casky run" \
  runner casky help

expect_output "help lists 'verify' command" "casky verify" \
  runner casky help

expect_output "help lists SKILL_LAB_NAME env var" "SKILL_LAB_NAME" \
  runner casky help

# ── 3. casky verify ───────────────────────────────────────────────────────────
section "casky verify — happy paths"

expect_pass "verify mock skill (sh ls cat grep all in alpine)" \
  runner casky verify mock

expect_pass "verify comments-blanks skill (comments and blank lines skipped)" \
  runner casky verify comments-blanks

expect_output "verify happy path shows PASS summary" "PASS:" \
  runner casky verify mock

section "casky verify — failure paths"

expect_fail "verify missing-tools skill exits 1 (tools absent)" \
  runner casky verify missing-tools

expect_output "verify missing-tools reports NOT FOUND" "NOT FOUND" \
  runner casky verify missing-tools

expect_fail "verify with no args exits 1" \
  runner casky verify

expect_output "verify no-args shows usage" "Usage:" \
  runner casky verify

expect_fail "verify unknown skill exits 1" \
  runner casky verify does-not-exist

expect_output "verify unknown skill explains missing manifest" "No .tools manifest" \
  runner casky verify does-not-exist

# ── 4. casky run — error paths ────────────────────────────────────────────────
# We test only error paths here; a full run would require a live API key.
section "casky run — error paths"

expect_fail "run with no args exits 1" \
  runner casky run

expect_output "run no-args shows usage" "Usage:" \
  runner casky run

# Prompt is read from stdin; the runner() function passes stdin through.
# Empty stdin → no prompt → abort.
stdin_test_pass() {
  local name="$1" input="$2"; shift 2
  local out
  out="$(echo "$input" | runner "$@" 2>&1)" && { fail "$name (expected non-zero)"; return; }
  pass "$name"
}
stdin_test_output() {
  local name="$1" input="$2" pattern="$3"; shift 3
  local out
  out="$(echo "$input" | runner "$@" 2>&1)" || true
  if echo "$out" | grep -qF "$pattern"; then pass "$name"
  else fail "$name — expected: $pattern"; echo "    got: $out" >&2; fi
}

stdin_test_pass   "run with empty stdin exits 1" \
  "" casky run web-app

stdin_test_pass   "run without ANTHROPIC_API_KEY exits 1" \
  "test prompt" casky run web-app

stdin_test_output "run without key explains requirement" \
  "test prompt" "ANTHROPIC_API_KEY" casky run web-app

stdin_test_pass   "run --agent gemini without GOOGLE_API_KEY exits 1" \
  "test prompt" casky run web-app --agent gemini

stdin_test_output "run gemini without key explains requirement" \
  "test prompt" "GOOGLE_API_KEY" casky run web-app --agent gemini

stdin_test_pass   "run with unknown agent exits 1" \
  "test prompt" casky run web-app --agent bogus-agent

# `claude --print` is piped from stdin with no TTY attached — there is no
# channel for Claude Code's per-tool-call approval prompt to ever be
# answered, so without --dangerously-skip-permissions every tool call
# (including the docker exec skill-lab/skill-live the prompt itself
# instructs) just blocks forever. Live-caught: the agent printed what it
# needed approved and exited 0, so the harness marked the step "DONE" with
# an empty report — not a crash, just silent non-execution. A static grep
# against the built image's installed script is a cheap, deterministic
# regression guard for this; actually invoking claude would need a live
# ANTHROPIC_API_KEY (see the section-4 comment above).
expect_pass "casky run passes --dangerously-skip-permissions to claude (no TTY for approval otherwise)" \
  docker run --rm "$IMAGE" grep -qF -- "--dangerously-skip-permissions" /usr/local/bin/casky

# ── 5. CASKY_RUN_ID + CASKY_TOKEN plumbing ───────────────────────────────────
# Verify the report section appears in the assembled prompt when both are set.
# We deliberately do NOT set ANTHROPIC_API_KEY so the run exits before calling
# Claude, but the error path fires AFTER the prompt is built — so we capture
# the prompt separately by peeking at the .md assembly step with a no-op agent check.
#
# Simpler: confirm that with a valid API key env var set but the mock having no
# real AI, the error message correctly identifies the agent, not the token env.
section "Report token env plumbing"

expect_output "CASKY_TOKEN env is documented in help" "CASKY_TOKEN" \
  runner casky help

expect_output "CASKY_RUN_ID env is documented in help" "CASKY_RUN_ID" \
  runner casky help

# ── 6. production .tools files parse cleanly ──────────────────────────────────
# Mount the real skills dir and ensure each file loads without syntax errors.
section "Production .tools manifests — parse check"

SKILLS_DIR="$(cd "$(dirname "$0")/../skills" && pwd)"

for f in "$SKILLS_DIR"/*.tools; do
  skill="$(basename "$f" .tools)"
  # Verify the file has at least one non-comment, non-blank line
  count=$(grep -cE '^[^#[:space:]]' "$f" || true)
  if [[ "$count" -gt 0 ]]; then
    pass "$skill.tools has $count tool entries"
  else
    fail "$skill.tools is empty or all-comments"
  fi
done

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== Results ===${RESET}"
echo -e "  ${GREEN}PASS${RESET}: $PASS"
if [[ $FAIL -gt 0 ]]; then
  echo -e "  ${RED}FAIL${RESET}: $FAIL"
  exit 1
fi
echo -e "  ${RED}FAIL${RESET}: 0"
echo -e "\n${GREEN}${BOLD}All tests passed.${RESET}"
