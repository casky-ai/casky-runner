#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in

  run)
    # casky run <skill-subdomain> [--agent claude|gemini]
    SKILL="${1:-}"; shift || true
    AGENT="claude"
    while [[ $# -gt 0 ]]; do
      case "$1" in --agent) AGENT="$2"; shift 2 ;; *) shift ;; esac
    done

    [[ -z "$SKILL" ]] && { echo "Usage: casky run <skill> [--agent claude|gemini]"; exit 1; }

    SKILL_MD_PATH="/etc/casky/skills/${SKILL}.md"
    [[ ! -f "$SKILL_MD_PATH" ]] && { echo "Unknown skill: $SKILL"; exit 1; }

    REPORT_SECTION=""
    if [[ -n "${CASKY_RUN_ID:-}" && -n "${CASKY_TOKEN:-}" ]]; then
      REPORT_SECTION="
## Report your findings

POST ${CASKY_APP_URL:-https://app.casky.ai}/api/runs/${CASKY_RUN_ID}/report
Authorization: Bearer ${CASKY_TOKEN}
Content-Type: application/json

{
  \"findings\": [...],
  \"summary\": \"What you did and what you found\",
  \"raw_output\": \"Full terminal output\"
}"
    fi

    CONTAINER="${SKILL_LAB_NAME:-skill-lab}"

    PROMPT="$(cat "$SKILL_MD_PATH")

---

## Your environment

Two containers are running on the casky-lab Docker network:

- **Skill container** (${CONTAINER}): holds your security tools — image ghcr.io/casky-ai/skills/$(echo "$SKILL")
- **Target container** (target): holds the vulnerable application you will attack

Run every tool command through the skill container:
  docker exec ${CONTAINER} <command>

Examples:
  docker exec ${CONTAINER} nmap -sV target
  docker exec ${CONTAINER} curl -s http://target
  docker exec ${CONTAINER} bash -c 'cat /results/output.txt'

Do NOT enter either container interactively.
${REPORT_SECTION}"

    case "$AGENT" in
      claude)
        [[ -z "${ANTHROPIC_API_KEY:-}" ]] && { echo "Set ANTHROPIC_API_KEY first"; exit 1; }
        echo "$PROMPT" | claude --print
        ;;
      gemini)
        [[ -z "${GOOGLE_API_KEY:-}" && -z "${GEMINI_API_KEY:-}" ]] && \
          { echo "Set GOOGLE_API_KEY first"; exit 1; }
        echo "$PROMPT" | gemini
        ;;
      *) echo "Unknown agent: $AGENT (use claude or gemini)"; exit 1 ;;
    esac
    ;;

  verify)
    # casky verify <skill-subdomain>
    # Checks every tool listed in /etc/casky/skills/<skill>.tools is in skill-lab
    SKILL="${1:-}"
    [[ -z "$SKILL" ]] && { echo "Usage: casky verify <skill>"; exit 1; }
    TOOLS_FILE="/etc/casky/skills/${SKILL}.tools"
    [[ ! -f "$TOOLS_FILE" ]] && { echo "No .tools manifest for: $SKILL"; exit 1; }

    CONTAINER="${SKILL_LAB_NAME:-skill-lab}"
    PASS=0; FAIL=0
    while IFS= read -r tool; do
      [[ -z "$tool" || "$tool" == \#* ]] && continue
      if docker exec "$CONTAINER" which "$tool" >/dev/null 2>&1; then
        echo "  ✓ $tool"
        ((PASS++))
      else
        echo "  ✗ $tool — NOT FOUND"
        ((FAIL++))
      fi
    done < "$TOOLS_FILE"

    echo ""
    if [[ $FAIL -gt 0 ]]; then
      echo "FAIL: $FAIL tool(s) missing from $CONTAINER"
      exit 1
    fi
    echo "PASS: all $PASS tools present in $CONTAINER ($SKILL)"
    ;;

  help|*)
    echo "casky — Casky skill runner"
    echo ""
    echo "Commands:"
    echo "  casky run <skill> [--agent claude|gemini]   Run a skill exercise"
    echo "  casky verify <skill>                         Check skill container has required tools"
    echo ""
    echo "Env vars:"
    echo "  ANTHROPIC_API_KEY    for Claude Code"
    echo "  GOOGLE_API_KEY       for Gemini CLI"
    echo "  CASKY_RUN_ID         link run to Casky platform (optional)"
    echo "  CASKY_TOKEN          sandbox JWT for findings reporting (optional)"
    echo "  SKILL_LAB_NAME       skill-lab container name (default: skill-lab)"
    ;;
esac
