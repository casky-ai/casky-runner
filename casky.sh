#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in

  run)
    # casky run <skill-category> [--agent claude|gemini]
    #
    # <skill-category> is one of the 18 skill image categories (web-app, forensics, …).
    # The actual skill prompt (from the 753-skill registry) is read from stdin —
    # paste the SKILL.md content, then press Ctrl+D.
    CATEGORY="${1:-}"; shift || true
    AGENT="claude"
    while [[ $# -gt 0 ]]; do
      case "$1" in --agent) AGENT="$2"; shift 2 ;; *) shift ;; esac
    done

    [[ -z "$CATEGORY" ]] && { echo "Usage: casky run <category> [--agent claude|gemini]"; exit 1; }

    CONTAINER="${SKILL_LAB_NAME:-skill-lab}"

    # Read the skill prompt from stdin (user pastes SKILL.md from the registry).
    if [[ -t 0 ]]; then
      echo "Paste your skill prompt below, then press Ctrl+D:" >&2
      echo "" >&2
    fi
    SKILL_PROMPT="$(cat)"

    [[ -z "$SKILL_PROMPT" ]] && { echo "No prompt received on stdin. Aborting."; exit 1; }

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

    PROMPT="${SKILL_PROMPT}

---

## Your environment

Two containers are running on the casky-lab Docker network:

- **Skill container** (${CONTAINER}): image ghcr.io/casky-ai/skills/${CATEGORY} — your security tools
- **Target container** (target): the vulnerable application you will attack

Run every tool command through the skill container:
  docker exec ${CONTAINER} <command>

Examples:
  docker exec ${CONTAINER} nmap -sV target
  docker exec ${CONTAINER} curl -s http://target
  docker exec ${CONTAINER} bash -c 'cat /results/output.txt'

Do NOT enter either container interactively.${REPORT_SECTION}"

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
    # casky verify <skill-category>
    # Checks every tool in /etc/casky/skills/<category>.tools exists in the skill container.
    CATEGORY="${1:-}"
    [[ -z "$CATEGORY" ]] && { echo "Usage: casky verify <category>"; exit 1; }
    TOOLS_FILE="/etc/casky/skills/${CATEGORY}.tools"
    [[ ! -f "$TOOLS_FILE" ]] && { echo "No .tools manifest for: $CATEGORY"; exit 1; }

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
    echo "PASS: all $PASS tools present in $CONTAINER ($CATEGORY)"
    ;;

  help|*)
    echo "casky — Casky skill runner"
    echo ""
    echo "Commands:"
    echo "  casky run <category> [--agent claude|gemini]"
    echo "      Run a skill exercise. <category> is the skill image category"
    echo "      (web-app, forensics, network, …). Paste the SKILL.md prompt on stdin."
    echo ""
    echo "  casky verify <category>"
    echo "      Check the skill container has all required tools for <category>."
    echo ""
    echo "Skill image categories:"
    echo "  forensics  malware  threat-intel  threat-hunting  network  cloud"
    echo "  web-app    vuln-scan  exploitation  post-exploit  incident-response"
    echo "  detection  osint  recon  identity  active-directory  appsec  devsecops"
    echo ""
    echo "Env vars:"
    echo "  ANTHROPIC_API_KEY    for Claude Code"
    echo "  GOOGLE_API_KEY       for Gemini CLI"
    echo "  SKILL_LAB_NAME       skill container name (default: skill-lab)"
    echo "  CASKY_RUN_ID         link run to Casky platform (optional)"
    echo "  CASKY_TOKEN          sandbox JWT for findings reporting (optional)"
    ;;
esac
