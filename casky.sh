#!/usr/bin/env bash
set -euo pipefail

# The image intentionally has no baked-in `USER` directive (see entrypoint.sh
# for why — the docker.sock GID varies by platform and has to be fixed up at
# runtime). That means `docker exec` into a running container — the primary
# documented way to use `casky run` interactively — defaults to root, even
# though the container's own main process already dropped to the non-root
# 'casky' user via entrypoint.sh. Mirror that same drop here, so every path
# into this script (docker run, docker exec, or entrypoint's own re-exec)
# ends up running as 'casky' consistently, not just the container's PID 1.
if [[ "$(id -u)" == "0" ]] && id casky &>/dev/null; then
  exec su casky -c "$(printf '%q ' "$0" "$@")"
fi

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in

  run)
    # casky run <skill-category> [--agent claude|gemini] [--live-target <host|url> --i-have-authorization]
    #
    # <skill-category> is one of the 18 skill image categories (web-app, forensics, …).
    # The actual skill prompt (from the 753-skill registry) is read from stdin —
    # paste the SKILL.md content, then press Ctrl+D.
    #
    # --live-target switches from the sandboxed lab (skill-lab, no internet egress) to
    # skill-live (real internet egress, see docker-compose.yml) — only for a real,
    # authorized target. Requires --i-have-authorization every time; see README's
    # "Live, authorized real-target investigations" section and SECURITY.md.
    CATEGORY="${1:-}"; shift || true
    AGENT="claude"
    AGENT_CMD=""
    LIVE_TARGET=""
    I_HAVE_AUTHORIZATION=false
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --agent) AGENT="$2"; shift 2 ;;
        --agent-cmd) AGENT_CMD="$2"; shift 2 ;;
        --live-target) LIVE_TARGET="$2"; shift 2 ;;
        --i-have-authorization) I_HAVE_AUTHORIZATION=true; shift ;;
        *) shift ;;
      esac
    done

    [[ -z "$CATEGORY" ]] && { echo "Usage: casky run <category> [--agent claude|gemini|copilot|custom] [--agent-cmd \"<binary>\"] [--live-target <host|url> --i-have-authorization]"; exit 1; }

    if [[ -n "$LIVE_TARGET" && "$I_HAVE_AUTHORIZATION" != true ]]; then
      echo "--live-target requires --i-have-authorization." >&2
      echo "Live-target mode runs real security tools against a real system with real internet" >&2
      echo "egress (skill-live, not the sandboxed skill-lab). Only use this against" >&2
      echo "infrastructure you have explicit authorization to test — see SECURITY.md." >&2
      echo "" >&2
      echo "Usage: casky run $CATEGORY --live-target $LIVE_TARGET --i-have-authorization" >&2
      exit 1
    fi

    if [[ -n "$LIVE_TARGET" ]]; then
      CONTAINER="${SKILL_LIVE_NAME:-skill-live}"
    else
      CONTAINER="${SKILL_LAB_NAME:-skill-lab}"
    fi

    # Read the skill prompt from stdin (user pastes SKILL.md from the registry).
    #
    # Ctrl+D alone is ambiguous when reading pasted multi-line text on a real
    # terminal: canonical-mode TTYs only treat it as true EOF when pressed on
    # an EMPTY line. Pasted text that doesn't end with a trailing newline
    # (the common case — copying from an editor/browser) means the first
    # Ctrl+D just flushes the last partial line instead of ending input; a
    # second Ctrl+D on the now-empty line is what actually finishes it. That
    # looks exactly like "nothing happens" from the user's side. Fix: accept
    # an explicit "END" sentinel line instead of relying solely on EOF
    # signaling — same fix applied to `casky harness`'s evidence entry step.
    if [[ -t 0 ]]; then
      echo "Paste your skill prompt below. When done, type END alone on its own line and press Enter (or press Ctrl+D):" >&2
      echo "" >&2
    fi
    SKILL_PROMPT=""
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" == "END" ]] && break
      SKILL_PROMPT+="${line}"$'\n'
    done

    [[ -z "$SKILL_PROMPT" ]] && { echo "No prompt received on stdin. Aborting."; exit 1; }

    REPORT_SECTION=""
    if [[ -n "${CASKY_RUN_ID:-}" && -n "${CASKY_TOKEN:-}" ]]; then
      REPORT_SECTION="

---

## Submit your findings

When done, run this curl command (replace [...] with your findings):

\`\`\`bash
curl -s -X POST \\
  -H 'Authorization: Bearer ${CASKY_TOKEN}' \\
  -H 'Content-Type: application/json' \\
  -d '{\"findings\":[{\"title\":\"TITLE\",\"severity\":\"high\",\"description\":\"DESC\",\"proof\":\"EVIDENCE\",\"mitre_technique\":\"TXXXX\"}],\"summary\":\"One sentence summary\",\"raw_output\":\"paste terminal output\"}' \\
  ${CASKY_APP_URL:-http://casky-runner:8765}/api/runs/${CASKY_RUN_ID}/report
\`\`\`

Severity: critical / high / medium / low / informational
No findings? Use empty array: \`{\"findings\":[],\"summary\":\"No issues found\",\"raw_output\":\"\"}\`
"
    fi

    if [[ -n "$LIVE_TARGET" ]]; then
      echo "[casky] ================================================================" >&2
      echo "[casky] LIVE TARGET MODE — tools will run against a REAL system: $LIVE_TARGET" >&2
      echo "[casky] You confirmed authorization via --i-have-authorization." >&2
      echo "[casky] Never run this against infrastructure you don't have explicit" >&2
      echo "[casky] authorization to test — unauthorized scanning may be illegal." >&2
      echo "[casky] ================================================================" >&2
      ENV_SECTION="You are investigating a REAL, live target — not a disposable practice lab.
The operator has confirmed explicit authorization to test it. Stay strictly within scope:
only interact with ${LIVE_TARGET}, never pivot to or scan any other host, domain, or IP you
discover along the way without the operator explicitly telling you to.

- **Skill container** (${CONTAINER}): image ghcr.io/casky-ai/skills/${CATEGORY} — your security tools,
  with real internet/DNS egress (this is skill-live, not the sandboxed skill-lab).
- **Live target**: ${LIVE_TARGET} — a container name (reachable if the operator ran
  \`docker network connect <network> skill-live\` beforehand), a hostname/IP, or a full URL/API
  endpoint. Use it exactly as given below — don't assume it resolves via a fixed alias like
  the lab's \"target\" hostname.

Run every tool command through the skill container:
  docker exec ${CONTAINER} <command>

Examples (substitute the literal value \"${LIVE_TARGET}\" for the target):
  docker exec ${CONTAINER} nmap -sV ${LIVE_TARGET}
  docker exec ${CONTAINER} curl -s ${LIVE_TARGET}
  docker exec ${CONTAINER} bash -c 'cat /results/output.txt'"
    else
      ENV_SECTION="Two containers are running on the casky-lab Docker network:

- **Skill container** (${CONTAINER}): image ghcr.io/casky-ai/skills/${CATEGORY} — your security tools
- **Target container** (target): the vulnerable application you will attack

Run every tool command through the skill container:
  docker exec ${CONTAINER} <command>

Examples:
  docker exec ${CONTAINER} nmap -sV target
  docker exec ${CONTAINER} curl -s http://target
  docker exec ${CONTAINER} bash -c 'cat /results/output.txt'"
    fi

    PROMPT="${SKILL_PROMPT}

---

## Your environment

${ENV_SECTION}

The skills library (all 817 skills — documentation, reference material, AND runnable code,
read-only) is mounted at /opt/skills-library inside ${CONTAINER} — NOT /skills. Each skill has
up to four things at /opt/skills-library/skills/<skill-slug>/ (not every skill ships all four):
  SKILL.md              — the narrative playbook (when to use it, workflow, key concepts)
  scripts/agent.py or    — a self-contained Python implementation of the technique (stdlib +
  scripts/process.py      common libs only, e.g. requests — no extra install needed). Every
                           skill has one or the other; check both names.
  references/*.md        — deeper technical context: standards.md (MITRE ATT&CK/ATLAS/D3FEND/
                           NIST mappings), workflows.md (detailed procedure), api-reference.md
                           (API/tool reference) — whichever the skill ships
  assets/template.md     — a filled-in example report/checklist for this technique

Prefer running a skill's own script over improvising your own exploitation code by hand — it's
tested, known-working code, not something you have to write from scratch. Check its --help
first, since arguments vary per skill. Check for reference material and a report template too
before falling back to raw CLI tools or hand-written commands/reports:
  docker exec ${CONTAINER} cat /opt/skills-library/skills/<skill-slug>/SKILL.md
  docker exec ${CONTAINER} ls /opt/skills-library/skills/<skill-slug>/references/ 2>/dev/null
  docker exec ${CONTAINER} python3 /opt/skills-library/skills/<skill-slug>/scripts/agent.py --help \
    || docker exec ${CONTAINER} python3 /opt/skills-library/skills/<skill-slug>/scripts/process.py --help
  docker exec ${CONTAINER} cat /opt/skills-library/skills/<skill-slug>/assets/template.md 2>/dev/null

Not every skill's SKILL.md happens to mention its own script/references/template in its
narrative — check for them regardless.

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
      copilot)
        [[ -z "${GITHUB_TOKEN:-}" ]] && { echo "Set GITHUB_TOKEN first (gh copilot auth)"; exit 1; }
        echo "$PROMPT" | copilot   # confirm exact copilot CLI invocation flags before shipping —
                                   # no copilot binary is installed in the image yet (see Section 6, item 8)
        ;;
      custom)
        [[ -z "${AGENT_CMD:-}" ]] && { echo "Usage: casky run <category> --agent custom --agent-cmd \"<binary>\""; exit 1; }
        echo "$PROMPT" | eval "$AGENT_CMD"
        ;;
      *) echo "Unknown agent: $AGENT (use claude, gemini, copilot, or custom --agent-cmd)"; exit 1 ;;
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
        PASS=$((PASS + 1))
      else
        echo "  ✗ $tool — NOT FOUND"
        FAIL=$((FAIL + 1))
      fi
    done < "$TOOLS_FILE"

    echo ""
    if [[ $FAIL -gt 0 ]]; then
      echo "FAIL: $FAIL tool(s) missing from $CONTAINER"
      exit 1
    fi
    echo "PASS: all $PASS tools present in $CONTAINER ($CATEGORY)"
    ;;

  skills)
    # casky skills list [subdomain]
    # casky skills show <slug>
    # casky skills verify <slug>
    SKILLS_PATH="${SKILLS_LIBRARY_PATH:-/opt/skills-library}"
    [[ ! -d "$SKILLS_PATH" ]] && { echo "Skills library not found at $SKILLS_PATH"; exit 1; }

    SUBCOMMAND="${1:-list}"
    case "$SUBCOMMAND" in
      list)
        SUBDOMAIN_FILTER="${2:-}"
        if [[ ! -f "$SKILLS_PATH/index.json" ]]; then
          echo "Skills index not found. Run: docker compose up casky-skills"
          exit 1
        fi
        # The raw index.json shipped in the skills-library image has no
        # `subdomain` field at all (only name/description/domain/path) — every
        # per-skill SKILL.md has it in its own frontmatter, but it's dropped
        # when the flat index gets built. Prefer the enriched copy entrypoint.sh
        # writes at container startup (scripts/enrich_skills_index.py); fall
        # back to the raw index (subdomain filtering just won't match anything)
        # if enrichment hasn't run for some reason.
        ENRICHED_INDEX="/var/casky/skills-index-enriched.json"
        INDEX_FILE="$SKILLS_PATH/index.json"
        [[ -f "$ENRICHED_INDEX" ]] && INDEX_FILE="$ENRICHED_INDEX"
        if [[ -z "$SUBDOMAIN_FILTER" ]]; then
          jq -r '.skills[] | "\(.name) (\(.subdomain // "uncategorized")) — \(.description)"' "$INDEX_FILE"
        else
          MATCHES="$(jq -r ".skills[] | select(.subdomain == \"$SUBDOMAIN_FILTER\") | \"\(.name) (\(.subdomain)) — \(.description)\"" "$INDEX_FILE")"
          if [[ -z "$MATCHES" ]]; then
            echo "No skills found for subdomain '$SUBDOMAIN_FILTER'."
            if [[ "$INDEX_FILE" == "$SKILLS_PATH/index.json" ]]; then
              echo "Note: the enriched index ($ENRICHED_INDEX) isn't present, so subdomain filtering has nothing to match against — every filter returns empty. Restart the container to let entrypoint.sh regenerate it."
            else
              echo "Available subdomains:"
              jq -r '[.skills[].subdomain] | unique | .[] | select(. != null) | "  " + .' "$INDEX_FILE"
            fi
            exit 1
          fi
          echo "$MATCHES"
        fi
        ;;
      show)
        SLUG="${2:-}"
        [[ -z "$SLUG" ]] && { echo "Usage: casky skills show <slug>"; exit 1; }
        SKILL_MD="$SKILLS_PATH/skills/$SLUG/SKILL.md"
        [[ ! -f "$SKILL_MD" ]] && { echo "Skill not found: $SLUG"; exit 1; }
        cat "$SKILL_MD"
        ;;
      verify)
        SLUG="${2:-}"
        [[ -z "$SLUG" ]] && { echo "Usage: casky skills verify <slug>"; exit 1; }
        AGENT_SCRIPT="$SKILLS_PATH/skills/$SLUG/scripts/agent.py"
        [[ ! -f "$AGENT_SCRIPT" ]] && { echo "Agent script not found: $SLUG"; exit 1; }
        CONTAINER="${SKILL_LAB_NAME:-skill-lab}"
        if docker exec "$CONTAINER" python3 -c "import sys; sys.exit(0)" 2>/dev/null; then
          echo "  ✓ Skill '$SLUG' agent.py exists and skill-lab has python3"
        else
          echo "  ✗ Skill-lab container '$CONTAINER' not available or no python3"
          exit 1
        fi
        ;;
      *) echo "Usage: casky skills {list|show|verify}"; exit 1 ;;
    esac
    ;;

  db)
    # casky db migrate         — apply casky_db/migrations/*.sql (idempotent)
    # casky db migrate-json    — one-time import of plans_dir/reports_dir JSON into Postgres
    #
    # Both require DATABASE_URL. Same dispatch pattern as `casky harness`:
    # exec the venv interpreter (has psycopg installed) as a module, so
    # relative imports inside casky_db/ resolve correctly.
    DB_SUBCOMMAND="${1:-}"; shift || true
    case "$DB_SUBCOMMAND" in
      migrate)
        exec /opt/casky-console/bin/python3 -m casky_db.migrate "$@"
        ;;
      migrate-json)
        exec /opt/casky-console/bin/python3 -m casky_db.json_import "$@"
        ;;
      *)
        echo "Usage: casky db {migrate|migrate-json}"
        exit 1
        ;;
    esac
    ;;

  harness)
    # casky harness [-i|--input-file <path>] [--auto]
    #
    # Launches the agentic harness — fetches an investigation plan from casky.ai
    # (platform mode) or from ~/.casky/plans/ (local mode), then runs all steps
    # as parallel Claude + CVE MCP + skill-tool agents.
    #
    # Platform mode: set CASKY_API_KEY (generate at casky.ai/profile → Runner Token)
    # Local mode:    leave CASKY_API_KEY empty; findings saved to /var/casky/reports/
    #
    # "$@" forwarded so -i/--input-file (read evidence from a file instead of the
    # interactive paste prompt) and --auto actually reach casky-harness's argparse —
    # a prior version dropped every arg here silently.
    exec /opt/casky-console/bin/python3 /usr/local/bin/casky-harness "$@"
    ;;

  help|*)
    echo "casky — Casky skill runner + agentic harness"
    echo ""
    echo "Commands:"
    echo "  casky harness [-i|--input-file <path>] [--auto]"
    echo "      Launch the agentic harness. Fetches your investigation plan from"
    echo "      casky.ai and runs all steps in parallel as Claude + CVE MCP agents."
    echo "      Platform mode: set CASKY_API_KEY. Local mode: leave it empty."
    echo "      -i/--input-file reads evidence from a file (e.g. a CloudTrail JSON"
    echo "      export) instead of the interactive paste prompt — see the"
    echo "      /var/casky/evidence bind mount in docker-compose.yml."
    echo ""
    echo "  casky run <category> [--agent claude|gemini|copilot|custom] [--agent-cmd \"<binary>\"]"
    echo "      Run a single skill. <category> is the skill image category"
    echo "      (web-app, forensics, network, …). Paste the SKILL.md prompt on stdin."
    echo "      --agent custom requires --agent-cmd \"<binary>\", a command that reads the"
    echo "      prompt from stdin (e.g. --agent custom --agent-cmd \"my-agent-cli\")."
    echo "      --live-target <host|url> --i-have-authorization runs against a REAL,"
    echo "      authorized target via skill-live (real internet egress) instead of the"
    echo "      sandboxed skill-lab — see README's live-target section and SECURITY.md."
    echo ""
    echo "  casky verify <category>"
    echo "      Check the skill container has all required tools for <category>."
    echo ""
    echo "  casky skills list [subdomain]"
    echo "      List available skills, optionally filtered by subdomain."
    echo ""
    echo "  casky skills show <slug>"
    echo "      Show the SKILL.md documentation for a skill."
    echo ""
    echo "  casky skills verify <slug>"
    echo "      Verify that a skill's agent.py is accessible and skill-lab has python3."
    echo ""
    echo "  casky db migrate"
    echo "      Apply casky_db/migrations/*.sql against DATABASE_URL (idempotent)."
    echo ""
    echo "  casky db migrate-json"
    echo "      One-time import of the on-disk plans_dir/reports_dir JSON into Postgres."
    echo ""
    echo "Skill image categories:"
    echo "  forensics  malware  threat-intel  threat-hunting  network  cloud"
    echo "  web-app    vuln-scan  exploitation  post-exploit  incident-response"
    echo "  detection  osint  recon  identity  active-directory  appsec  devsecops"
    echo ""
    echo "Env vars:"
    echo "  ANTHROPIC_API_KEY      for Claude Code (required)"
    echo "  CASKY_API_KEY          Casky Runner Token — enables platform mode in harness"
    echo "  CASKY_APP_URL          platform URL (default: https://casky.ai)"
    echo "  CASKY_LOCAL_PORT       local report server port (default: 8765)"
    echo "  SKILLS_LIBRARY_PATH    path to skills library (default: /opt/skills-library)"
    echo "  GOOGLE_API_KEY         for Gemini CLI (optional)"
    echo "  GITHUB_TOKEN           for GitHub Copilot CLI, --agent copilot (optional)"
    echo "  SKILL_LAB_NAME         skill container name (default: skill-lab)"
    echo "  SKILL_LIVE_NAME        live-target skill container name (default: skill-live)"
    echo "  CASKY_RUN_ID           single-run platform link (optional, for casky run)"
    echo "  CASKY_TOKEN            single-run sandbox JWT (optional, for casky run)"
    echo "  DATABASE_URL           Postgres connection string — enables casky_db persistence"
    echo "                         (optional; local mode without it falls back to JSON files)"
    ;;
esac
