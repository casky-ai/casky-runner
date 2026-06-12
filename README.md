# casky-runner

The AI runner image for the [Casky](https://casky.ai) platform. Ships Claude Code and Gemini CLI in a minimal Ubuntu container. Drives security exercises and investigations by issuing commands into a skill container via `docker exec`, against a target container on the same isolated Docker network.

**Last Updated:** 2026-06-11  
**Part of:** Casky v1.1 (May 31 – Jul 9, 2026)

```
┌────────────────────────────────────────────────────────────────────┐
│  Casky Platform (casky.ai)                                         │
│  ├─ Evidence-first investigation entry point (/investigate)        │
│  ├─ Context Graph assembly (CVE Watch, Playbooks, History)        │
│  ├─ Investigation Plan generation + review                        │
│  └─ CISO report synthesis                                         │
└────┬────────────────────────────────────────────────────────────────┘
     │ Triggers skilled runs (Evidence mode)
     │
┌────┴────────────────────────────────────────────────────────────────┐
│  Casky Box: Local Execution (casky-runner + docker-compose)        │
│                                                                    │
│  Docker host (your laptop or CI runner)                           │
│  │                                                                │
│  ├── casky-lab ─── isolated bridge network                        │
│  │   ├── casky-runner (Claude Code + Gemini)                     │
│  │   ├── casky-mcp (CVE MCP server)                              │
│  │   ├── skill container ghcr.io/casky-ai/skills/<name>:latest  │
│  │   └── target container ghcr.io/casky-ai/targets/<name>:latest│
│  │                                                                │
│  └── docker exec ──► findings JSON ──► /api/runs/[id]/report    │
└────────────────────────────────────────────────────────────────────┘
```

## What is Casky?

Casky is a **structured security investigation platform**. Unlike traditional AI chat windows, Casky:

1. **Takes raw evidence** — CloudTrail logs, PCAP captures, SIEM exports, or custom artifacts
2. **Assembles context** — CVE enrichment, playbook matching, historical investigation similarity
3. **Generates a plan** — ordered skill runs, each mapped to a MITRE technique, with rationale you review before running
4. **Produces findings** — structured, severity-badged, with remediation steps
5. **Synthesizes a CISO report** — executive summary, confirmed techniques, prioritized remediation

The **Casky Box** (casky-runner) is how you run investigations **locally** without platform setup, using docker-compose.

## Runner image

```
ghcr.io/casky-ai/box/runner:latest
```

## Getting Started: Three Ways to Run Casky

### Option 1: Docker Compose with Target Selection (Recommended)

The easiest way to test Casky Box locally. Choose your target and run:

```bash
# 1. Clone and navigate
git clone https://github.com/casky-ai/casky-runner.git
cd casky-runner

# 2. Copy environment template
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Choose and start a target (pick ONE):

# ✅ DVWA (full web app vulnerabilities + database)
docker compose --profile lab-dvwa up -d

# OR

# ✅ OWASP Juice Shop (self-contained, no DB)
docker compose --profile lab-juice-shop up -d

# OR

# ✅ Custom target (bring your own)
export TARGET_IMAGE=your-app:latest
docker compose --profile lab-custom up -d

# 4. Verify target is ready
docker exec skill-lab curl -s -I http://target/ | head -3

# 5. Start interactive investigation
docker exec -it casky-runner casky run web-app
```

**What starts (all targets include):**
- `casky-runner` — Claude Code agent
- `casky-mcp` — CVE MCP server (auto-registered in Claude)
- `skill-lab` — security tools (nmap, nuclei, sqlmap, etc.)
- `casky-target` — your chosen vulnerable app
- `casky-target-db` — MySQL (DVWA only; auto-initialized)

**Environment variables in `.env`:**
```bash
ANTHROPIC_API_KEY=your-api-key-here
CASKY_RUN_ID=optional-run-uuid  # Links findings to platform
CASKY_TOKEN=optional-jwt         # JWT for POSTing findings
SKILL_LAB_NAME=skill-lab         # Skill container name
CASKY_APP_URL=https://casky.ai   # Platform URL override
DB_PASSWORD=dvwa                 # MySQL password (DVWA only)
TARGET_IMAGE=your-app:latest     # Custom target image
```

**Target Comparison:**

| Target | Database | Best For | Setup Time |
|--------|----------|----------|------------|
| **DVWA** | MySQL (auto) | Full web app assessment (SQLi, XSS, CSRF, auth) | 30s |
| **Juice Shop** | None (Node.js) | Web app + ecommerce vulns | 10s |
| **Custom** | Your choice | Your own app or third-party | Varies |

### Option 2: Manual Docker (for Integration Testing)

Run each container separately to test specific skills or targets.

```bash
# 1. Create the isolated lab network (once)
docker network create casky-lab

# 2. Start the target for your exercise (example: DVWA for web-app skill)
docker run -d --name target \
  --network casky-lab \
  ghcr.io/casky-ai/targets/dvwa:latest

# 3. Start the skill container
docker run -d --name skill-lab \
  --network casky-lab \
  ghcr.io/casky-ai/skills/web-app:latest

# 4. Run the AI agent
docker run --rm \
  -e ANTHROPIC_API_KEY="<your-key>" \
  -e CASKY_RUN_ID="<run-id>" \
  -e CASKY_TOKEN="<token>" \
  -e SKILL_LAB_NAME=skill-lab \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/casky-ai/box/runner:latest \
  casky run web-app
```

### Option 3: Platform Integration (Full Workflow)

Connect your local Casky Box to the **Casky platform** for structured investigations.

**What happens:**
1. You paste evidence on `casky.ai/investigate`
2. Platform generates an investigation plan (ordered skill runs)
3. You approve the plan
4. Platform creates runs, dispatches to your Casky Box via `POST /api/runs`
5. Runner executes skills, POSTs findings back to `/api/runs/[id]/report`
6. Platform assembles findings into a CISO report

**Setup:**
```bash
# 1. Start Casky Box (Option 1 or 2 above)

# 2. In the platform, create a workspace and get a CASKY_TOKEN (JWT)

# 3. Export the token in Casky Box environment
export CASKY_TOKEN=eyJ...  # JWT from platform

# 4. From the platform, submit evidence at casky.ai/investigate
# Platform generates a plan and triggers your Casky Box runners

# 5. View findings and CISO report on the platform dashboard
```

## Investigation Workflow

### Step 1: Bring Evidence
Open `casky.ai/investigate` and either:
- **Paste text** — CloudTrail logs, SIEM exports, PCAP summaries, policy files
- **Upload files** — `.log`, `.json`, `.csv`, `.txt`, `.xml` (max 2 MB each)

Acknowledge the PII scrubbing checkbox before submitting.

### Step 2: Context Assembly
Before the AI sees your evidence, Casky assembles context in parallel:

| Engine | Contributes |
|--------|------------|
| **CVE Watch** | CVSS, KEV status, MITRE mapping for detected CVEs |
| **Playbook Library** | Matching investigation playbooks for detected techniques |
| **Historical Plans** | Similar past investigations from your team (≥0.8 rating) |

If any context engine fails, it contributes a gap message and the others proceed. **Investigations never block.**

### Step 3: Review the Plan
The platform generates a **structured investigation plan** with:
- Ordered skill steps
- Rationale for each step
- Expected findings per step
- MITRE technique coverage

**You control the plan.** Remove steps that don't fit. Reorder if needed. Only click Approve when you're ready.

### Step 4: Runs Execute in Parallel
Platform dispatches one run per approved step to your Casky Box:
```
/api/runs → POST { run_id, skill_slug, evidence_text }
                    ↓
        Casky Box receives run request
                    ↓
        casky-runner: docker exec skill-lab <command>
                    ↓
        Claude analyzes evidence with skill context
                    ↓
        findings JSON → POST /api/runs/[id]/report
                    ↓
        Platform dashboard updates live
```

Each run surfaces **structured findings**: severity-badged, with remediation steps.

### Step 5: Generate CISO Report
Click **Generate CISO Report** when all runs complete. The platform synthesizes:

| Section | Content |
|---------|---------|
| Executive Summary | What happened, what was confirmed, business impact |
| Risk Rating | critical / high / medium / low |
| Confirmed Techniques | MITRE ATT&CK IDs from actual evidence |
| Key Findings | Table: severity · title · remediation (max 5) |
| Remediation Actions | Table: priority · action · effort · impact (max 6) |
| Immediate Next Steps | 2-3 specific actions to take now |
| Affected Assets | Identifiers from the evidence |

**This is the output you hand to a CISO or attach to a ticket.**

### Step 6: Rate Steps (Feedback Loop)
Rate each step: **Found something** / **Confirmed nothing** / **Wrong skill** / **Missed something**

High-rated plans (≥0.8 with outcome summary) enter the few-shot pool — future investigations benefit from your team's actual judgments.

---

## Commands

| Command | Description |
|---|---|
| `casky run <skill>` | Run a skill exercise with Claude (default) |
| `casky run <skill> --agent gemini` | Run with Gemini CLI instead |
| `casky verify <skill>` | Check that the skill container has all required tools |

## Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude Code API key |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Gemini CLI API key |
| `SKILL_LAB_NAME` | Name of the running skill container (default: `skill-lab`) |
| `CASKY_RUN_ID` | Links findings to a Casky platform run (optional) |
| `CASKY_TOKEN` | JWT for POSTing findings to the platform (optional) |
| `CASKY_APP_URL` | Override platform URL (default: `https://app.casky.ai`) |

## Skills

Each skill maps 1-to-1 to an image in [casky-ai/skill-images](https://github.com/casky-ai/skill-images).

| Skill name | Skill image | Paired targets |
|---|---|---|
| `forensics` | `ghcr.io/casky-ai/skills/forensics` | `evidence-pack` |
| `malware` | `ghcr.io/casky-ai/skills/malware` | `sample-pack` |
| `threat-intel` | `ghcr.io/casky-ai/skills/threat-intel` | — |
| `threat-hunting` | `ghcr.io/casky-ai/skills/threat-hunting` | `evidence-pack` |
| `network` | `ghcr.io/casky-ai/skills/network` | `pcap-server` |
| `cloud` | `ghcr.io/casky-ai/skills/cloud` | `localstack` |
| `web-app` | `ghcr.io/casky-ai/skills/web-app` | `dvwa`, `juice-shop` |
| `vuln-scan` | `ghcr.io/casky-ai/skills/vuln-scan` | `vulnstack` |
| `exploitation` | `ghcr.io/casky-ai/skills/exploitation` | `metasploitable`, `vulnservices` |
| `post-exploit` | `ghcr.io/casky-ai/skills/post-exploit` | `linux-pivot` |
| `incident-response` | `ghcr.io/casky-ai/skills/incident-response` | `evidence-pack` |
| `detection` | `ghcr.io/casky-ai/skills/detection` | — |
| `osint` | `ghcr.io/casky-ai/skills/osint` | — |
| `recon` | `ghcr.io/casky-ai/skills/recon` | `vulnstack` |
| `identity` | `ghcr.io/casky-ai/skills/identity` | `minidc` |
| `active-directory` | `ghcr.io/casky-ai/skills/active-directory` | `minidc` |
| `appsec` | `ghcr.io/casky-ai/skills/appsec` | `vulncode` |
| `devsecops` | `ghcr.io/casky-ai/skills/devsecops` | — |

Target images are published from [casky-ai/skill-targets](https://github.com/casky-ai/skill-targets) to `ghcr.io/casky-ai/targets/<name>:latest`.

## Local development

```bash
make build    # build runner image (casky-runner:dev)
make scan     # Trivy HIGH/CRITICAL scan
make lint     # shellcheck casky.sh
make test     # run the integration test harness
make shell    # bash shell inside the runner

# Run a skill (requires a running skill-lab container)
make run SKILL=web-app AGENT=claude

# Verify tools are present in the skill container
make verify SKILL=web-app
```

## How it works

1. The runner, skill, and target containers all start on the `casky-lab` Docker network.
2. `casky run <category>` reads the skill prompt from **stdin** — paste any `SKILL.md` from the [753-skill registry](https://github.com/casky-ai/casky-runner), then press `Ctrl+D`. The runner appends environment context (which containers are running, how to exec into the skill container) and pipes the combined prompt to Claude Code or Gemini CLI.
3. The AI agent runs tool commands via `docker exec <skill-container> <cmd>` — it never enters either container interactively.
4. If `CASKY_RUN_ID` and `CASKY_TOKEN` are set, the agent POSTs findings back to the Casky platform API on completion.
5. `casky verify <category>` checks every tool listed in `/etc/casky/skills/<category>.tools` exists in the skill container — used in CI to confirm skill images ship the expected toolchain.

## CI

- **build.yml** — builds the runner image, runs Trivy (HIGH/CRITICAL exit-code 1), pushes to GHCR on `main`. Trivy always scans the locally built image, not a stale GHCR tag.
- **test.yml** — matrix over all 18 skills; pulls the corresponding `ghcr.io/casky-ai/skills/<name>:latest` image, starts it as `skill-lab`, runs `casky verify <skill>`. Skips gracefully if the skill image isn't published yet.

## License

MIT
