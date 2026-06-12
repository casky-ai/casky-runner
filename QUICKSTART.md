# Casky Runner — Quick Start

Run structured security investigations locally using the Casky Box (casky-runner v1.1).

**What this does:**
- Boots an isolated lab network with security tools (skill image) and a target application
- Supports **interactive guided investigations** — Claude guides you through each skill step-by-step
- Receives investigation plans from the Casky platform (or runs local plans air-gapped)
- Synthesizes findings into structured reports (MITRE, severity, remediation)
- POSTs findings back to the platform dashboard (or saves locally)

**Time to first investigation:** 5 minutes

---

## Prerequisites

- Docker Desktop 4.x+ with at least 8 GB RAM allocated
- `ANTHROPIC_API_KEY` (Claude Code API key)
- Optional: `CASKY_TOKEN` (JWT from app.casky.ai workspace) for platform integration

## 1. Clone and configure environment

```bash
git clone https://github.com/casky-ai/casky-runner
cd casky-runner
cp .env.example .env.local
```

**Edit `.env.local`** — required (open with your editor):
```bash
nano .env.local
# OR
vi .env.local
```

Add your API key:
```
ANTHROPIC_API_KEY=sk-ant-v3-YOUR_KEY_HERE
```

**Optional** — for platform integration:
```
CASKY_API_KEY=csk_...            # Casky platform API key (for platform mode)
CASKY_APP_URL=https://app.casky.ai
```

**Note:** The runner container reads `ANTHROPIC_API_KEY` from the environment. Make sure it's set in `.env.local` before starting containers with `--env-file .env.local`.

## 2. Populate the skills library (one-time setup)

Before starting the investigation, download the 754-skill security library:

```bash
# Pull the latest skills library image
docker compose pull casky-skills

# Populate the shared volume (one-time, ~30 seconds)
docker compose up casky-skills
```

Expected output:
```
casky-skills  | Skills library ready: 754 skills
casky-skills exited with code 0
```

Re-run these commands anytime you want to update the skills library to the latest version.

## 3. Choose and start a target

Pick one of three target options:

### Option A: DVWA (Damn Vulnerable Web App) — Full multi-vulnerability investigation

```bash
docker compose --profile lab-dvwa --env-file .env.local up -d runner db skill-lab target-dvwa target-db
```

**Starts:**
- **casky-runner** — Claude Code agent
- **casky-mcp** — CVE MCP server
- **skill-lab** — web-app tools (nmap, nuclei, sqlmap, etc.)
- **casky-target** — DVWA vulnerable app
- **casky-target-db** — MySQL database (auto-initialized)

**Best for:** Web application security (SQL injection, XSS, CSRF, auth bypass)

### Option B: OWASP Juice Shop — Self-contained, no database setup

```bash
docker compose --profile lab-juice-shop --env-file .env.local up -d runner db skill-lab target-juice-shop
```

**Starts:**
- Same services as Option A, but with Juice Shop (Node.js) instead of DVWA
- No database to configure; faster to start

**Best for:** Web app security + ecommerce vulnerabilities

### Option C: Custom target — Bring your own container

```bash
export TARGET_IMAGE=your-custom:latest
docker compose --profile lab-custom --env-file .env.local up -d runner db skill-lab target-custom
```

**Requirements:**
- Container must listen on port 80 or 8080
- Connected to `casky-lab` Docker network
- Document the application's vulnerabilities in a README

**Best for:** Testing against your own applications or third-party targets

## 3. Verify tools are ready

```bash
docker exec casky-runner casky verify web-app
```

Expected output:
```
✓ nmap
✓ nuclei
✓ ffuf
...
PASS: all 12 tools present in skill-lab (web-app)
```

If tools are missing, the skill image may still be pulling. Wait 30s and retry.

Also verify the target is responding:

```bash
docker exec skill-lab curl -s -I http://target/ | head -3
```

Should see `HTTP/1.1 200` or `302 Found`.

## 4. Browse the skills library

You can explore available skills before starting an investigation:

```bash
# List all skills
docker exec casky-runner casky skills list

# List skills in a specific domain (e.g., cloud-security)
docker exec casky-runner casky skills list cloud-security

# View the full documentation for a skill
docker exec casky-runner casky skills show detecting-aws-cloudtrail-anomalies
```

## 5. Interactive guided investigation workflow

This is a **human-in-the-loop** investigation where Claude guides you step-by-step through each skill.

### Step 1: Evidence gathering

Gather preliminary reconnaissance on your target:

```bash
# Example: Web app reconnaissance
docker exec skill-lab bash -c '
echo "=== HTTP Headers ==="
curl -s -I http://target/ | head -5

echo "=== Server Detection ==="
curl -s http://target/ | head -20
'
```

Or upload/paste evidence from logs, exports, or SIEM systems.

### Step 2: Skill identification & interactive execution

Start Claude as your investigation guide:

```bash
docker exec -it casky-runner casky run web-app
```

Paste this prompt (or your own evidence + task):

```
# Interactive Web Application Security Investigation

## My Evidence
[Paste your reconnaissance output or raw logs here]

## Task
Based on this evidence, guide me through a structured investigation:

1. **Identify applicable skills** — which security assessment techniques apply?
2. **For each skill, provide guidance:**
   - What the skill tests for (MITRE techniques, vulnerability classes)
   - Exact command(s) to run in the skill container
   - What to look for in the output
3. **Sequential execution** — one skill at a time
   - I'll run the command you suggest
   - Paste the output back
   - You analyze and move to the next skill
4. **After all skills:**
   - Synthesize findings into a structured report
   - Map to MITRE ATT&CK
   - Provide severity ratings + remediation

Let's start: what's skill #1, and what exact command should I run?
```

Then:
- Claude suggests **Skill 1** and the exact command to run
- You copy the command and execute it (in another terminal):
  ```bash
  docker exec skill-lab [command Claude suggested]
  ```
- Paste the output back to Claude
- Claude analyzes, suggests **Skill 2**
- Repeat until all applicable skills are covered

### Step 3: Findings synthesis

Once all skills are executed, Claude synthesizes:
- **Confirmed vulnerabilities** (with proof from tool output)
- **MITRE ATT&CK mapping** (which techniques)
- **Risk rating** (CRITICAL/HIGH/MEDIUM/LOW)
- **Remediation steps** (specific fixes)
- **CISO report** (executive summary, prioritized actions)

### Alternative: Automated harness mode

If you prefer fully automated (no interactive guidance):

```bash
# Platform mode
docker exec -it casky-runner casky harness
# (requires CASKY_TOKEN; fetches plan from app.casky.ai)

# Or local mode
docker cp /path/to/plan.json casky-runner:/home/casky/.casky/plans/my-plan.json
docker exec -it casky-runner casky harness
```

---

## Skill image categories (18 total)

| Skill | Tools | Practice targets |
|-------|-------|------------------|
| `web-app` | nmap, nuclei, ffuf, ZAP | dvwa, juice-shop |
| `cloud` | ScoutSuite, AWS CLI, Prowler | localstack |
| `network` | nmap, masscan, tcpdump, tshark | pcap-server |
| `forensics` | Volatility, Autopsy, binwalk | evidence-pack |
| `recon` | amass, subfinder, shodan | vulnstack |
| `vuln-scan` | OpenVAS, Nessus, nuclei, trivy | vulnstack |
| `exploitation` | metasploit, searchsploit | metasploitable, vulnservices |
| `post-exploit` | linpeas, Linux privesc tools | linux-pivot |
| `active-directory` | ldapsearch, Rubeus, BloodHound | minidc |
| `incident-response` | plaso, timesketch | evidence-pack |
| `malware` | YARA, Cuckoo, volatility | sample-pack |
| `appsec` | semgrep, truffleHog, bandit | vulncode |
| `identity` | ldapsearch, adidnsdump | minidc |
| `threat-intel` | MISP tools, threat feeds | — |
| `threat-hunting` | osquery, sigma-cli | evidence-pack |
| `detection` | osquery, wazuh-cli, sigma | — |
| `osint` | shodan, censys, pwndb | — |
| `devsecops` | checkov, snyk, trivy | — |

## Environment variables reference

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude Code API key (required) |
| `CASKY_TOKEN` | — | JWT for platform integration (optional) |
| `CASKY_RUN_ID` | — | UUID linking findings to platform run |
| `CASKY_APP_URL` | `https://app.casky.ai` | Platform URL override |
| `SKILL_LAB_NAME` | `skill-lab` | Skill container name |
| `SKILL_IMAGE` | `ghcr.io/casky-ai/skills/web-app:latest` | Skill container image |
| `TARGET_IMAGE` | `ghcr.io/casky-ai/targets/dvwa:latest` | Target container image |

---

## Testing Scenarios

### Scenario 1: Interactive Web App Investigation (DVWA)

```bash
# Start DVWA stack
docker compose --profile lab-dvwa --env-file .env.local up -d
sleep 10

# Verify target is ready
docker exec skill-lab curl -s -I http://target/ | head -3

# Start interactive investigation
docker exec -it casky-runner casky run web-app
```

Paste your evidence or this template:

```
# DVWA Investigation

## Evidence
- Target: http://target:80 (Apache/PHP)
- Authentication: admin/password credentials
- Application: DVWA (intentionally vulnerable web app)

## Goal
Guide me through a security assessment. For each skill:
1. Show what MITRE techniques it covers
2. Provide the exact command to run
3. I'll paste the output back
4. You analyze and suggest the next skill

Let's start: what's the first skill?
```

### Scenario 2: Quick Tool Verification

```bash
# Verify skill-lab has all web-app tools
docker exec casky-runner casky verify web-app

# Verify other skill categories
docker exec casky-runner casky verify cloud
docker exec casky-runner casky verify network
```

### Scenario 3: Platform Integration

1. Set `CASKY_TOKEN` in `.env.local` (generate at `app.casky.ai/workspace/settings`)
2. Run Casky Box: `docker compose --profile lab-dvwa up -d`
3. Go to `app.casky.ai/investigate`
4. Paste or upload evidence
5. Platform generates a plan and dispatches to your Casky Box
6. Watch findings stream live
7. Generate CISO report when complete

### Scenario 4: Air-gapped (No Internet)

```bash
# Run with CASKY_TOKEN empty
docker compose --profile lab-dvwa up -d

# Load a pre-exported plan (or create one manually)
docker cp /path/to/plan.json casky-runner:/home/casky/.casky/plans/my-plan.json

# Run the harness locally
docker exec -it casky-runner casky harness

# Retrieve findings
docker exec casky-runner cat /var/casky/reports/my-plan/findings.json
```

### Scenario 5: Custom Target

```bash
# Set your own target image
export TARGET_IMAGE=myapp:latest
docker compose --profile lab-custom --env-file .env.local up -d

# Verify it's reachable
docker exec skill-lab curl -s http://target:80 | head -20

# Run investigation
docker exec -it casky-runner casky run web-app
```

---

## Troubleshooting

**Skill image tools missing after `casky verify`**
```bash
docker compose pull skill-lab
docker compose --profile lab restart
```

**`docker exec` permission denied**
```bash
# On Linux, add your user to docker group:
sudo usermod -aG docker $USER
newgrp docker
```

**Port already in use**
```bash
# Casky Box uses docker.sock (no external ports by default)
# If localhost:8765 blocked, check for conflicting services
lsof -i :8765
```

**Platform findings not arriving**
- Verify `CASKY_TOKEN` is set and valid (check workspace settings on app.casky.ai)
- Check runner logs: `docker compose logs -f casky-runner`
- Confirm network connectivity: `docker exec casky-runner curl https://app.casky.ai`

**"No plans" when running harness**
- In local mode: manually create or export a plan JSON and copy it to `/home/casky/.casky/plans/`
- In platform mode: approve an investigation at app.casky.ai/investigate first

---

## Next steps

- Read **[Investigating Security Incidents with Casky](../blog-investigating-with-casky.md)** for the full investigation workflow
- Check **[v1.1 Architecture Plan](../plans/025_consolidated.md)** for technical details (Context Graph, Evidence Library, Marketplace)
- Explore the **[18 skill categories](#skill-image-categories-18-total)** and their target pairs
