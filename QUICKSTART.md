# Casky Runner — Quick Start

Run structured security investigations locally using the Casky Box (casky-runner v1.1).

**What this does:**
- Boots an isolated lab network with security tools (skill image) and a target application
- Receives investigation plans from the Casky platform (or runs local plans air-gapped)
- Executes skill runs via Claude Code against your evidence
- POSTs findings back to the platform dashboard (or saves locally)

**Time to first investigation:** 5 minutes

---

## Prerequisites

- Docker Desktop 4.x+ with at least 8 GB RAM allocated
- `ANTHROPIC_API_KEY` (Claude Code API key)
- Optional: `CASKY_TOKEN` (JWT from app.casky.ai workspace) for platform integration

## 1. Clone and configure

```bash
git clone https://github.com/casky-ai/casky-runner
cd casky-runner
cp .env.example .env.local
```

Edit `.env.local` — required:
```
ANTHROPIC_API_KEY=sk-ant-v3-...
```

Optional — for platform integration:
```
CASKY_TOKEN=eyJhbGc...           # JWT from workspace settings
CASKY_RUN_ID=550e8400-e29b...    # UUID linking findings to platform run
CASKY_APP_URL=https://app.casky.ai
SKILL_LAB_NAME=skill-lab         # Name of skill container
```

## 2. Start the Casky Box stack

```bash
# Start all services: casky-runner, casky-mcp, skill, target
docker compose --profile lab --env-file .env.local up -d
```

This starts:
- **casky-runner** — Claude Code agent + agentic harness
- **casky-mcp** — CVE MCP server (auto-registered in Claude)
- **skill-lab** — security tool container (default: `web-app`)
- **target** — vulnerable application (default: `dvwa`)

All on an isolated Docker network (`casky-lab`).

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

## 4. Run an investigation from the platform

**Option A: Platform mode** (requires `CASKY_TOKEN`):

1. Go to `app.casky.ai/investigate`
2. Paste evidence (CloudTrail logs, SIEM exports, etc.) or upload a file
3. Review the generated investigation plan
4. Click Approve — platform dispatches runs to your Casky Box
5. Watch findings arrive in real-time on the platform dashboard
6. Click **Generate CISO Report** when all runs complete

Your Casky Box receives `POST /api/runs`, executes skills, and POSTs findings back to `/api/runs/[id]/report`.

**Option B: Local/air-gapped mode** (no API key needed):

```bash
# Load a plan JSON file (exported from casky.ai or created manually)
docker cp /path/to/plan.json casky-runner:/home/casky/.casky/plans/my-plan.json

# Run the agentic harness
docker exec -it casky-runner casky harness

# Select the plan from the menu
# Findings are saved to /var/casky/reports/my-plan/findings.json
```

## 5. View findings

**Platform mode:** Findings appear on app.casky.ai dashboard in real-time.

**Local mode:** Retrieve findings from the container:
```bash
docker exec casky-runner cat /var/casky/reports/my-plan/REPORT.md
docker exec casky-runner cat /var/casky/reports/my-plan/findings.json
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

### Test 1: Single skill run (manual)
```bash
docker exec -it casky-runner casky run web-app
# Paste a SKILL.md prompt, press Ctrl+D
# Claude Code runs the skill against evidence
```

### Test 2: Verify tool availability
```bash
docker exec casky-runner casky verify cloud
# Confirms all cloud-security tools are present in skill-lab
```

### Test 3: Full investigation from evidence
1. Prepare evidence: CloudTrail logs, SIEM export, or PCAP file
2. Open `app.casky.ai/investigate`
3. Upload or paste evidence
4. Review platform-generated investigation plan
5. Approve to trigger your Casky Box
6. Watch findings stream live
7. Generate CISO report when all runs complete

### Test 4: Air-gapped / local-only mode
- Run Casky Box with `CASKY_TOKEN` empty
- Export a plan JSON from the platform
- Copy plan into container: `docker cp plan.json casky-runner:/home/casky/.casky/plans/`
- Run `docker exec -it casky-runner casky harness`
- Findings saved locally to `/var/casky/reports/`

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
