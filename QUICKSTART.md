# Casky Runner — Quick Start

Get from zero to running a real security investigation in under 5 minutes.

## Prerequisites

- Docker Desktop 4.x+ with at least 8 GB RAM allocated
- `ANTHROPIC_API_KEY` (Claude Code)
- Optional: `CASKY_API_KEY` from app.casky.ai → Profile → Runner Token (enables platform sync)

## 1. Clone and configure

```bash
git clone https://github.com/casky-ai/casky-runner
cd casky-runner
cp .env.example .env.local
```

Edit `.env.local` — at minimum set:
```
ANTHROPIC_API_KEY=sk-ant-...
```

For platform sync (reports findings to casky.ai dashboard):
```
CASKY_API_KEY=csk_...   # generate at app.casky.ai/profile → Runner Token
```

## 2. Start the stack

```bash
# Core services (runner + database)
docker compose --env-file .env.local up -d

# Core + skill/target lab containers
docker compose --env-file .env.local --profile lab up -d
```

## 3. Verify tools are ready

```bash
# Check that all web-app tools are present in the skill container
docker exec casky-runner casky verify web-app
```

Expected output:
```
  ✓ nmap
  ✓ nuclei
  ✓ ffuf
  ...
PASS: all N tools present in skill-lab (web-app)
```

## 4. Run a single skill (manual mode)

Paste any skill document from the registry on stdin:

```bash
docker exec -it casky-runner casky run web-app
# Paste your skill prompt, then press Ctrl+D
```

## 5. Run the agentic harness (recommended)

The harness fetches your investigation plan from casky.ai, runs all steps in parallel
as independent Claude + CVE MCP agents, and reports findings back automatically.

**Platform mode** (requires `CASKY_API_KEY`):
```bash
docker exec -it casky-runner casky harness
```

**Local mode** (no API key needed — works air-gapped or for data privacy):
```bash
# CASKY_API_KEY left empty in .env.local
# Load a plan exported from casky.ai:
docker cp /path/to/plan.json casky-runner:/home/casky/.casky/plans/my-plan.json

docker exec -it casky-runner casky harness
# Select "my-plan" from the list
# Findings are saved to /var/casky/reports/my-plan/
```

Retrieve local reports:
```bash
docker exec casky-runner cat /var/casky/reports/my-plan/REPORT.md
```

## Skill image categories

| Category | Tools |
|---|---|
| `web-app` | nmap, nuclei, ffuf, ZAP, sqlmap |
| `cloud` | ScoutSuite, AWS CLI, Prowler, CloudSploit |
| `network` | nmap, masscan, tcpdump, tshark |
| `forensics` | Volatility, Autopsy, binwalk, strings |
| `recon` | amass, subfinder, shodan, theHarvester |
| `vuln-scan` | OpenVAS, Nessus CLI, nuclei, trivy |
| ... | 18 categories total |

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude Code (required) |
| `CASKY_API_KEY` | — | Platform mode — generate at app.casky.ai |
| `CASKY_APP_URL` | `https://app.casky.ai` | Platform URL |
| `CASKY_LOCAL_PORT` | `8765` | Local report server port |
| `SKILL_IMAGE` | `ghcr.io/casky-ai/skills/web-app:latest` | Skill container image |
| `TARGET_IMAGE` | `ghcr.io/casky-ai/targets/dvwa:latest` | Target container image |

## Troubleshooting

**`casky verify` shows missing tools**: The skill image may not have pulled yet. Run `docker compose pull` and retry.

**`casky harness` shows "no plans"**: Approve an investigation plan on app.casky.ai first, then run the harness.

**Local report server not reachable**: Ensure port 8765 is not blocked by a local firewall. Change `CASKY_LOCAL_PORT` if needed.

**Docker socket permission denied**: On Linux, add your user to the `docker` group: `sudo usermod -aG docker $USER`
