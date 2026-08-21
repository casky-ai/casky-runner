# Casky Box — Quick Start

Run structured security investigations locally using Casky Box (`casky-runner`) — no account, no
cloud dependency required. See [README.md](README.md) for the full architecture and BYO-Agent /
BYO-LLM / BYO-DB configuration reference; this doc is a hands-on walkthrough.

**What this gives you:**
- A local lab network with security tools (skill containers) and a target application to practice against
- `casky harness` — evidence in, an ordered MITRE-mapped investigation plan out, via the 4-stage
  classifier pipeline described in [README.md](README.md#how-a-plan-actually-gets-built)
- `casky run <skill>` — interactive, human-in-the-loop investigation guided by your chosen coding agent
- Structured findings (severity, remediation, MITRE mapping), saved locally, synced to a platform
  dashboard only if you opt in

**Time to first investigation:** ~5 minutes if you already have Docker running.

---

## Prerequisites

- Docker Desktop 4.x+ with at least 8 GB RAM allocated
- An LLM provider for the classifier pipeline — `ANTHROPIC_API_KEY` by default (see README's
  [BYO-LLM section](README.md#byo-llm--which-model-plans-the-investigation) for OpenAI/Qwen/Kimi/local alternatives)
- Optional: a Casky platform account (`CASKY_API_KEY`, generated at [casky.ai](https://casky.ai)) if
  you want plan sync / hosted dashboard on top of the local pipeline — not required for anything below

## 1. Clone and configure environment

```bash
git clone https://github.com/casky-ai/casky-runner.git
cd casky-runner
cp .env.example .env
```

**Edit `.env`** and set at minimum:
```
ANTHROPIC_API_KEY=sk-ant-...
```

`docker compose` reads `.env` automatically — no `--env-file` flag needed for anything in this guide.
(`.env.local` is a *separate* file used only by `tests/compose-test.sh`'s own test harness — don't
confuse the two.)

**Optional** — for platform sync (entirely additive, see README):
```
CASKY_API_KEY=csk_...             # generate at casky.ai — this is what enables platform mode
CASKY_APP_URL=https://casky.ai    # default, only needed if you're overriding it
```

## 2. Populate the skills library (one-time)

`casky-skills` is a thin packaging container ([docker/skills/Dockerfile](docker/skills/Dockerfile))
that clones the upstream skills repo
([mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills))
verbatim and copies it into a shared volume other services mount read-only.

**If you're testing this repo before it's pushed/published** (no `ghcr.io/casky-ai/skills-library`
image exists yet — that only gets built and published by this repo's own GitHub Actions workflow
after it's pushed), build it locally instead of pulling:

```bash
docker build -f docker/skills/Dockerfile -t ghcr.io/casky-ai/skills-library:latest .
docker compose up casky-skills
```

**Once this repo is pushed and the image is published**, you can skip the local build and just pull:
```bash
docker compose pull casky-skills
docker compose up casky-skills
```

Expected output either way (the exact count tracks upstream and will drift over time — 754 when
this doc was first written, 817 as of the last local verification; don't worry if yours differs,
just confirm it's a nonzero count and exit code 0):
```
casky-skills  | Skills library ready: N skills
casky-skills exited with code 0
```

`casky-skills` is a one-shot init container — it populates the shared volume, then exits 0. That
exit is expected, not a failure. Re-run whichever of the two commands above anytime you want to
refresh to the latest skill set.

## 3. Choose and start a target

Pick one profile:

### Option A: DVWA — full multi-vulnerability web app

```bash
docker compose --profile lab-dvwa up -d
```

**Starts:** `casky-runner`, `db` (local Postgres), `skill-lab` (web-app tools: nmap, nuclei, ffuf, etc.),
`target-dvwa` (container name `casky-target`), `target-db` (MySQL, auto-initialized).

**Best for:** SQL injection, XSS, CSRF, auth bypass.

### Option B: OWASP Juice Shop — self-contained, no database

```bash
docker compose --profile lab-juice-shop up -d
```

Same services as Option A, but the target is Juice Shop (Node.js) — no database to wait on, faster
to start.

### Option C: Custom target — bring your own container

```bash
export TARGET_IMAGE=your-custom:latest
docker compose --profile lab-custom up -d
```

Your image needs to listen on port 80 and join the `casky-lab` network — `docker-compose.yml` wires
this up automatically once `TARGET_IMAGE` is set.

## 4. Verify everything is actually up

```bash
docker exec casky-runner casky verify web-app
```

Expected:
```
  ✓ nmap
  ✓ nuclei
  ...
PASS: all N tools present in skill-lab (web-app)
```

And confirm the target itself is reachable — every target profile gets a stable `target` network
alias regardless of which one is active:

```bash
docker exec skill-lab curl -s -I http://target/ | head -3
```

Expect `HTTP/1.1 200` or `302 Found`. If tools are still missing, the skill image may still be
pulling — wait ~30s and retry `casky verify`.

## 5. Browse the skills library

```bash
# List all skills
docker exec casky-runner casky skills list

# List skills in a specific subdomain (real example — this one has 60+ matches)
docker exec casky-runner casky skills list cloud-security

# View full documentation for one skill
docker exec casky-runner casky skills show detecting-aws-cloudtrail-anomalies
```

If a subdomain filter ever returns nothing, `casky skills list <subdomain>` will now tell you
explicitly and list the real available subdomains — it won't just go silent.

## 6. Run an investigation

### Path A — automatic: evidence in, plan out (`casky harness`)

This is the primary, recommended path — it's what runs the actual classifier pipeline
(entity extraction → context adapters → 4-stage classification) described in the README.

```bash
docker exec -it casky-runner casky harness
```

Choose `g` (generate new plan), paste your evidence — a CloudTrail event, a suspicious log line,
anything — then **type `END` alone on a new line and press Enter** to submit (Ctrl+D also works, but
`END` sidesteps a real terminal quirk: Ctrl+D only signals true end-of-input on an *empty* line, so
pasted text without a trailing newline can need a second Ctrl+D press). You'll see live progress as
each pipeline stage runs, then an ordered plan with rationale per step — nothing executes until you
review it.

**From a file instead of pasting** — drop the evidence file in `./evidence/` on the host (bind-mounted
read-only into the container at `/var/casky/evidence`, no `docker cp` needed) and pass `-i`:

```bash
cp your-cloudtrail-export.json evidence/
docker exec -it casky-runner casky harness -i /var/casky/evidence/your-cloudtrail-export.json
```

This skips the Plan Source menu and paste prompt entirely and generates the plan directly from the
file's contents. `casky harness` doesn't accept literal `.pcap` files — for packet captures, run
`tshark -r yourfile.pcap -nn` (or `tcpdump -r yourfile.pcap -nn`) first and save the *text output* to
`evidence/` instead. `evidence/` is gitignored (except its own README) — evidence can contain real
investigation data and must never be committed.

### Path B — interactive: guided step-by-step with your coding agent (`casky run`)

For a more conversational flow where your agent proposes one command at a time and you paste results
back:

```bash
docker exec -it casky-runner casky run web-app
```

Paste a task prompt (same `END`-to-submit rule applies), for example:

```
# Interactive Web Application Security Investigation

## My Evidence
[Paste your reconnaissance output or raw logs here — or leave blank to start from zero-knowledge recon]

## Task
Guide me through a structured investigation: identify applicable skills, give me the exact command
to run for each one, analyze what I paste back, then move to the next skill. After all skills,
synthesize findings into a MITRE-mapped report with severity ratings and remediation.

Let's start: what's skill #1, and what exact command should I run?
END
```

Your agent will suggest a command; run it yourself in another terminal (`docker exec skill-lab
<command>`) and paste the output back, or — if your agent has its own `docker exec` access — just
tell it to run the commands itself and report back.

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

**Note:** these 18 are the skill *image* categories (`casky run`/`casky verify <category>`). The
classifier pipeline's internal `skill_category` grouping (`SUBDOMAIN_TO_CATEGORY` in `harness.py`) is
a coarser 17-value mapping used only for plan-step labeling — `active-directory` evidence, for
example, gets classified under the `identity` category rather than its own bucket. This doesn't
affect which skill gets selected, only how the resulting step is labeled.

## Environment variables reference

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required unless you configure a different `CASKY_MODEL_PROVIDER` (see README) |
| `CASKY_API_KEY` | — | Enables **platform mode** — fetches/syncs plans with casky.ai. Leave unset for fully local/offline use (this, not `CASKY_TOKEN`, is what actually switches the harness into platform mode) |
| `CASKY_RUN_ID` / `CASKY_TOKEN` | — | Link a *single* skill run's findings to a platform run — separate from `CASKY_API_KEY` above |
| `CASKY_APP_URL` | `https://casky.ai` | Platform URL override |
| `SKILL_LAB_NAME` | `skill-lab` | Skill container name |
| `SKILL_IMAGE` | `ghcr.io/casky-ai/skills/web-app:latest` | Skill container image |
| `TARGET_IMAGE` | `ghcr.io/casky-ai/targets/dvwa:latest` | Target container image (lab-custom profile) |

See `.env.example` for the complete annotated list, including BYO-LLM (`CASKY_MODEL_*`) and CVE
enrichment API keys (all optional — NVD + EPSS + CISA KEV work with none of them set).

---

## Testing scenarios

### Scenario 1: Interactive web app investigation (DVWA)

```bash
docker compose --profile lab-dvwa up -d
docker exec skill-lab curl -s -I http://target/ | head -3   # confirm target is up
docker exec -it casky-runner casky run web-app
```

### Scenario 2: Quick tool verification across categories

```bash
docker exec casky-runner casky verify web-app
docker exec casky-runner casky verify cloud
docker exec casky-runner casky verify network
```

### Scenario 3: Platform integration (optional)

1. Set `CASKY_API_KEY` in `.env` (generate at casky.ai)
2. `docker compose --profile lab-dvwa up -d`
3. `docker exec -it casky-runner casky harness` — this now runs in **PLATFORM MODE**, fetching your
   existing investigation plans from casky.ai instead of generating a new one locally
4. Findings sync back to your platform dashboard automatically

### Scenario 4: Air-gapped / fully local

```bash
# Leave CASKY_API_KEY unset (or empty) — this is the default, no action needed
docker compose --profile lab-dvwa up -d
docker exec -it casky-runner casky harness   # local mode: generate a plan from pasted evidence
```

### Scenario 5: Custom target

```bash
export TARGET_IMAGE=myapp:latest
docker compose --profile lab-custom up -d
docker exec skill-lab curl -s -I http://target/ | head -3
docker exec -it casky-runner casky run web-app
```

---

## Troubleshooting

**Skill image tools missing after `casky verify`**
```bash
docker compose pull skill-lab
docker compose --profile lab-dvwa up -d --force-recreate skill-lab
```

**`docker exec` permission denied**
```bash
# Linux only — add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
```

**`docker compose up` fails with "network ... not found"**

Usually stale containers left over from an earlier session holding a reference to a since-recreated
network. Remove the orphans and retry:
```bash
docker rm -f skill-lab casky-target
docker compose --profile lab-dvwa up -d
```

**`casky harness`/`casky run` seems to hang after pasting evidence**

Type `END` on its own line and press Enter rather than relying on Ctrl+D — see the note in step 6
above for why Ctrl+D alone can be ambiguous with pasted multi-line text.

**Platform findings not arriving**
- Confirm `CASKY_API_KEY` (not `CASKY_TOKEN`) is set and valid
- Check runner logs: `docker compose logs -f runner`
- Confirm connectivity: `docker exec casky-runner curl -sI https://casky.ai`

---

## Next steps

- Read [README.md](README.md) for the full architecture, BYO-Agent/LLM/DB configuration, and known limitations
- Read [CLAUDE.md](CLAUDE.md) if you're using an AI coding agent to contribute to this repo
- Read [PHASE1_CONTRACT.md](PHASE1_CONTRACT.md) for the detailed design record of the `casky_pipeline` architecture
