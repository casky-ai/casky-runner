# Casky Box — Quick Start

Run structured security investigations locally using Casky Box (`casky-runner`) — no account, no
cloud dependency required. See [README.md](README.md) for the full architecture and BYO-Agent /
BYO-LLM / BYO-DB configuration reference; this doc is a hands-on walkthrough.

**What this gives you:**
- A local lab network with security tools (skill containers) and a target application to practice against
- `casky harness` — evidence in, an ordered MITRE-mapped investigation plan out, via the 4-stage
  classifier pipeline described in [README.md](README.md#how-a-plan-actually-gets-built)
- `casky run <skill>` — interactive, human-in-the-loop investigation guided by your chosen coding agent
- `casky run <skill> --live-target` — the same, but against a real, authorized target (a container,
  URL, or API endpoint) instead of the practice lab — see Path C in step 6 below
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

The easiest way — this also builds `skill-lab` with the *matching* tool image, not whatever it was
built with last:

```bash
make lab TARGET=dvwa
```

`TARGET` is any of: `dvwa`, `juice-shop`, `vulnstack`, `metasploitable`, `vulnservices`,
`linux-pivot`, `minidc`, `pcap-server`, `localstack`, `vulncode`, `evidence-pack`, `sample-pack`,
`custom`. Each pairs with a specific skill category (`casky run <category>` must match — `make lab`
prints which `SKILL_IMAGE` it used so you know) — see the full table in
[README.md](README.md#two-ways-to-investigate--and-where-the-lab-targets-fit-in).

**Starts:** `casky-runner`, `db` (local Postgres), `skill-lab` (built from the matching
`ghcr.io/casky-ai/skills/<category>:latest`), the target container (`casky-target`) — plus
`target-db` (MySQL) if you picked `dvwa`, the only target with a database dependency.

**Only one target runs at a time** — they all share the stable hostname `target`. Switching means
tearing down the old one first:
```bash
docker compose --profile lab-<old-target> down
# or, if you hit "name already in use":
docker rm -f casky-target skill-lab
```

**`sample-pack` is private on GHCR** (real malware samples, deliberately gated) — `docker login
ghcr.io` with org access before pulling it. Every other target is public.

**Custom target — bring your own container:**

```bash
export TARGET_IMAGE=your-custom:latest
make lab TARGET=custom   # defaults SKILL_IMAGE to web-app; override it yourself if you need
                          # different tools, e.g. SKILL_IMAGE=ghcr.io/casky-ai/skills/cloud:latest
```

Your image needs to listen on port 80 and join the `casky-lab` network — `docker-compose.yml` wires
this up automatically once `TARGET_IMAGE` is set.

Without `make lab`, the equivalent is `SKILL_IMAGE=ghcr.io/casky-ai/skills/<category>:latest
docker compose --profile lab-<target> up -d --build`.

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

And confirm Casky UI is up (no extra flag needed — it's part of the default `docker compose up`):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8766/login
```

Expect `200`. See step 7 below for first login.

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

**Executing the plan** (`--auto`, or stepping through the printed runbook manually): for each step,
the agent is pointed at that skill's own tested script (`scripts/agent.py`/`process.py`), reference
material, and report template — not left to invent commands from scratch. See README's "How the
agent uses a skill" for what's actually happening under the hood.

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

`skill-lab` (used by Paths A and B above) deliberately has no internet access — it's an isolated
practice sandbox. If you need to point live tools at a **real, authorized target** instead (a
container, a URL, an API endpoint), that's Path C below, not this one.

### Path C — live, authorized real-target investigations (`casky run --live-target`)

This uses `skill-live` instead of `skill-lab` — same tools, but with real internet/DNS egress —
and only ever runs against infrastructure you're explicitly authorized to test (see
[`SECURITY.md`](SECURITY.md)):

```bash
make live LIVE_TARGET=https://staging.example.com AUTHORIZED=yes SKILL=web-app AGENT=claude
```

Both `AUTHORIZED=yes` and authorization confirmation at the `casky run` level are required every
time — there's no way to set this once and forget it. You'll see a `[casky] LIVE TARGET MODE`
banner before anything runs, confirming exactly what target and mode you're in. `LIVE_TARGET` can
be a hostname, a full URL/API endpoint, or an existing container's name (run `docker network
connect <its-network> skill-live` first so `skill-live` can actually reach it).

Without `make live`:

```bash
SKILL_IMAGE=ghcr.io/casky-ai/skills/web-app:latest docker compose --profile live up -d --build skill-live
docker exec skill-live curl -sI https://staging.example.com   # confirm reachability first
docker exec -it casky-runner casky run web-app --live-target https://staging.example.com --i-have-authorization
```

## 7. Browse results in Casky UI

Everything from step 6 — the plan, findings, remediation status, the outcome you recorded, and any
organizational memory it surfaced — is queryable from a browser, not just the terminal.

**First login:**
```bash
docker compose logs ui | grep -A5 "ADMIN PASSWORD"
```
That prints the auto-generated admin password once (only on first boot — it won't show up again on
a restart, and the password itself doesn't change on restart either). If you'd rather set your own,
put `CASKY_UI_ADMIN_PASSWORD=<your-choice>` in `.env` *before* first bringing the stack up.

Open **http://127.0.0.1:8766**, log in, and check:
- **Dashboard** — investigation/finding counts
- **Investigations → [your investigation]** — the 8-tab detail view; `Execution` is the
  chronological trace of what actually ran, `Outcome / Memory` is where a recorded outcome and any
  extracted organizational memory show up
- **Findings** — cross-investigation, filterable by severity/status
- **Reports** — the consolidated report, downloadable as Markdown

It's read/browse plus two narrow write paths (finding status, remediation notes) — you still start
new investigations from the CLI (`casky harness`/`casky run`), not from the UI.

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
| `SKILL_IMAGE` | `ghcr.io/casky-ai/skills/web-app:latest` | Which of the 18 real skill tool images `skill-lab` is built from — `make lab TARGET=<name>` sets this to match automatically; see the target/category table above |
| `TARGET_IMAGE` | `alpine:latest` | Target container image, `lab-custom` profile only |
| `DATABASE_URL` | bundled `db` service | Point Casky UI + the harness's persistence layer at your own Postgres instead |
| `CASKY_UI_ADMIN_PASSWORD` | auto-generated on first boot | Casky UI's single-admin login — see step 7 |
| `CASKY_UI_PORT` | `8766` | Host port Casky UI is reachable on |

See `.env.example` for the complete annotated list, including BYO-LLM (`CASKY_MODEL_*`) and CVE
enrichment API keys (all optional — NVD + EPSS + CISA KEV work with none of them set).

---

## Testing scenarios

### Scenario 1: Interactive web app investigation (DVWA)

```bash
make lab TARGET=dvwa
docker exec skill-lab curl -s -I http://target/ | head -3   # confirm target is up
docker exec -it casky-runner casky run web-app
```

### Scenario 2: Tool verification across categories

`skill-lab` only has one category's tools at a time — verifying a different category means
rebuilding for it first (each `make lab` call replaces the previous build):

```bash
make lab TARGET=dvwa && docker exec casky-runner casky verify web-app
make lab TARGET=localstack && docker exec casky-runner casky verify cloud
make lab TARGET=pcap-server && docker exec casky-runner casky verify network
```

### Scenario 3: Platform integration (optional)

1. Set `CASKY_API_KEY` in `.env` (generate at casky.ai)
2. `make lab TARGET=dvwa`
3. `docker exec -it casky-runner casky harness` — this now runs in **PLATFORM MODE**, fetching your
   existing investigation plans from casky.ai instead of generating a new one locally
4. Findings sync back to your platform dashboard automatically

### Scenario 4: Air-gapped / fully local

```bash
# Leave CASKY_API_KEY unset (or empty) — this is the default, no action needed
make lab TARGET=dvwa
docker exec -it casky-runner casky harness   # local mode: generate a plan from pasted evidence
```

### Scenario 5: Custom target

```bash
export TARGET_IMAGE=myapp:latest
make lab TARGET=custom   # override SKILL_IMAGE=... too if your image needs non-web-app tools
docker exec skill-lab curl -s -I http://target/ | head -3
docker exec -it casky-runner casky run web-app
```

### Scenario 6: A different lab target/category (e.g. network recon against pcap-server)

```bash
make lab TARGET=pcap-server
docker exec skill-lab which tshark tcpdump masscan   # confirm the right tools landed
docker exec -it casky-runner casky run network
```

### Scenario 7: Live, authorized real-target investigation

Only against infrastructure you have explicit authorization to test — see
[`SECURITY.md`](SECURITY.md).

```bash
make live LIVE_TARGET=https://staging.example.com AUTHORIZED=yes SKILL=web-app AGENT=claude
```

Both `AUTHORIZED=yes` and `--i-have-authorization` (passed through automatically by `make live`)
are required every time — omit either and it refuses to run. You'll see a `[casky] LIVE TARGET
MODE` banner confirming the target before anything executes. `LIVE_TARGET` can also be an existing
container's name if you first run `docker network connect <its-network> skill-live` so `skill-live`
can actually reach it.

---

## Troubleshooting

**Starting completely fresh (ghost containers, stale volumes, switching targets)**

The lighter fix below (remove orphans, retry) covers most cases. For a full reset — no leftover
containers, no stale Postgres data, nothing holding a reference to a since-recreated network:
```bash
docker rm -f casky-runner casky-skills casky-db casky-ui skill-lab casky-target casky-target-db 2>/dev/null
docker compose down -v   # -v also removes volumes (investigation data, Postgres data) — omit to keep them
docker compose --profile lab-dvwa up -d   # or whichever target you're using
```

**Skill image tools missing / wrong category after `casky verify`**

`skill-lab` is built locally (not pulled) from whichever `SKILL_IMAGE` it was last built with —
rebuild it for the category you actually want:
```bash
make lab TARGET=<matching-target>   # e.g. TARGET=pcap-server for network tools
# or manually:
SKILL_IMAGE=ghcr.io/casky-ai/skills/<category>:latest docker compose --profile lab-<target> up -d --build
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
