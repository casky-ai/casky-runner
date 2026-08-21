# Casky Box

**An open-source, self-hosted security investigation runtime.** Bring your own AI agent, your own
LLM, and your own database — Casky Box turns raw evidence into a structured, MITRE-mapped
investigation plan and runs it against your own environment. No account, no cloud dependency, no
crippled trial mode: everything in this repo runs standalone.

```
Evidence (paste text or point at logs)
        │
        ▼
Entity extraction (CVE IDs, MITRE T-codes, IPs, hostnames)
        │
        ▼
Context adapters (run concurrently, one failing never blocks the others)
  ├── CveMcpAdapter        — free NVD + EPSS + CISA KEV enrichment (bundled, no API keys required)
  └── LocalPlaybookAdapter — matches your evidence against a starter playbook library,
                              optionally reasoning about intent (not just T-code overlap) if
                              an LLM provider is configured
        │
        ▼
4-stage classifier pipeline (BYO-LLM: Anthropic, OpenAI, Qwen, Kimi, local Ollama/LM Studio/vLLM)
  TechniqueValidator → SkillSelector → (StepOrderer ∥ EvidenceGap)
        │
        ▼
Investigation plan — ordered skill steps, each with a rationale and a MITRE technique,
                      persisted locally, never uploaded anywhere unless you opt in
        │
        ▼
Execution (BYO-Agent: Claude Code, Gemini CLI, GitHub Copilot CLI, or any custom agent binary)
  each step runs against a skill container via `docker exec`, findings come back structured
```

**Optional, not required:** point `CASKY_API_KEY` at [casky.ai](https://casky.ai) and findings sync
to a hosted dashboard, get cert/XP tracking, and gain access to Casky's curated CVE dataset and
cross-customer playbook library. None of that is needed to use this repo for real investigations —
the local pipeline above is the whole product on its own.

---

## Quickstart

```bash
git clone https://github.com/casky-ai/casky-runner.git
cd casky-runner
cp .env.example .env
# Edit .env — at minimum, set ANTHROPIC_API_KEY (or configure a different provider, see below)

# Start the full local stack: runner, skills library, local Postgres, plus a lab target
docker compose --profile lab-dvwa up -d

# Confirm the target is reachable
docker exec skill-lab curl -s -I http://target/ | head -3

# Run an investigation
docker exec -it casky-runner casky run web-app
```

That's it — no `CASKY_API_KEY`, no platform account, no waiting on anything external beyond your
chosen LLM/agent provider.

---

## Bring Your Own Everything

Casky Box has three independent BYO configuration surfaces. None of them require the others.

### BYO-Agent — who executes each investigation step

```bash
casky run web-app --agent claude              # default
casky run web-app --agent gemini
casky run web-app --agent copilot              # requires GITHUB_TOKEN (gh copilot auth)
casky run web-app --agent custom --agent-cmd "my-agent-cli"   # any binary that reads a prompt on stdin
```

### BYO-LLM — which model plans the investigation

The classifier pipeline (the thing that turns evidence into an ordered plan) is model-agnostic.
Configure it in `.env`:

```bash
CASKY_MODEL_PROVIDER=anthropic          # default — uses ANTHROPIC_API_KEY
# CASKY_MODEL_PROVIDER=openai_compatible
# CASKY_MODEL_BASE_URL=https://api.openai.com/v1        # or http://localhost:11434/v1 (Ollama),
#                                                         # http://localhost:1234/v1 (LM Studio),
#                                                         # any vLLM server's /v1 URL
# CASKY_MODEL_NAME=gpt-4o-mini
# CASKY_MODEL_API_KEY=                                    # bearer token, if the endpoint needs one
```

This is separate from `--agent` above — `--agent` picks which coding agent *executes* a step;
`CASKY_MODEL_PROVIDER` picks which LLM *generates the plan itself*.

### BYO-DB — where investigations are stored

The bundled `docker compose` stack ships a local Postgres (`db` service, `casky-db` container) with
zero configuration needed. To point at your own managed Postgres instead — cloud-hosted or
otherwise — set `DATABASE_URL` in `.env` and skip the bundled `db` service. Investigation data never
leaves whichever database you configure; nothing is centralized unless you opt into platform sync.

---

## How a plan actually gets built

1. **Entity extraction** — pure regex, no LLM call: CVE IDs, MITRE technique IDs, IPs, hostnames.
2. **Context adapters run concurrently** (`casky_pipeline/adapters/`):
   - `CveMcpAdapter` wraps the bundled `cve-mcp-server` (stdio, no network config needed) for free
     NVD + EPSS + CISA KEV enrichment on any detected CVE.
   - `LocalPlaybookAdapter` matches your evidence against the starter playbook library in
     `casky_pipeline/playbooks/` (12 playbooks shipped, real MITRE technique coverage — see below
     on contributing more). By default this matches on technique-ID overlap only, which is fast and
     free. If you've configured a BYO-LLM provider, it also does a second pass reasoning about
     whether the evidence's actual narrative matches the playbook's intent — not just coincidental
     T-code overlap — and records its reasoning on the match.
   - If either adapter fails (network hiccup, missing dependency, whatever), the investigation
     **does not stop** — it proceeds with a noted gap instead. This is enforced by
     `run_adapters()`'s `asyncio.gather(..., return_exceptions=True)` fan-out.
3. **4-stage classifier pipeline** (`casky_pipeline/pipeline.py`), fed by the context above:
   - `TechniqueValidator` — confirms which MITRE techniques the evidence actually supports, with
     specific evidence anchors (not just plausible-sounding guesses)
   - `SkillSelector` — picks investigation skills constrained to what's actually in your skills
     library (no invented/hallucinated skill names — this is enforced in code, not just prompted for)
   - `StepOrderer` and `EvidenceGap` run in parallel — one orders the steps, the other identifies
     what additional evidence would strengthen the findings
4. **Plan review** — nothing executes automatically. You see the ordered steps with rationale before
   anything runs.
5. **Execution** — each approved step runs via your chosen `--agent`, against a skill container over
   `docker exec`. Findings come back structured (severity, remediation, MITRE mapping).

---

## Two ways to investigate — and where the lab targets fit in

These are independent, unrelated workflows. Pick whichever matches what you're starting from — you
don't need both, and nothing wires them together automatically.

**A. Evidence-driven — you already have something to analyze.** A CloudTrail export, a suspicious log
line, `tshark`/`tcpdump` output from a pcap, analyst notes. Feed it to the classifier and get an
ordered, MITRE-mapped investigation plan back:

```bash
docker exec -it casky-runner casky harness -i /var/casky/evidence/yourfile.json   # from a file — see below
docker exec -it casky-runner casky harness                                       # or paste it interactively
```

**No lab target is touched in this path at all.** The classifier only reads the text you give it.

**B. Live target practice — you have nothing yet and want to generate real findings from scratch.**
`casky run <category>` runs actual security tools against a real, deliberately-vulnerable target
running in an isolated lab network, no evidence required. The easiest way to start one — this picks
the matching tool image *and* the target automatically:

```bash
make lab TARGET=dvwa                             # any TARGET from the table below
docker exec skill-lab curl -s -I http://target/  # confirm the target is reachable
docker exec -it casky-runner casky run web-app   # category must match the tool image — see table
```

Only one target runs at a time (they all resolve to the stable hostname `target`) — switching
targets means tearing down the old one first: `docker compose --profile lab-<old> down` (or
`docker rm -f casky-target skill-lab` if you hit a "name already in use" error).

**The full target catalogue.** Every target below is a real, published image from
[`casky-ai/skill-targets`](https://github.com/casky-ai/skill-targets) (`dvwa`/`juice-shop` use
well-known third-party images instead — same effect). Each pairs with one of the 18 real tool
images from [`casky-ai/skill-images`](https://github.com/casky-ai/skill-images); `make lab` sets
`SKILL_IMAGE` for you, so `skill-lab` is always built with the right tools for the category you
picked, not just whatever it happened to be built with last.

| `TARGET=` | Skill category (`casky run <category>`) | Best for |
|---|---|---|
| `dvwa` | `web-app` | SQL injection, XSS, CSRF, auth bypass — the default in Quickstart above |
| `juice-shop` | `web-app` | Same tool set, faster to start, no database to wait on |
| `vulnstack` | `vuln-scan` | CVE scanning, version detection, misconfiguration |
| `metasploitable` | `exploitation` | Service exploitation, vsftpd backdoor, Samba |
| `vulnservices` | `exploitation` | vsftpd backdoor, Samba, Tomcat AJP Ghostcat |
| `linux-pivot` | `post-exploit` | SUID, weak sudo, writable cron, shadow read |
| `minidc` | `active-directory` (or `identity`) | Kerberoast, AS-REP roast, ACL abuse, LDAP enum |
| `pcap-server` | `network` | FTP/Telnet cleartext, DNS tunnel detection |
| `localstack` | `cloud` | S3 misconfig, IAM enumeration, hardcoded Lambda secrets |
| `vulncode` | `appsec` | SAST, SQLi, path traversal, secrets in git history |
| `evidence-pack` | `forensics` (or `incident-response`) | Disk triage, MFT timeline, lateral movement logs |
| `sample-pack` | `malware` | YARA, static analysis, deobfuscation, IOC extraction — **private on GHCR**, `docker login ghcr.io` with org access first |
| `custom` | whatever you set `SKILL_IMAGE=` to | Your own image (`export TARGET_IMAGE=...`) |

Without `make lab`, the equivalent is `SKILL_IMAGE=ghcr.io/casky-ai/skills/<category>:latest
docker compose --profile lab-<target> up -d --build` — `make lab` just remembers the pairing so you
don't have to.

**Combining them yourself.** Nothing does this for you, but it's a legitimate manual pattern: attack a
lab target live, capture the resulting traffic (`tcpdump` on the `casky-lab` network while you run
`casky run`), then feed *that* capture back into `casky harness -i` as evidence — a way to close the
loop from "generate an incident" to "get an investigation plan for it." See
[`evidence/README.md`](evidence/README.md) for the `-i`/`--input-file` flag, the `./evidence/` bind
mount, and evidence size limits.

---

## Commands

| Command | Description |
|---|---|
| `casky run <skill> [--agent claude\|gemini\|copilot\|custom] [--agent-cmd "<binary>"]` | Run a single skill investigation |
| `casky verify <skill>` | Check the skill container has all required tools |
| `casky harness [-i\|--input-file <path>] [--auto]` | Run the full investigation harness (entity extraction → adapters → plan → execution). `-i` reads evidence from a file instead of the interactive paste prompt — drop it in `./evidence/` on the host (bind-mounted read-only to `/var/casky/evidence`, see `docker-compose.yml`) and pass the in-container path. |

## Environment variables

| Variable | Purpose | Required? |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude Code agent + default classifier LLM | Required unless using a different `CASKY_MODEL_PROVIDER` |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Gemini CLI agent | Only if using `--agent gemini` |
| `GITHUB_TOKEN` | GitHub Copilot CLI agent | Only if using `--agent copilot` |
| `CASKY_MODEL_PROVIDER` / `CASKY_MODEL_BASE_URL` / `CASKY_MODEL_NAME` / `CASKY_MODEL_API_KEY` | BYO-LLM for the classifier pipeline | Optional — defaults to Anthropic |
| `DATABASE_URL` | Point at your own Postgres instead of the bundled `db` service | Optional |
| `SKILL_LAB_NAME` | Name of the running skill container | Optional, default `skill-lab` |
| `CASKY_APP_URL` | Platform URL override | Optional, only relevant if syncing to casky.ai |
| `CASKY_API_KEY` | **This is what switches `casky harness` into platform mode** (fetches/syncs investigation plans with casky.ai). Leave unset for fully local/offline use — this is the one that matters for "am I in local or platform mode?" | Optional |
| `CASKY_RUN_ID` / `CASKY_TOKEN` | A *separate* mechanism from `CASKY_API_KEY` above — links one `casky run <skill>` execution's findings back to a specific platform run via `POST /api/runs/[id]/report`. Not what you need for general plan sync | Optional |
| `NVD_API_KEY`, `SHODAN_KEY`, `VIRUSTOTAL_KEY`, `GREYNOISE_API_KEY`, etc. | Extra CVE MCP enrichment sources | Optional — NVD + EPSS + CISA KEV work with none of these set |

See `.env.example` for the full annotated list.

---

## Skills

Each skill maps 1-to-1 to an image in [casky-ai/skill-images](https://github.com/casky-ai/skill-images).
The underlying skill definitions (817+ skills, MITRE/NIST/OWASP-mapped, Apache 2.0) live in the
public [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
registry.

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

Target images are published from [casky-ai/skill-targets](https://github.com/casky-ai/skill-targets)
to `ghcr.io/casky-ai/targets/<name>:latest`.

### Investigation playbooks

`casky_pipeline/playbooks/` ships 12 starter playbooks (credential dumping, cloud IAM privilege
escalation, web-app SQLi, network lateral movement, Kerberoasting, ransomware triage, and more) —
see the directory for the full list. Playbooks are plain YAML; contributing new ones is one of the
highest-leverage ways to help this project (see Contributing below).

---

## Local development

```bash
make build          # build the runner image (casky-runner:dev)
make pytest          # run the casky_pipeline unit test suite (adapters, pipeline, llm_providers)
make test            # pytest + the image-level integration test harness
make test-compose    # test the full docker-compose stack
make scan            # Trivy HIGH/CRITICAL scan
make lint            # shellcheck casky.sh
make shell           # bash shell inside the runner image
make run SKILL=web-app AGENT=claude
make verify SKILL=web-app   # confirm skill-lab has all required tools
```

`make pytest` creates a local `.venv` on first run if one doesn't exist (`pytest`,
`pytest-asyncio`, `anthropic`, `requests`, `pyyaml`, `rich`, `mcp`).

---

## Project layout

```
casky-runner/
├── harness.py               Core investigation harness — entity extraction, adapter fan-out,
│                             pipeline invocation, execution dispatch, local report server
├── casky.sh                 The `casky` CLI wrapper (run/verify/harness/help)
├── casky_pipeline/          Context adapters, 4-stage classifier, BYO-LLM provider layer
│   ├── adapters/            ContextEngineAdapter interface + CveMcpAdapter + LocalPlaybookAdapter
│   ├── playbooks/            Starter investigation playbook library (YAML)
│   ├── pipeline.py           TechniqueValidator → SkillSelector → (StepOrderer ∥ EvidenceGap)
│   ├── llm_providers.py      AnthropicProvider / OpenAICompatibleProvider / build_provider_from_env()
│   └── tests/                 pytest suite — run via `make pytest`
├── docker-compose.yml        Full local stack: runner, skills library, Postgres, lab targets
├── docker/                   Dockerfiles for skill/target/MCP containers
├── skills/                   Per-skill tool manifests (used by `casky verify`)
├── tests/                    Shell-based image/compose integration tests
├── CLAUDE.md                 Guidance for AI coding agents working in this repo
└── PHASE1_CONTRACT.md        Design record of the casky_pipeline architecture — useful background
                               if you're extending the adapter/pipeline system
```

---

## Optional: syncing to the Casky platform

If you want a hosted dashboard, cert/XP tracking, or access to Casky's curated CVE dataset and
cross-customer playbook library on top of everything above:

```bash
# 1. Create a workspace at casky.ai and get a Runner Token
# 2. Set it in .env (or your environment) — this is the variable that actually
#    switches `casky harness` into platform mode, not CASKY_TOKEN:
export CASKY_API_KEY=csk_...

# 3. `casky harness` now runs in PLATFORM MODE — fetching and syncing
#    investigation plans with your casky.ai workspace instead of generating
#    them locally. Confirm which mode you're in from the banner it prints.
```

This is entirely additive — nothing in this repo depends on it, and you can start/stop syncing at
any time without losing local functionality.

---

## Known limitations

Being upfront about where this stands, not glossing over gaps:

- `LocalPlaybookAdapter`'s intent-based matching only activates when a BYO-LLM provider is
  configured; without one, matching falls back to technique-ID overlap only (still useful, just
  less precise about genuine narrative intent vs. coincidental T-code overlap).
- Prompt caching (for deployments using Anthropic) benefits some pipeline stages more than others —
  it's on by default for the classifier pipeline here, but a genuinely one-off system prompt would
  need to opt out explicitly via `cacheable_system=False`.
- Local investigation memory (learning from your own past investigations over time, not just the
  static starter playbooks) isn't built yet — the current pipeline doesn't carry context forward
  between separate runs.
- The classifier's internal `skill_category` grouping (`SUBDOMAIN_TO_CATEGORY` in `harness.py`) is
  coarser than the 18 real skill-image categories — e.g. `active-directory` evidence gets labeled
  under `identity` rather than its own category. This only affects plan-step labeling, not which
  skill actually gets selected or run.
- `casky verify`/`make verify` check tool presence in a running skill container, not full
  correctness of every tool's output.
- `skill-lab` only builds against one `SKILL_IMAGE` at a time — running multiple categories
  simultaneously (e.g. `web-app` and `network` tools both available at once) isn't supported;
  switch categories by rebuilding (`make lab TARGET=<name>` again).
- `skill-targets`' own README documents `targets/evidence-pack` as GHCR-private, but it currently
  pulls successfully with no authentication configured — likely a visibility setting that drifted
  from what's documented, not an intentional access change. Flagged upstream; don't rely on this
  either way (it may become genuinely gated, or the docs may just need correcting) — `sample-pack`
  is confirmed genuinely private and needs `docker login ghcr.io` with org access regardless.

---

## Contributing

- New playbooks: add a YAML file to `casky_pipeline/playbooks/` following the existing schema.
- New adapters: implement `ContextEngineAdapter` in `casky_pipeline/adapters/` — see `base.py` for
  the interface and `cve_mcp_adapter.py` for a minimal example.
- Read `CLAUDE.md` first if you're using an AI coding agent to contribute — it documents this
  repo's conventions, including the prompt-caching pattern all new LLM call sites should follow.

## CI

- **build.yml** — builds the runner image, runs Trivy (HIGH/CRITICAL exit-code 1), pushes to GHCR on `main`.
- **test.yml** — matrix over all skills; pulls the corresponding skill image, runs `casky verify`.

## License

Apache 2.0 — see `LICENSE`. Matches the license already used by the
[skills-registry](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) this repo depends on.
