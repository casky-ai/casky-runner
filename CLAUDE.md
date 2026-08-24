# Casky Runner (Casky Box) — Engineering Notes

## What this is

The **Casky Box**: an open-source, self-hosted investigation runtime — the CLI/Docker
counterpart to the closed-source `casky.ai` SaaS platform (`claude-skills-security` repo,
a sibling, *not* a dependency of this one). Ships Claude Code + Gemini CLI in a minimal
Ubuntu container; drives security investigations by issuing commands into a skill
container via `docker exec`, against a target container on an isolated Docker network.

Three BYO axes, all independently configurable:

| Axis | What you bring | Status |
|---|---|---|
| **BYO-Agent** | Claude Code, Gemini CLI, GitHub Copilot CLI, or any custom binary | Live |
| **BYO-LLM** | Anthropic or any OpenAI-compatible endpoint for the classifier pipeline | Live (Phase 1) |
| **BYO-DB** | Bring your own Postgres for plan/run/outcome/memory persistence via `casky_db` | **Live** — optional, `DATABASE_URL`; JSON-file storage is the fallback/default when unset, not a stub |

## Repo layout

| Path | Role |
|---|---|
| `harness.py` | Core CLI harness — entity extraction, adapter fan-out, pipeline invocation, execution dispatch, outcome capture, report synthesis. Single large file; see "Token economy" below before reading it whole. Fully wired to `casky_pipeline/` (see module map below) — this is not a pending integration pass. |
| `casky.sh` | The `casky` wrapper CLI (`casky run`, `casky verify`, `casky harness`, `casky skills`) — agent-CLI dispatch lives here. |
| `casky_pipeline/` | 4-stage classifier pipeline + adapters + memory layer + BYO-LLM provider layer. See module map below. |
| `casky_db/` | Postgres persistence layer (`store.py` plain-SQL repository functions, `migrations/`) — optional, see BYO-DB above. |
| `casky-ui/` | Self-hosted Next.js UI reading the `casky_db` schema directly — see README's "Casky UI" section. Requires `DATABASE_URL`; no JSON-file fallback (unlike the harness). |
| `docker-compose.yml`, `docker/` | Lab network services: runner, CVE MCP server, skill containers, target containers (DVWA/Juice Shop/custom). |
| `tests/` | Shell-based integration tests (`run-tests.sh`, `compose-test.sh`, `fixtures/`) — pre-date the adapter/pipeline system, cover the container/CLI layer. |
| `skills/` | Per-skill tool manifests, used by `casky verify`. |
| `PHASE1_CONTRACT.md` | Original interface contract for the pipeline/adapter work — useful background on the design, not a live status doc; some of its "future work" items (BYO-DB, historical/memory adapters) have since shipped. |

### `casky_pipeline/` module map

```
casky_pipeline/
├── llm_providers.py              # LLMProvider ABC, AnthropicProvider, OpenAICompatibleProvider,
│                                  # build_provider_from_env()
├── pipeline.py                   # 4-stage classifier: TechniqueValidator -> SkillSelector ->
│                                  # (StepOrderer parallel with EvidenceGap) -> run_pipeline()
├── memory.py                     # Memory extraction (LLM stage), decay math, dual-mode
│                                  # (Postgres/JSON-file) storage + entity-overlap retrieval
├── adapters/
│   ├── base.py                   # ContextEngineAdapter ABC, GraphNode/GraphEdge/AdapterResult,
│   │                              # run_adapters() (concurrent, one bad adapter never blocks others)
│   ├── cve_mcp_adapter.py        # CveMcpAdapter — ports harness.py's enrich_with_cve_mcp() (stdio MCP)
│   ├── local_playbook_adapter.py # LocalPlaybookAdapter — matches playbooks/*.yaml by MITRE technique
│   ├── local_history_adapter.py  # LocalHistoryAdapter — past investigations via casky_db.store.find_related()
│   └── memory_adapter.py         # MemoryAdapter — organizational memory via casky_pipeline.memory
├── playbooks/                    # 12 starter YAML playbooks, one per MITRE-domain category
└── tests/                        # pytest unit tests, one file per module above
```

All four adapters above are wired into the fan-out in `harness.py`'s `generate_local_plan()` — none
of this is aspirational or pending integration.

### `LocalSkillsLibrary` (in `harness.py`) — leveraging each skill's full artifact set

Not just `SKILL.md`. `get_executable_script(slug)` resolves `scripts/agent.py` or `scripts/process.py`
(agent.py wins when both exist — every skill has at least one of the two), `get_reference_files(slug)`
returns whatever `references/*.md` a skill ships (no fixed filename set), `get_report_template(slug)`
resolves `assets/template.md` when present. `assemble_prompt(plan, step)` injects all three into the
step prompt when they exist for that step's skill — additive to `skill_document`, never a replacement,
and silently skipped when absent (not every skill ships every artifact). `symlink_for_native_loading(slug)`
additionally symlinks the skill into `~/.claude/skills/<slug>/` right before `AgentWorker.execute()`
spawns `casky run`, so `claude --print` discovers it as a first-class Skill — best-effort, never
raises, since the prompt-injected guidance already works without it. See README's "How the agent uses
a skill" for the user-facing explanation of why (steering, not enforcement — matches how the upstream
skills library's own Black Hat Arsenal deployment uses it).

## BYO configuration (env vars)

**Agent CLI selection** (`casky run <category> --agent <name>`, dispatched in `casky.sh`):

| Var | Used by |
|---|---|
| `ANTHROPIC_API_KEY` | `--agent claude` (Claude Code CLI) |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | `--agent gemini` (Gemini CLI) |
| `GITHUB_TOKEN` | `--agent copilot` (GitHub Copilot CLI) |
| — (pass `--agent-cmd "<binary>"`) | `--agent custom` |

**Classifier LLM selection** (`casky_pipeline/llm_providers.py`, `build_provider_from_env()`):

| Var | Purpose | Default |
|---|---|---|
| `CASKY_MODEL_PROVIDER` | `anthropic` \| `openai_compatible` | `anthropic` |
| `CASKY_MODEL_BASE_URL` | Required when `openai_compatible` (OpenAI, Ollama, LM Studio, vLLM, …) | — |
| `CASKY_MODEL_NAME` | Model id | `claude-haiku-4-5` (anthropic) / `gpt-4o-mini` (openai_compatible) |
| `CASKY_MODEL_API_KEY` | Bearer token for `openai_compatible` backends that require one | — |
| `CASKY_MODEL_TEMPERATURE` | Sampling temperature for every pipeline stage's LLM call | `0.0` — deliberately not the API's own default (1.0); every stage is classification/extraction, and 0.0 is what fixes the run-to-run "same evidence, different validated techniques/skills" variance (see `AnthropicProvider`'s `extra_body` note: this SDK version removed `temperature` from `messages.create()`'s typed signature, but the REST API still honors it) |

**Persistence:** `DATABASE_URL` for BYO-DB is live — set it to use Postgres via `casky_db`; leave it
unset and everything (plans, reports, outcomes, memories) falls back to JSON files under `~/.casky/`
and `/var/casky/reports/`, which is the default/expected mode for most installs, not a degraded one.

Other harness-level vars (`CASKY_API_KEY`, `CASKY_APP_URL`, `CASKY_TOKEN`, `CASKY_RUN_ID`,
`SKILL_LAB_NAME`, `CASKY_CONCURRENCY`, `SKILLS_LIBRARY_PATH`) are unchanged by Phase 1 — see
`harness.py`'s `Config` dataclass and `README.md`/`QUICKSTART.md` for the full reference tables.

## Running tests

```bash
# Pipeline/adapter/memory code (no real network or DB I/O — casky_db is mocked)
pytest casky_pipeline/tests/

# Postgres-backed persistence layer — needs a real, reachable Postgres (skips
# cleanly, not a failure, when DATABASE_URL is unset/unreachable — see
# casky_db/tests/conftest.py's docstring for how to point one at it locally)
pytest casky_db/tests/

# Shell-based integration tests (container/CLI layer, pre-dates the adapter/pipeline system)
tests/run-tests.sh
tests/compose-test.sh
```

## Token economy

This file and `PHASE1_CONTRACT.md` exist to cut exploration cost in a repo with a large
single-file harness and a freshly-landed multi-module package. Before touching the
pipeline/adapters:

1. **Read `PHASE1_CONTRACT.md` and this file first.** The interface contracts (dataclass
   shapes, adapter signatures, `LLMProvider` interface, module layout) are already fully
   specified there — don't re-derive them by re-reading every file in `casky_pipeline/`
   from scratch.
2. **Every new LLM call site in `casky_pipeline/` goes through
   `LLMProvider.complete(..., cacheable_system=True)`** — never construct a raw
   Anthropic/OpenAI client call directly inside a pipeline stage. `cacheable_system=True`
   is the default for a reason: it's what makes Anthropic prompt caching actually take
   effect for that call. A bypassed call site silently loses the cost savings — no error,
   no warning, just a bigger bill.
3. **Prefer targeted `Read` with line ranges over reading a whole file** when you already
   know the function/class you need exists. `harness.py` is the canonical example — it's
   one large file (~47K bytes) with clearly line-numbered sections (see
   `PHASE1_CONTRACT.md` Section 1 for a map of what lives where); read the 20-40 lines you
   need, not the whole file, unless you're doing a full audit.

## Where the detailed contract lives

`PHASE1_CONTRACT.md` documents the Phase 1 interface contract in full (dataclass fields,
adapter behavior, playbook YAML schema, `LLMProvider` implementations, per-agent file
ownership). This file intentionally does not duplicate it — go there for specifics.
