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
| **BYO-DB** | Bring your own Postgres for plan/run persistence | **Not built** — Phase 2, do not claim it exists |

## Repo layout

| Path | Role |
|---|---|
| `harness.py` | Core CLI harness — plan generation, step execution, report synthesis. Single large file; see "Token economy" below before reading it whole. |
| `casky.sh` | The `casky` wrapper CLI (`casky run`, `casky verify`, `casky harness`, `casky skills`) — agent-CLI dispatch lives here. |
| `casky_pipeline/` | New package (Phase 1): 4-stage classifier pipeline + adapters + BYO-LLM provider layer. See module map below. |
| `docker-compose.yml`, `docker/` | Lab network services: runner, CVE MCP server, skill containers, target containers (DVWA/Juice Shop/custom). |
| `tests/` | Shell-based integration tests (`run-tests.sh`, `compose-test.sh`, `fixtures/`) — pre-date Phase 1, cover the container/CLI layer. |
| `plans/`, `skills/` | Sample plans and the local skills library layout. |
| `PHASE1_CONTRACT.md` | Interface contract for the Phase 1 pipeline work — see "Token economy" below. |

### `casky_pipeline/` module map (Phase 1 — some paths land as this phase's parallel agents finish)

```
casky_pipeline/
├── llm_providers.py              # LLMProvider ABC, AnthropicProvider, OpenAICompatibleProvider,
│                                  # build_provider_from_env()
├── pipeline.py                   # 4-stage classifier: TechniqueValidator -> SkillSelector ->
│                                  # (StepOrderer parallel with EvidenceGap) -> run_pipeline()
├── adapters/
│   ├── base.py                   # ContextEngineAdapter ABC, GraphNode/GraphEdge/AdapterResult,
│   │                              # run_adapters() (concurrent, one bad adapter never blocks others)
│   ├── cve_mcp_adapter.py        # CveMcpAdapter — ports harness.py's enrich_with_cve_mcp() (stdio MCP)
│   └── local_playbook_adapter.py # LocalPlaybookAdapter — matches playbooks/*.yaml by MITRE technique
├── playbooks/                    # 12 starter YAML playbooks, one per MITRE-domain category
└── tests/                        # pytest unit tests, one file per module above
```

`harness.py` and `casky.sh` are **not** rewired to `casky_pipeline/` yet — that's a separate
integration pass (see `PHASE1_CONTRACT.md` Section 6) after the parallel agents land.

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

**Persistence:** `DATABASE_URL` for BYO-DB is **Phase 2, not yet built** — don't wire to it or
document it as available.

Other harness-level vars (`CASKY_API_KEY`, `CASKY_APP_URL`, `CASKY_TOKEN`, `CASKY_RUN_ID`,
`SKILL_LAB_NAME`, `CASKY_CONCURRENCY`, `SKILLS_LIBRARY_PATH`) are unchanged by Phase 1 — see
`harness.py`'s `Config` dataclass and `README.md`/`QUICKSTART.md` for the full reference tables.

## Running tests

```bash
# New Phase 1 pipeline code (adapters, pipeline, llm_providers)
pytest casky_pipeline/tests/

# Existing shell-based integration tests (container/CLI layer, pre-dates Phase 1)
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
