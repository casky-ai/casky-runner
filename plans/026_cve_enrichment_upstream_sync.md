# Plan: CVE Enrichment Pipeline + Upstream Sync for casky-runner

**Created:** 2026-06-12  
**Status:** Approved & Ready for Implementation  
**Session:** Phase 2 Implementation

## Implementation Timeline

| # | Task | Status | Completed |
|---|------|--------|-----------|
| 1 | `docker/skills/Dockerfile` — multi-stage skills library build | ✅ Done | 2026-06-12 |
| 2 | `.github/workflows/build-skills.yml` — CI/CD for skills image | ✅ Done | 2026-06-12 |
| 3 | `docker-compose.yml` — casky-skills init service + volume mounts | ✅ Done | 2026-06-12 |
| 4 | `harness.py` — `LocalSkillsLibrary`, `generate_local_plan()`, SUBDOMAIN_TO_CATEGORY | ✅ Done | 2026-06-12 |
| 5 | `casky.sh` — `skills list/show/verify` subcommand | ✅ Done | 2026-06-12 |
| 6 | `.env.example`, QUICKSTART.md, INVESTIGATION_GUIDE.md — docs | ✅ Done | 2026-06-12 |
| 7 | `TESTING_SKILLS_LIBRARY.md`, `QUICK_TEST_REFERENCE.md` | ✅ Done | 2026-06-12 |
| 8 | Fix `build-skills.yml` date step ordering bug | 🔲 Todo | — |
| 9 | `Dockerfile` — add `mcp` + `anthropic` to casky-console venv | 🔲 Todo | — |
| 10 | `harness.py` — `extract_entities()` (pure regex, mirrors entity-extractor.ts) | 🔲 Todo | — |
| 11 | `harness.py` — `enrich_with_cve_mcp()` (MCP SDK stdio, direct Python) | 🔲 Todo | — |
| 12 | `harness.py` — `fetch_platform_cve_spotlights()` (optional, needs CASKY_API_KEY) | 🔲 Todo | — |
| 13 | `harness.py` — `find_similar_local_plans()` (local ~/.casky/plans/ few-shot) | 🔲 Todo | — |
| 14 | `harness.py` — `fetch_platform_playbooks()` (optional, needs CASKY_API_KEY) | 🔲 Todo | — |
| 15 | `harness.py` — replace `subprocess` in `generate_local_plan()` with Anthropic SDK | 🔲 Todo | — |
| 16 | `harness.py` — update `Plan` dataclass (cve_references, evidence_gaps, confidence) | 🔲 Todo | — |
| 17 | `.github/workflows/sync-skills.yml` — daily upstream sync with version tracking | 🔲 Todo | — |
| 18 | `docker/skills/.last-sync` — version tracking file | 🔲 Todo | — |
| 19 | Commit + push all changes | 🔲 Todo | — |

**Tests (to run after implementation):**
| # | Test | Expected Result |
|---|------|----------------|
| T1 | `python3 -m py_compile harness.py` | No errors |
| T2 | `extract_entities("CVE-2024-3400 T1078 192.168.1.1")` | Returns populated ExtractedEntities |
| T3 | `docker exec -it casky-runner python3 -c "import asyncio; from harness import enrich_with_cve_mcp; print(asyncio.run(enrich_with_cve_mcp(['CVE-2024-3400'])))"` | Returns CVSS/KEV data from MCP |
| T4 | `casky harness` → `[g]` → paste evidence with CVE → check saved plan JSON | `cve_references`, `confidence`, `suggested_evidence_gaps` present |
| T5 | With `CASKY_API_KEY` set: same plan generation → check playbook enrichment | Platform playbooks + CVE skill_ids appear in context |
| T6 | `workflow_dispatch` `sync-skills.yml` force=true | Image rebuilt, `.last-sync` committed |
| T7 | `build-skills.yml` trigger | `:YYYYMMDD` tag appears in ghcr.io |

---

## Context

The current `generate_local_plan()` in `harness.py` only calls Haiku with raw evidence + skill summaries. The casky.ai platform (`claude-skills-security`) runs a richer 3-phase pipeline before classifying: entity extraction → CVE enrichment → historical similarity → Haiku with full context. casky-runner already has the CVE MCP server installed and registered (via `entrypoint.sh`), but `generate_local_plan()` never calls it. Additionally, the `casky-skills` Docker image has no automated rebuild when the upstream mukul975 library releases new skills — both repos need a sync workflow.

**Goal:** Bring `generate_local_plan()` to platform parity for the pieces casky-runner can support, and establish a daily auto-sync pipeline from mukul975 into the `casky-skills` image.

---

## What the Platform Does vs What We Can Replicate

| Platform phase | Platform source | casky-runner equivalent | Available? |
|---|---|---|---|
| Entity extraction (CVE IDs, T-codes, IPs) | `entity-extractor.ts` — pure regex | Python regex, exact mirror | ✅ Always |
| CVE enrichment (CVSS, KEV, analysis) | Supabase `cve_spotlights` table | MCP SDK → `cve_mcp.server` stdio (direct Python call) | ✅ Always |
| Historical plan similarity (few-shot) | Supabase `investigation_plans` | Local `~/.casky/plans/*.json` files | ✅ Always |
| Evidence gap suggestions | Haiku output field | Same — included in classifier prompt | ✅ Always |
| Confidence scores per step | Haiku output field | Same — add to classifier prompt | ✅ Always |
| Playbook matching | Supabase `investigation_playbooks` | `GET /api/v1/playbooks?techniques=...` | ✅ If `CASKY_API_KEY` set |
| CVE → skill_ids routing | Casky-curated `cve_spotlights.skill_ids` | `GET /api/v1/cve-spotlights?cve_ids=...` | ✅ If `CASKY_API_KEY` set |

**Full parity is achievable.** When `CASKY_API_KEY` is configured, all 7 phases run. Without it, 5 phases run. Both modes produce valid plans; the platform-connected mode produces richer skill routing.

**Privacy guarantee:** Only extracted IDs are sent to the platform API — CVE IDs (e.g. `CVE-2024-3400`) and MITRE technique IDs (e.g. `T1078`). Raw evidence text, IPs, hostnames, and all other sensitive artifacts **never leave the box**.

---

## Key Technical Decisions

### CVE MCP Server Access: Direct Python Call via MCP SDK

We do NOT go through Claude Code or register in `claude_desktop_config.json`. The MCP Python SDK supports direct stdio connection:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def enrich_with_cve_mcp(cve_ids: list[str]) -> dict:
    params = StdioServerParameters(
        command="/opt/cve-mcp/bin/python3",
        args=["-m", "cve_mcp.server"]
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("lookup_cve", {"cve_ids": cve_ids})
            return json.loads(result.content[0].text)
```

**Benefits:**
- Structured JSON directly from MCP server (no text parsing)
- No subprocess wrapper around Claude Code
- Clean async/await integration with existing harness patterns
- Requires only the `mcp` Python package in the venv

### Classifier: Direct Anthropic SDK, Not claude --print

Phase D replaces `subprocess.run(["claude", "--print"], ...)` with:

```python
anthropic.Anthropic().messages.create(
    model="claude-haiku-4-5-20251001",
    max_tokens=2048,
    messages=[{"role": "user", "content": classifier_prompt}]
)
```

**Benefits:**
- Fully typed API, not text parsing
- Can inject system prompt directly
- Respects `ANTHROPIC_API_KEY` from environment
- Single Anthropic SDK import for all LLM calls

---

## Architecture: Enhanced generate_local_plan()

```
Raw evidence text
       │
       ▼
[Phase A] extract_entities(evidence_text)              ← Pure Python regex
   Returns: ExtractedEntities
   • cve_ids, technique_ids, ips, hostnames
       │
       ├─ (only if cve_ids)          ├─ (only if CASKY_API_KEY)
       ▼                              ▼
   B1: enrich_with_cve_mcp()    B2: fetch_platform_cve_spotlights()
   └─ MCP SDK stdio                └─ GET /api/v1/cve-spotlights?cve_ids=...
          │                             │
          └─────────────┬───────────────┘
                        ▼
                  merged CveEnrichment
       │
       ├─ (always)                   ├─ (only if CASKY_API_KEY)
       ▼                              ▼
   C1: find_similar_local_plans  C2: fetch_platform_playbooks()
   └─ read ~/.casky/plans/           └─ GET /api/v1/playbooks?techniques=...
          │                             │
          └─────────────┬───────────────┘
                        ▼
                  merged Intelligence
       │
       ▼
   D: Haiku classifier (Anthropic SDK)
   └─ returns JSON with confidence, domain, cve_references, evidence_gaps
```

---

## Files to Modify

### 1. `.github/workflows/build-skills.yml` — Fix Date Step Bug

Move `id: date` step BEFORE the `docker/build-push-action` step so `:YYYYMMDD` tag is available when referenced.

### 2. `Dockerfile` — Add Dependencies

Add to the `casky-console` venv pip install:
```
mcp anthropic
```

### 3. `harness.py` — Implement All 4 Phases

See implementation details in the full plan file. Key functions:
- `extract_entities(evidence_text)` — pure regex
- `enrich_with_cve_mcp(cve_ids)` — async, MCP SDK stdio
- `find_similar_local_plans(evidence_text)` — reads local plans
- `fetch_platform_cve_spotlights(cve_ids)` — optional, REST call
- `fetch_platform_playbooks(technique_ids)` — optional, REST call
- Updated `generate_local_plan()` — orchestrates all phases with Anthropic SDK
- Updated `Plan` dataclass — add cve_references, evidence_gaps, confidence

### 4. `.github/workflows/sync-skills.yml` — Daily Upstream Sync

Mirror `claude-skills-security`'s workflow. Checks upstream tag, rebuilds image if changed, commits `.last-sync`.

### 5. `docker/skills/.last-sync` — Version Tracking

Empty file initially. Workflow writes upstream tag. Acts as canonical version record.

---

## Verification Checklist

**Without CASKY_API_KEY (5 phases working):**
- [ ] T1: `python3 -m py_compile harness.py` — no errors
- [ ] T2: `extract_entities()` returns CVE IDs, T-codes
- [ ] T3: `enrich_with_cve_mcp()` returns CVSS/KEV from MCP
- [ ] T4: `casky harness` → `[g]` → paste CVE evidence → plan has `cve_references`

**With CASKY_API_KEY (7 phases, full parity):**
- [ ] T5: Same flow shows playbook-matched skills + CVE skill_ids

**Sync pipeline:**
- [ ] T6: `workflow_dispatch sync-skills.yml force=true` → `.last-sync` committed
- [ ] T7: `build-skills.yml` trigger → `:YYYYMMDD` tag in ghcr.io

---

## Integration Notes

### Required Platform API Endpoints (out of scope, document as dependency)

Two new routes needed in `claude-skills-security`:

**`GET /api/v1/cve-spotlights?cve_ids=CVE-2024-3400,CVE-2023-1234`**
- Auth: Bearer token (existing pattern)
- Returns: `{ spotlights: [{ cve_id, cvss_score, cvss_severity, is_kev, technique_ids, skill_ids, ai_analysis }] }`

**`GET /api/v1/playbooks?techniques=T1078,T1098`**
- Auth: Bearer token
- Returns: `{ playbooks: [{ id, name, domain, mitre_techniques, steps: [{ skill_slug }] }] }`

These unlock full platform parity when `CASKY_API_KEY` is set.

### Upstream Sync Strategy

```
mukul975/Anthropic-Cybersecurity-Skills  (single source of truth)
  ├── claude-skills-security (submodule, 06:00 UTC daily)
  └── casky-runner (Docker rebuild, 06:30 UTC daily)
```

No separate pipeline repo needed. Both repos sync independently via GitHub Actions.

---

## Next Steps (After Approval)

1. Fix `build-skills.yml` date step ordering (Task #8)
2. Add `mcp` + `anthropic` to Dockerfile (Task #9)
3. Implement harness.py phases A-D (Tasks #10-16)
4. Create sync workflow (Task #17)
5. Run test suite (T1-T7)
6. Commit & push (Task #19)
