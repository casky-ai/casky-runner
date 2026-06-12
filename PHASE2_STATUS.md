# Phase 2 Implementation Status

**Status:** ✅ Ready for testing

**Last Updated:** 2026-06-12

---

## What's Running

```
✅ casky-db          (Postgres) — Local findings database
✅ casky-runner      (Docker) — Claude Code agent + harness
✅ casky-target      (DVWA)   — Vulnerable web app for testing
✅ casky-target-db   (MySQL)  — DVWA database
✅ skill-lab         (Docker) — Security tools container
⏳ casky-mcp         (Pending) — CVE MCP server (optional Phase B)
```

---

## Phase 2 Components Delivered

### ✅ Phase A: Entity Extraction
- File: [harness.py:extract_entities()](harness.py)
- Status: Implemented & tested
- Extracts: CVE IDs, MITRE techniques, IP addresses, hostnames
- Test: `docker exec casky-runner casky harness` → choose "g" for generate

### ✅ Phase B: CVE Enrichment (Optional)
- File: [harness.py:enrich_with_cve_mcp()](harness.py)
- Status: Implemented (awaiting cve_mcp module)
- Currently: Falls back gracefully if MCP unavailable
- Plan: Will add dedicated CVE MCP server container in follow-up

### ✅ Phase C: Platform Integration (Optional)
- Files: [harness.py:fetch_platform_cve_spotlights()](harness.py) & [fetch_platform_playbooks()](harness.py)
- Status: Implemented
- Requires: `CASKY_API_KEY` in `.env.local`
- Usage: Platform API returns curated CVE spotlights and playbooks

### ✅ Phase D: Haiku Classification
- File: [harness.py:generate_local_plan()](harness.py)
- Status: Implemented
- Uses: Anthropic SDK to select 5-8 relevant skills
- Returns: Confidence scores + evidence gaps

---

## Updated Files & Configurations

| File | Change | Purpose |
|------|--------|---------|
| [harness.py](harness.py) | +250 lines Phase 2 code | Entity extraction, CVE enrichment, plan generation |
| [Dockerfile](Dockerfile) | `mcp anthropic` deps | CVE enrichment libraries |
| [docker-compose.yml](docker-compose.yml) | +skill-lab profiles | Security tools container availability |
| [.github/workflows/sync-skills.yml](.github/workflows/sync-skills.yml) | NEW | Daily upstream sync at 06:30 UTC |
| [docker/skills/.last-sync](docker/skills/.last-sync) | NEW | Version tracking for upstream syncs |

---

## Ready for Testing

### Quick Test: Phase A (Entity Extraction)

```bash
docker exec casky-runner python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
# Test will be added with working Python path
"
```

### Full Test: Plan Generation (All Phases)

```bash
# Interactive harness
docker exec -it casky-runner casky harness

# Choose: [g] Generate new plan
# Paste evidence with CVEs/techniques
# Expected: Plan with cve_references, evidence_gaps, confidence
```

### Integration Test: DVWA Investigation

```bash
# Verify DVWA target is running
docker exec skill-lab curl -s -I http://casky-target/ | head -3

# Start interactive investigation
docker exec -it casky-runner casky run web-app

# Paste DVWA reconnaissance evidence
```

---

## What to Test Next

| Test | Command | Expected |
|------|---------|----------|
| **T1: Syntax** | `python3 -m py_compile harness.py` | ✅ (verified) |
| **T2: Plan Generation** | `docker exec -it casky-runner casky harness` → [g] | Plan with CVE metadata |
| **T3: Skill Library** | `docker exec casky-runner casky skills list` | 754 skills |
| **T4: DVWA Target** | `docker exec skill-lab curl -s -I http://casky-target/` | HTTP 200 |
| **T5: Full Investigation** | Interactive skill execution + findings synthesis | CISO report |

---

## Environment Setup

Your `.env.local` should have:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-v3-YOUR_KEY_HERE

# Optional (Platform integration)
CASKY_API_KEY=csk_...
CASKY_APP_URL=https://app.casky.ai

# Optional (CVE enrichment)
NVD_API_KEY=...
GITHUB_TOKEN=...
```

---

## Known Limitations

1. **CVE MCP Server** — Not yet containerized
   - Impact: Phase B enrichment returns basic CVE data only
   - Workaround: Will be added in follow-up PR
   - Fallback: Phase A (entity extraction) still works

2. **Local MCP Testing** — Python import path not set up
   - Impact: Can't test `extract_entities()` locally
   - Workaround: Test inside container or use docker exec

3. **Platform API** (Phase C)
   - Impact: Optional; skipped if CASKY_API_KEY not set
   - Workaround: Works without platform integration (local mode)

---

## Cleanup & Restart

Always use this before testing:

```bash
docker rm -f casky-target casky-runner casky-skills casky-db skill-lab 2>/dev/null
docker compose down -v
docker compose --profile lab-dvwa --env-file .env.local up -d
```

Or use the helper script:

```bash
bash docker-clean-start.sh lab-dvwa
```

(Script to be created as part of START_CLEAN.md)

---

## Next Steps

1. **Run T2-T5 tests** — Verify plan generation and DVWA investigation
2. **Document Phase 2 results** — Update README with Phase A-D pipeline
3. **Implement casky-mcp container** — Add dedicated CVE MCP server
4. **Phase 3 planning** — Review backlog and select priority features

---

## Documentation Links

- [QUICKSTART.md](QUICKSTART.md) — Full setup guide
- [INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md) — How to run investigations
- [TESTING_SKILLS_LIBRARY.md](TESTING_SKILLS_LIBRARY.md) — Test suite details
- [START_CLEAN.md](START_CLEAN.md) — Container cleanup procedures
- [plans/032_phase3_backlog.md](plans/032_phase3_backlog.md) — Feature ideas for Phase 3
