# Phase 1 Contract — Multi-Agent Classifier Pipeline + BYO-LLM Provider Layer

This document is the single source of truth for five parallel agents (A–E) building against
`casky-runner-phase1`. Follow the exact file paths and signatures below. Do not invent alternate
names, do not edit files outside your assigned list, do not talk to the other agents — this
document is the contract.

**Do not modify `harness.py` or `casky.sh` (except Agent E, casky.sh only) as part of this phase.**
A sixth, later integration agent wires everything together — see Section 6.

---

## 1. Current State Summary (harness.py / casky.sh as they exist today)

### 1.1 Dataclasses (`harness.py`)

- `Step` — `harness.py:54-65`. Fields: `id: str`, `skill_slug: str`, `skill_category: str`,
  `skill_document: str`, `technique_id: str`, `technique_name: str`, `rationale: str`,
  `evidence_focus: str`, `step_order: int`, `status: str = "pending"`.
- `ExtractedEntities` — `harness.py:68-74`. Fields: `cve_ids: list[str]`, `technique_ids: list[str]`,
  `ips: list[str]`, `hostnames: list[str]` (all `field(default_factory=list)`).
- `CveEnrichment` — `harness.py:76-85`. Fields: `cve_id: str`, `cvss_score: float | None = None`,
  `cvss_severity: str = ""`, `is_kev: bool = False`, `technique_ids: list[str]`, `skill_ids: list[str]`,
  `ai_analysis: str = ""`.
- `Playbook` — `harness.py:87-94`. Fields: `id: str`, `name: str`, `domain: str`,
  `mitre_techniques: list[str]`, `steps: list[dict]`. **Currently defined but never instantiated
  anywhere in harness.py — dead code.** Agent B's `LocalPlaybookAdapter` supersedes this; the
  integration agent should decide whether to delete it or repoint it (Section 6, item 6).
- `Plan` — `harness.py:96-107`. Fields: `id: str`, `domain: str`, `evidence_text: str`,
  `status: str`, `steps: list[Step]`, `created_at: str = ""`, `cve_references: list[CveEnrichment]`,
  `evidence_gaps: list[str]`, `confidence: float = 0.0`.
- `AgentResult` — `harness.py:109-116`. Fields: `step: Step`, `run_id: str`, `exit_code: int`,
  `output: str`, `report_url: str`.
- `Config` — `harness.py:120-139`. Fields read from env: `api_key` (`CASKY_API_KEY`), `app_url`
  (`CASKY_APP_URL`), `local_port` (`CASKY_LOCAL_PORT`), `lab_name` (`SKILL_LAB_NAME`),
  `concurrency` (`CASKY_CONCURRENCY`), `plans_dir` (`~/.casky/plans`), `skills_library_path`
  (`SKILLS_LIBRARY_PATH`, default `/opt/skills-library`). Properties: `is_local_mode` (139:130-132,
  `not self.api_key`), `auth_header` (134-136, `Bearer` header dict). A single module-level
  `config = Config()` instance (`harness.py:139`) is imported/used throughout the file.

### 1.2 Current classifier (the thing being replaced)

`generate_local_plan(evidence_text: str) -> Plan | None` — `harness.py:350-532`. This is **the**
integration point. Current flow inside it:

1. `entities = extract_entities(evidence_text)` (`harness.py:358`, function at `252-268`) — pure
   regex extraction of CVE IDs, MITRE technique IDs, IPs, hostnames into `ExtractedEntities`.
2. `cve_enrichment = asyncio.run(enrich_with_cve_mcp(entities.cve_ids))` (`harness.py:361`,
   function at `271-290`) — see 1.3 below.
3. If platform mode, `fetch_platform_cve_spotlights()` (`harness.py:293-309`) merges in platform
   CVE data.
4. `find_similar_local_plans()` (`harness.py:312-328`) and, if platform mode,
   `fetch_platform_playbooks()` (`harness.py:331-347`) — both currently produce free-text context
   only (`enrichment_context` string, `harness.py:371-381`), never structured nodes/edges.
5. **The single-call classifier** — `harness.py:383-425`:
   - `classifier_prompt` is a hand-built string (`383-405`) listing evidence, the enrichment
     context string, and `library.subdomain_summary()` (list of up to 800 skills as
     `"name (subdomain) — description"` lines, `harness.py:243-247`).
   - `client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))` (`harness.py:409`)
     — **this is the hardcoded Anthropic client being generalized.**
   - `response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=2048,
     messages=[{"role": "user", "content": classifier_prompt}])` (`harness.py:410-414`) — **this
     is the single Haiku call being replaced by the 4-stage pipeline.** Note the model ID is a
     dated snapshot (`-20251001`); new provider code in this contract uses the current bare ID
     `claude-haiku-4-5` instead (see Section 4) — Anthropic's naming convention as of this
     contract's authoring, not a functional requirement.
   - Response text is stripped of code fences (`416-420`) and `json.loads()`'d into a JSON array
     (`422-425`) — each item: `{skill_slug, skill_category, technique_id, technique_name,
     rationale, evidence_focus, step_order, confidence, evidence_gaps: [...]}`. **This exact item
     shape is the contract the new pipeline's final output must reproduce** (Section 3,
     `ClassifierOutput`).
6. Items are converted into `Step` objects (`harness.py:431-449`), mapping `skill_category`
   (really a *subdomain* string from the skill index) through the `SUBDOMAIN_TO_CATEGORY` dict
   (`harness.py:144-213`, maps ~40 subdomain strings to 18 canonical category strings, default
   fallback `"recon"`) into `Step.skill_category`.
7. `cve_refs` built from `cve_enrichment` matched against `entities.cve_ids` (`harness.py:455-467`).
8. `avg_confidence` = mean of per-item `confidence` (`harness.py:469`).
9. `Plan` is constructed and written to `config.plans_dir / f"{plan.id}.json"` in a specific JSON
   shape (`harness.py:483-520`, the `investigation_steps` key holds the serialized `Step` list —
   **this on-disk shape must not change**, other code (`PlatformClient._parse_plan`,
   `harness.py:647-686`) reads plans back in exactly this shape).

Entry point: `main()` → local mode → source `"g"` → `plan = generate_local_plan(evidence_text)`
at `harness.py:1211`.

### 1.3 CVE enrichment via the bundled MCP server (current mechanism)

`enrich_with_cve_mcp(cve_ids: list[str]) -> dict[str, Any]` — `harness.py:271-290`, `async`. Uses
the `mcp` SDK directly (not a Claude tool-use loop): `StdioServerParameters(command=
"/opt/cve-mcp/bin/python3", args=["-m", "cve_mcp.server"])` (`277-280`), opens a
`stdio_client`/`ClientSession`, calls `session.call_tool("lookup_cve", {"cve_ids": cve_ids})`
(`284`), and `json.loads()`s the first content block's `.text`. Failures are swallowed (`except
Exception` → logs a yellow warning, returns `{}` — `288-290`).

**Important:** `docker/mcp/Dockerfile` (the standalone `cve-mcp-server` container, SSE transport)
is explicitly marked unused in its own header comment (`docker/mcp/Dockerfile:1-5`) — "kept as a
reference for a future standalone mcp.casky.ai deployment." The real, currently-active install path
is in the **repo-root** `Dockerfile`: a venv at `/opt/cve-mcp` (`python3 -m venv /opt/cve-mcp &&
/opt/cve-mcp/bin/pip install git+https://github.com/mukul975/cve-mcp-server.git`), invoked over
**stdio**, matching `harness.py:277-280` exactly. Agent A's `CveMcpAdapter` must use this same
stdio invocation — do not switch to SSE/HTTP.

Optional CVE-source API keys from `.env.example` (all optional, free NVD+EPSS+CISA-KEV path works
with none of them set): `NVD_API_KEY`, `GITHUB_TOKEN`, `SHODAN_KEY`, `VIRUSTOTAL_KEY`,
`GREYNOISE_API_KEY`, `ABUSEIPDB_KEY`, `URLSCAN_KEY`, `CIRCL_PDNS_USER`/`CIRCL_PDNS_PASS`. These are
read by the `cve-mcp-server` package itself, not by harness.py — no adapter code needs to read them
directly, just make sure they stay in the container's env (already the case, no action needed).

### 1.4 Findings / report structure

`casky.sh`'s `REPORT_SECTION` (`casky.sh:34-55`) is injected into the prompt handed to the coding
agent (`claude`/`gemini`) whenever `CASKY_RUN_ID`+`CASKY_TOKEN` are set; it instructs the agent to
`curl -X POST .../api/runs/${CASKY_RUN_ID}/report` with body
`{"findings":[{"title","severity","description","proof","mitre_technique"}], "summary",
"raw_output"}` (severity ∈ critical/high/medium/low/informational). In local mode this POST lands
on `_ReportHandler.do_POST` (`harness.py:541-567`), which persists each run's report JSON to
`/var/casky/reports/<plan_id>/<run_id>.json`. `generate_consolidated_report(plan, results)`
(`harness.py:821-887`) later reads every run's report file back, flattens `findings_all`, sorts by
a fixed severity order (`harness.py:841`), and writes both `REPORT.md` and `consolidated.json`.
None of this changes in Phase 1 — it is downstream of the classifier/plan and out of scope for all
five agents.

### 1.5 `casky.sh` agent dispatch (today)

`casky run <category> [--agent claude|gemini]` (`casky.sh:9-90`). Arg parsing loop `casky.sh:16-19`
(`--agent VALUE`, everything else shifted/ignored). Dispatch `case "$AGENT" in` at `casky.sh:78-89`:
- `claude` (`79-82`): requires `ANTHROPIC_API_KEY`, runs `echo "$PROMPT" | claude --print`.
- `gemini` (`83-87`): requires `GOOGLE_API_KEY` or `GEMINI_API_KEY`, runs `echo "$PROMPT" | gemini`.
- default (`88`): `echo "Unknown agent: $AGENT (use claude or gemini)"; exit 1`.

This is a **separate** concern from the Python BYO-LLM provider layer in Section 4: this dispatch
picks which *coding agent CLI* executes one investigation step's tool commands; Section 4's
`LLMProvider` picks which *LLM API* the classifier pipeline calls to *produce* the plan. Do not
conflate them — Agent E only touches the former.

---

## 2. New Module Layout

New package root: **`/Users/rajesh/code/casky-runner-phase1/casky_pipeline/`** (sibling to
`harness.py`, *not* `harness/` — see naming-collision rationale at the top of this document).

```
casky-runner-phase1/
├── harness.py                              # UNCHANGED in this phase (integration agent edits later)
├── casky.sh                                # Agent E edits only casky run's --agent dispatch
├── casky_pipeline/
│   ├── __init__.py                         # Agent A — empty/docstring only, no re-exports
│   ├── llm_providers.py                    # Agent D
│   ├── pipeline.py                         # Agent C
│   ├── adapters/
│   │   ├── __init__.py                     # Agent A — empty/docstring only, no re-exports
│   │   ├── base.py                         # Agent A
│   │   ├── cve_mcp_adapter.py              # Agent A
│   │   └── local_playbook_adapter.py       # Agent B
│   ├── playbooks/                          # Agent B — data only, no __init__.py (not imported as a package)
│   │   ├── cloud-iam-privilege-escalation.yaml
│   │   ├── web-app-sqli-investigation.yaml
│   │   ├── network-lateral-movement.yaml
│   │   ├── identity-credential-dumping.yaml
│   │   ├── active-directory-kerberoasting.yaml
│   │   ├── threat-hunting-ransomware-triage.yaml
│   │   ├── incident-response-initial-access.yaml
│   │   ├── forensics-disk-image-analysis.yaml
│   │   ├── malware-static-triage.yaml
│   │   ├── osint-external-exposure.yaml
│   │   ├── post-exploit-persistence-hunt.yaml
│   │   └── devsecops-cicd-secrets-leak.yaml
│   └── tests/                              # no __init__.py needed (pytest works without it here)
│       ├── test_adapters_base.py           # Agent A
│       ├── test_cve_mcp_adapter.py         # Agent A
│       ├── test_local_playbook_adapter.py  # Agent B
│       ├── test_pipeline.py                # Agent C
│       └── test_llm_providers.py           # Agent D
```

Why introduce a package now: harness.py has no `pyproject.toml`/`requirements.txt` at all — deps
are a single `pip install` line in the repo-root `Dockerfile` (see Section 6, item 3, for the
change that line needs). `casky_pipeline/` is plain importable Python (repo root is the working
directory both in dev and in the container, per the existing `COPY harness.py
/usr/local/bin/casky-harness` + `python3 /usr/local/bin/casky-harness` invocation chain) — no build
step is introduced.

---

## 3. Dataclass / Type Definitions

### 3.1 `casky_pipeline/adapters/base.py` (Agent A)

```python
"""Context engine adapter interface — the pluggable enrichment layer.

Every adapter takes extracted entities + config and returns a partial graph
(nodes/edges) plus any evidence gaps it noticed. Adapters run concurrently via
run_adapters() and MUST NOT let one failing adapter block the others.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    id: str                                   # stable, globally-unique within one investigation
    type: str                                 # e.g. "cve", "technique", "asset", "playbook_step"
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    source_adapter: str = ""                  # populated by run_adapters(), not by the adapter itself


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str                             # e.g. "exploits", "maps_to", "affects", "suggested_by"
    properties: dict[str, Any] = field(default_factory=dict)
    source_adapter: str = ""                  # populated by run_adapters(), not by the adapter itself


@dataclass
class AdapterResult:
    adapter_name: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    error: str | None = None                  # set when the adapter degraded gracefully; still a valid result
    duration_ms: float = 0.0


@dataclass
class AdapterEntities:
    """Decoupled mirror of harness.ExtractedEntities (harness.py:68-74).
    Adapters must not import harness.py directly — the integration agent
    converts ExtractedEntities -> AdapterEntities at the call site."""
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@dataclass
class AdapterConfig:
    """Generic per-adapter config bag, populated from Config/env at the call site."""
    timeout_s: float = 15.0
    extra: dict[str, Any] = field(default_factory=dict)


class ContextEngineAdapter(ABC):
    """One pluggable enrichment source. Subclasses: CveMcpAdapter (Agent A),
    LocalPlaybookAdapter (Agent B). Future adapters (platform CVE spotlights,
    platform playbooks) follow the same shape."""

    name: str = "base"

    @abstractmethod
    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        """MUST NOT raise for expected failure modes (timeout, network error,
        missing/invalid credentials, empty input). Catch internally and return
        AdapterResult(adapter_name=self.name, error=str(exc)) instead — this
        keeps run_adapters() simple and keeps a bad adapter from ever reading
        as 'crashed' versus 'found nothing'. Only let truly unexpected
        exceptions (bugs) propagate; run_adapters()'s return_exceptions=True
        is the last-resort backstop, not the primary error path."""
        raise NotImplementedError


async def run_adapters(
    adapters: list[ContextEngineAdapter],
    entities: AdapterEntities,
    config: AdapterConfig,
) -> list[AdapterResult]:
    """Runs every adapter concurrently; one failing/raising adapter never
    blocks the others. Always returns len(adapters) results, in the same
    order as `adapters`."""
    started = time.monotonic()
    raw = await asyncio.gather(
        *(a.enrich(entities, config) for a in adapters),
        return_exceptions=True,
    )
    results: list[AdapterResult] = []
    for adapter, r in zip(adapters, raw):
        if isinstance(r, BaseException):
            results.append(
                AdapterResult(
                    adapter_name=adapter.name,
                    error=f"{type(r).__name__}: {r}",
                    duration_ms=(time.monotonic() - started) * 1000,
                )
            )
        else:
            for n in r.nodes:
                n.source_adapter = n.source_adapter or adapter.name
            for e in r.edges:
                e.source_adapter = e.source_adapter or adapter.name
            results.append(r)
    return results
```

### 3.2 `casky_pipeline/adapters/cve_mcp_adapter.py` (Agent A)

```python
"""Ports harness.py's enrich_with_cve_mcp() (harness.py:271-290) into the
ContextEngineAdapter shape. Same stdio invocation, same tool call — do not
switch to the (unused) SSE container in docker/mcp/."""

from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from casky_pipeline.adapters.base import (
    AdapterConfig,
    AdapterEntities,
    AdapterResult,
    ContextEngineAdapter,
    GraphEdge,
    GraphNode,
)

CVE_MCP_COMMAND = "/opt/cve-mcp/bin/python3"   # matches repo-root Dockerfile venv path
CVE_MCP_ARGS = ["-m", "cve_mcp.server"]


class CveMcpAdapter(ContextEngineAdapter):
    name = "cve_mcp"

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        if not entities.cve_ids:
            return AdapterResult(adapter_name=self.name)

        try:
            params = StdioServerParameters(command=CVE_MCP_COMMAND, args=CVE_MCP_ARGS)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "lookup_cve", {"cve_ids": entities.cve_ids}
                    )
                    data: dict[str, Any] = {}
                    if result.content:
                        data = json.loads(result.content[0].text)
        except Exception as exc:  # noqa: BLE001 — must degrade, never raise (see base.py contract)
            return AdapterResult(adapter_name=self.name, error=f"{type(exc).__name__}: {exc}")

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        gaps: list[str] = []
        for cve_id in entities.cve_ids:
            cve_data = data.get(cve_id)
            if not cve_data:
                gaps.append(f"No CVE enrichment data returned for {cve_id}")
                continue
            node_id = f"cve:{cve_id}"
            nodes.append(GraphNode(
                id=node_id,
                type="cve",
                label=cve_id,
                properties={
                    "cvss_score": cve_data.get("cvss_score"),
                    "cvss_severity": cve_data.get("cvss_severity", ""),
                    "is_kev": cve_data.get("is_kev", False),
                },
            ))
            for tech_id in cve_data.get("technique_ids", []):
                edges.append(GraphEdge(
                    source_id=node_id,
                    target_id=f"technique:{tech_id}",
                    relation="maps_to",
                ))
        return AdapterResult(adapter_name=self.name, nodes=nodes, edges=edges, gaps=gaps)
```

### 3.3 `casky_pipeline/adapters/local_playbook_adapter.py` (Agent B) — signature only

Full implementation is Agent B's job; this is the exact shape it must expose:

```python
from __future__ import annotations

from pathlib import Path

from casky_pipeline.adapters.base import (
    AdapterConfig, AdapterEntities, AdapterResult, ContextEngineAdapter,
)

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"


class LocalPlaybookAdapter(ContextEngineAdapter):
    name = "local_playbook"

    def __init__(self, playbooks_dir: Path | None = None) -> None:
        self.playbooks_dir = playbooks_dir or PLAYBOOKS_DIR

    async def enrich(self, entities: AdapterEntities, config: AdapterConfig) -> AdapterResult:
        """Load every *.yaml under self.playbooks_dir, match playbooks whose
        mitre_techniques intersects entities.technique_ids, and emit:
          - one GraphNode(type="playbook", id=f"playbook:{playbook.id}") per matched playbook
          - one GraphNode(type="playbook_step", id=f"playbook_step:{playbook.id}:{i}") per step
          - GraphEdge(relation="suggested_by", source_id=step_node_id,
            target_id=f"technique:{step.technique_id}") per step
          - gaps = the matched playbook(s)' evidence_gaps list
        Never raises (per ContextEngineAdapter.enrich contract) — a missing or
        malformed YAML file is a single skipped playbook + nothing more."""
        raise NotImplementedError  # Agent B implements this
```

**Playbook YAML schema** (one file per playbook under `casky_pipeline/playbooks/`, exact keys):

```yaml
id: credential-dumping-investigation      # str, unique, kebab-case
name: Credential Dumping Investigation    # str, human-readable
domain: identity                          # str — one of SUBDOMAIN_TO_CATEGORY's 18 category values
                                           # (harness.py:144-213): cloud, identity, web-app, appsec,
                                           # network, vuln-scan, threat-intel, threat-hunting,
                                           # incident-response, forensics, malware, osint, recon,
                                           # post-exploit, exploitation, detection, devsecops,
                                           # active-directory
mitre_techniques:                         # list[str] — matched against AdapterEntities.technique_ids
  - T1003
  - T1552
description: >
  One-paragraph summary of what this playbook investigates.
steps:                                    # list — field names mirror harness.Step exactly, on purpose
  - skill_slug: mimikatz-detection
    skill_category: identity
    technique_id: T1003
    technique_name: OS Credential Dumping
    rationale: Evidence references LSASS access patterns consistent with credential dumping tooling.
    evidence_focus: LSASS process handles, unusual reads of SAM/SECURITY hives
    step_order: 1
evidence_gaps:                            # list[str] — surfaced verbatim when this playbook matches
  - No EDR telemetry confirming LSASS access source process
```

Agent B builds exactly these 12 playbook files (within the requested 10-15 range), one per line in
the file tree in Section 2 — cover a distinct `domain` in each so the starter set spans the
category taxonomy. Every playbook needs a fully filled `steps:` list (2-5 steps each is reasonable)
and at least one `evidence_gaps` entry.

### 3.4 Pipeline stage I/O — `casky_pipeline/pipeline.py` (Agent C)

```python
"""4-stage classifier pipeline: TechniqueValidator -> SkillSelector ->
(StepOrderer parallel with EvidenceGap). Stub/mock the LLM calls against the
LLMProvider interface from casky_pipeline.llm_providers (Section 4) — do NOT
wire this into harness.py yet (that is the integration agent's job, Section 6)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from casky_pipeline.adapters.base import GraphEdge, GraphNode
from casky_pipeline.llm_providers import LLMProvider


# ── Pipeline input ──────────────────────────────────────────────────────────

@dataclass
class PipelineEntities:
    """Same shape as casky_pipeline.adapters.base.AdapterEntities — duplicated
    here (not imported) so pipeline.py has no import-order dependency on
    adapters/. The integration agent passes the same values into both."""
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@dataclass
class ClassifierInput:
    evidence_text: str
    entities: PipelineEntities
    context_nodes: list[GraphNode] = field(default_factory=list)   # from run_adapters()
    context_edges: list[GraphEdge] = field(default_factory=list)   # from run_adapters()
    context_gaps: list[str] = field(default_factory=list)          # from run_adapters()
    skill_index: list[dict] = field(default_factory=list)          # LocalSkillsLibrary.load_index() (harness.py:225-234)


# ── Stage 1: TechniqueValidator ──────────────────────────────────────────────

@dataclass
class ValidatedTechnique:
    technique_id: str
    technique_name: str
    confidence: float
    evidence_anchors: list[str] = field(default_factory=list)   # verbatim substrings of evidence_text
    rationale: str = ""


@dataclass
class TechniqueValidatorOutput:
    techniques: list[ValidatedTechnique] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)


class TechniqueValidator:
    async def run(self, input: ClassifierInput, provider: LLMProvider) -> TechniqueValidatorOutput:
        raise NotImplementedError  # stub/mock the provider.complete(...) call for this phase


# ── Stage 2: SkillSelector ───────────────────────────────────────────────────

@dataclass
class SelectedSkill:
    skill_slug: str
    skill_category: str          # raw subdomain string — SUBDOMAIN_TO_CATEGORY mapping happens at
                                  # the harness.py integration call site (Section 6, item 7), NOT here
    technique_id: str
    technique_name: str
    rationale: str
    evidence_focus: str
    confidence: float
    evidence_anchors: list[str] = field(default_factory=list)


@dataclass
class SkillSelectorOutput:
    selected: list[SelectedSkill] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)


class SkillSelector:
    async def run(
        self,
        input: ClassifierInput,
        validated: TechniqueValidatorOutput,
        provider: LLMProvider,
    ) -> SkillSelectorOutput:
        raise NotImplementedError  # stub/mock


# ── Stage 3a: StepOrderer (runs parallel with EvidenceGap) ──────────────────

@dataclass
class OrderedStep:
    skill_slug: str
    step_order: int
    depends_on: list[str] = field(default_factory=list)   # skill_slugs this step should follow


@dataclass
class StepOrdererOutput:
    ordered: list[OrderedStep] = field(default_factory=list)


class StepOrderer:
    async def run(self, selected: SkillSelectorOutput, provider: LLMProvider) -> StepOrdererOutput:
        raise NotImplementedError  # stub/mock


# ── Stage 3b: EvidenceGap (runs parallel with StepOrderer) ──────────────────

@dataclass
class EvidenceGapOutput:
    gaps: list[str] = field(default_factory=list)


class EvidenceGap:
    async def run(
        self,
        input: ClassifierInput,
        selected: SkillSelectorOutput,
        provider: LLMProvider,
    ) -> EvidenceGapOutput:
        raise NotImplementedError  # stub/mock


# ── Final pipeline output — the exact shape generate_local_plan() consumes ──

@dataclass
class ClassifierOutput:
    """Mirrors the JSON-array item shape the current single Haiku call
    produces (harness.py:394-404 prompt spec, parsed at harness.py:422-453):
    each dict in `steps` has keys skill_slug, skill_category, technique_id,
    technique_name, rationale, evidence_focus, step_order, confidence,
    evidence_gaps — so the integration agent's diff at the harness.py call
    site is small (Section 6, item 1)."""
    steps: list[dict] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    confidence: float = 0.0


async def run_pipeline(input: ClassifierInput, provider: LLMProvider) -> ClassifierOutput:
    validated = await TechniqueValidator().run(input, provider)
    selected = await SkillSelector().run(input, validated, provider)
    step_order_result, gap_result = await asyncio.gather(
        StepOrderer().run(selected, provider),
        EvidenceGap().run(input, selected, provider),
    )
    order_by_slug = {o.skill_slug: o.step_order for o in step_order_result.ordered}
    steps = [
        {
            "skill_slug": s.skill_slug,
            "skill_category": s.skill_category,
            "technique_id": s.technique_id,
            "technique_name": s.technique_name,
            "rationale": s.rationale,
            "evidence_focus": s.evidence_focus,
            "step_order": order_by_slug.get(s.skill_slug, i + 1),
            "confidence": s.confidence,
            "evidence_gaps": [],
        }
        for i, s in enumerate(selected.selected)
    ]
    all_gaps = list(dict.fromkeys(
        validated.evidence_gaps + selected.evidence_gaps + gap_result.gaps + input.context_gaps
    ))
    confidences = [s.confidence for s in selected.selected]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    return ClassifierOutput(steps=steps, evidence_gaps=all_gaps, confidence=avg_confidence)
```

---

## 4. `LLMProvider` Interface (Agent D — `casky_pipeline/llm_providers.py`)

```python
"""BYO-LLM provider layer. CASKY_MODEL_PROVIDER selects the backend;
CASKY_MODEL_BASE_URL / CASKY_MODEL_NAME configure it. Default stays
Haiku-tier to match the classifier's current cost profile (harness.py:410-414
used claude-haiku-4-5-20251001) — this is a low-latency classification task,
not a place to default to a larger/thinking model."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        """Returns the raw text completion. Implementations must raise on
        unrecoverable errors (auth failure, 4xx) so pipeline stages can
        surface them; may retry internally on 429/5xx.

        cacheable_system: when True (the default) and the provider supports
        prompt caching, mark system_prompt as an ephemeral cache breakpoint.
        Every pipeline stage's system prompt is static per stage (only
        user_prompt varies per investigation), so this is on by default —
        callers should only pass False for a genuinely one-off system prompt
        that will never repeat (rare in this codebase)."""
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    """Prompt caching: Anthropic's prompt caching is GA (no beta header
    required for the default 5-minute ephemeral TTL used here). Marking the
    system prompt as cache_control=ephemeral means every pipeline stage
    (TechniqueValidator, SkillSelector, StepOrderer, EvidenceGap) that reuses
    the same system prompt across a burst of investigations only pays full
    input-token price on the first call; subsequent calls within the TTL
    read the cached prefix at a fraction of the cost. This is the single
    highest-leverage cost fix in this pipeline, since the 4-stage design
    means the same static system prompts fire on every investigation."""

    def __init__(self, api_key: str | None = None, model: str = "claude-haiku-4-5") -> None:
        import anthropic
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._model = model

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        import anthropic

        system_param: list[dict] | None = None
        if system_prompt:
            block: dict = {"type": "text", "text": system_prompt}
            if cacheable_system:
                block["cache_control"] = {"type": "ephemeral"}
            system_param = [block]

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system_param,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.AuthenticationError:
            raise
        except anthropic.RateLimitError:
            raise
        except anthropic.APIStatusError:
            raise

        usage = getattr(response, "usage", None)
        if usage is not None:
            cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
            cache_created = getattr(usage, "cache_creation_input_tokens", 0) or 0
            if cache_read or cache_created:
                import sys
                print(
                    f"[casky_pipeline:llm] model={self._model} "
                    f"cache_read={cache_read} cache_created={cache_created} "
                    f"input={usage.input_tokens} output={usage.output_tokens}",
                    file=sys.stderr,
                )
        return response.content[0].text


class OpenAICompatibleProvider(LLMProvider):
    """Any OpenAI-compatible /chat/completions endpoint: OpenAI, Qwen, Kimi,
    local Ollama / LM Studio / vLLM. Implemented over raw HTTP via `requests`
    (already an installed dependency, see repo-root Dockerfile) rather than
    the `openai` package, to avoid adding a new dependency to the runner
    image for this phase.

    cacheable_system is accepted for interface compliance but has no effect
    here: prompt caching is provider-specific (Anthropic's cache_control,
    OpenAI's automatic prefix caching, none/varies for local runtimes) and
    is out of scope for this phase's OpenAI-compatible path — most local
    backends (Ollama/LM Studio/vLLM) either cache automatically or don't
    support explicit cache control at all, so there's nothing correct to do
    here yet without per-backend branching. Revisit if/when a specific
    OpenAI-compatible backend's caching semantics are worth wiring."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key or os.environ.get("CASKY_MODEL_API_KEY", "")

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        import asyncio
        import requests

        def _call() -> str:
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": user_prompt})
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json={"model": self._model, "messages": messages, "max_tokens": max_tokens},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        return await asyncio.to_thread(_call)


def build_provider_from_env() -> LLMProvider:
    """
    CASKY_MODEL_PROVIDER  — "anthropic" (default) | "openai_compatible"
    CASKY_MODEL_BASE_URL  — required when CASKY_MODEL_PROVIDER=openai_compatible,
                             e.g. https://api.openai.com/v1, http://localhost:11434/v1 (Ollama),
                             http://localhost:1234/v1 (LM Studio), a vLLM server's /v1 URL
    CASKY_MODEL_NAME      — model name/id passed to the provider
                             (default "claude-haiku-4-5" for anthropic, "gpt-4o-mini" for openai_compatible)
    CASKY_MODEL_API_KEY   — optional bearer token for openai_compatible backends that require one
    """
    provider_kind = os.environ.get("CASKY_MODEL_PROVIDER", "anthropic").lower()
    model_name = os.environ.get("CASKY_MODEL_NAME", "")

    if provider_kind == "anthropic":
        return AnthropicProvider(model=model_name or "claude-haiku-4-5")

    if provider_kind == "openai_compatible":
        base_url = os.environ.get("CASKY_MODEL_BASE_URL", "")
        if not base_url:
            raise ValueError(
                "CASKY_MODEL_BASE_URL is required when CASKY_MODEL_PROVIDER=openai_compatible"
            )
        return OpenAICompatibleProvider(base_url=base_url, model=model_name or "gpt-4o-mini")

    raise ValueError(
        f"Unknown CASKY_MODEL_PROVIDER: {provider_kind!r} (expected 'anthropic' or 'openai_compatible')"
    )
```

---

## 5. Task Assignment Table (zero file overlap)

| Agent | Owns (creates/edits) | Notes |
|---|---|---|
| **A** | `casky_pipeline/__init__.py`, `casky_pipeline/adapters/__init__.py`, `casky_pipeline/adapters/base.py`, `casky_pipeline/adapters/cve_mcp_adapter.py`, `casky_pipeline/tests/test_adapters_base.py`, `casky_pipeline/tests/test_cve_mcp_adapter.py` | Both `__init__.py` files are empty/docstring-only — no re-exports, so no other agent ever needs to edit them. Implement Section 3.1 and 3.2 verbatim. |
| **B** | `casky_pipeline/adapters/local_playbook_adapter.py`, `casky_pipeline/playbooks/*.yaml` (the 12 files listed in Section 2), `casky_pipeline/tests/test_local_playbook_adapter.py` | Adds a file into the `adapters/` directory Agent A also writes into — no filename collision, safe. Follow the YAML schema in Section 3.3 exactly. |
| **C** | `casky_pipeline/pipeline.py`, `casky_pipeline/tests/test_pipeline.py` | Import `from casky_pipeline.llm_providers import LLMProvider` and code/test against that exact signature (Section 4) — do not redefine `LLMProvider` locally, and do not edit `llm_providers.py` (Agent D owns it). Stage bodies (`TechniqueValidator.run`, etc.) can be stubbed/mocked for this phase; get the dataclass shapes and `run_pipeline()` orchestration (the parallel `asyncio.gather` of StepOrderer + EvidenceGap) right. |
| **D** | `casky_pipeline/llm_providers.py`, `casky_pipeline/tests/test_llm_providers.py` | Implement Section 4 verbatim. `AnthropicProvider` uses `anthropic.AsyncAnthropic` (already an installed dependency). `OpenAICompatibleProvider` uses `requests` (already installed) — do not add the `openai` package as a dependency. |
| **E** | `casky.sh` only | Add `--agent copilot` and `--agent custom --agent-cmd "<binary>"` to the `casky run` dispatch (`casky.sh:78-89`) and the arg-parsing loop (`casky.sh:16-19`). Does not touch any Python file. See starter shape below. |
| **F** | `packages/investigate/src/llm.ts` in the **separate** `claude-skills-security` repo (not this worktree) | Token-cost fix, independent of A–E: add Anthropic prompt caching to the existing `callAgent()`/`callAgentStructured()` call sites. Today `system` is passed as a plain string (confirmed: zero `cache_control` usage anywhere in `packages/investigate/src/`). Change to `system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }]` — same technique as `AnthropicProvider` in Section 4 above. This is live production code (used by `apps/web` and `apps/teams` today) — every one of the 4 pipeline agents (TechniqueValidatorAgent, SkillSelectorAgent, StepOrdererAgent, EvidenceGapAgent) fires a static-per-call-type system prompt on every investigation, so this is real, immediate cost savings independent of the Phase 1 casky-runner work. Also log `usage.cache_read_input_tokens`/`cache_creation_input_tokens` from the response the same way Section 4's `AnthropicProvider` does, so cache effectiveness is visible in logs. Add/update tests in `apps/web/__tests__/` (or wherever `llm.ts` is currently tested) asserting the `system` param is now an array with `cache_control` set. |
| **G** | `CLAUDE.md` at the root of **this** repo (`casky-runner-phase1/CLAUDE.md`) | This repo has no `CLAUDE.md` today (confirmed). Write one following the style of `claude-skills-security/CLAUDE.md` (read it for tone/structure) but scoped to this repo: what this repo is (the open-source "Casky Box" runtime), the `casky_pipeline/` module layout from Section 2 once it exists, how `harness.py`/`casky.sh` fit together, the BYO-Agent/BYO-LLM/BYO-DB env var conventions, how to run tests (`pytest casky_pipeline/tests/`, `tests/run-tests.sh`), and — the specific ask this task exists for — a short "Token economy" section instructing future Claude sessions working in this repo to prefer reading `PHASE1_CONTRACT.md`/this file over re-exploring the whole codebase from scratch, and to reuse the `LLMProvider.complete(cacheable_system=True)` default rather than re-deriving prompt-caching decisions per call site. This directly reduces future exploration-token burn in this repo, which is the point of a good `CLAUDE.md`. |

No two agents write the same file. Agents B and C each read (import) a file owned by another agent
(A's `adapters/base.py`, D's `llm_providers.py`) but never write to it. Agents F and G write to a
different repo/file entirely (F: the closed SaaS repo; G: this repo's root) and have zero
dependency on A–E's work — they can run fully in parallel with everything else.

**Agent E starter shape** (extend, don't replace, the existing `case`/parsing blocks):

```bash
# in the arg-parsing loop (casky.sh:16-19), add a case:
      case "$1" in
        --agent) AGENT="$2"; shift 2 ;;
        --agent-cmd) AGENT_CMD="$2"; shift 2 ;;
        *) shift ;;
      esac

# in the dispatch (casky.sh:78-89), add two branches before the default case:
      copilot)
        [[ -z "${GITHUB_TOKEN:-}" ]] && { echo "Set GITHUB_TOKEN first (gh copilot auth)"; exit 1; }
        echo "$PROMPT" | copilot   # confirm exact copilot CLI invocation flags before shipping —
                                   # no copilot binary is installed in the image yet (see Section 6, item 8)
        ;;
      custom)
        [[ -z "${AGENT_CMD:-}" ]] && { echo "Usage: casky run <category> --agent custom --agent-cmd \"<binary>\""; exit 1; }
        echo "$PROMPT" | eval "$AGENT_CMD"
        ;;
      *) echo "Unknown agent: $AGENT (use claude, gemini, copilot, or custom --agent-cmd)"; exit 1 ;;
```

Also update the `help|*` usage block (`casky.sh:187-189`, `208-217`) to document `copilot`, `custom
--agent-cmd`, and any new env vars (e.g. document that `custom` requires `--agent-cmd`).

---

## 6. Integration Agent Punch List (6th agent, after A–E land)

1. **Replace the classify call site.** Target: `harness.py:350-532`
   (`generate_local_plan`), specifically the enrichment calls at `harness.py:361` and the
   classifier block at `harness.py:383-425`. Replace with:
   - Build `AdapterEntities`/`PipelineEntities` from the existing `ExtractedEntities`
     (`harness.py:358`).
   - `results = await run_adapters([CveMcpAdapter(), LocalPlaybookAdapter()], entities, AdapterConfig())`
     (replaces the direct `enrich_with_cve_mcp()` call at `harness.py:361`).
   - Flatten `results` into `context_nodes`/`context_edges`/`context_gaps` for `ClassifierInput`.
   - `provider = build_provider_from_env()`; `output = await run_pipeline(ClassifierInput(...), provider)`.
   - Convert `output.steps` (list of dicts) into `Step` objects exactly as `harness.py:431-449`
     already does — that loop's body barely changes, since `ClassifierOutput.steps` items use the
     identical key set the old `selected_skills` items had.
2. **Remove/deprecate:** the direct `anthropic.Anthropic(...)` construction and
   `client.messages.create(...)` call at `harness.py:409-414`. Decide whether `enrich_with_cve_mcp()`
   (`harness.py:271-290`) stays as a thin wrapper `CveMcpAdapter` delegates to, or is deleted outright
   once nothing else calls it.
3. **Dockerfile changes** (repo-root `Dockerfile`):
   - The `/opt/casky-console` pip install line currently installs `rich requests mcp anthropic` —
     add `pyyaml` (needed by `LocalPlaybookAdapter` to parse the playbook YAML files).
   - `COPY harness.py /usr/local/bin/casky-harness` copies only the single file today — add
     `COPY casky_pipeline/ /opt/casky-console/lib/casky_pipeline/` and put
     `/opt/casky-console/lib` on `PYTHONPATH` (e.g. `ENV PYTHONPATH=/opt/casky-console/lib`) so
     `import casky_pipeline` resolves inside the container the same way it does from the repo root
     in dev.
4. **`.env.example`**: add `CASKY_MODEL_PROVIDER`, `CASKY_MODEL_BASE_URL`, `CASKY_MODEL_NAME`,
   `CASKY_MODEL_API_KEY` with the same comment-block style as the existing `## Optional:` sections.
5. **Tests**: per-module unit tests are Agents A–D's own files (Section 5). The integration agent
   adds one end-to-end test that calls `generate_local_plan()` with a mocked `LLMProvider` and
   mocked adapters, asserting: (a) the resulting `Plan`/`Step` objects and the on-disk
   `investigation_steps` JSON shape are unchanged from today's contract (`harness.py:483-520`), and
   (b) `PlatformClient._parse_plan` (`harness.py:647-686`) can still round-trip the written file.
6. **Dead code**: `Playbook` dataclass (`harness.py:87-94`) is currently unreferenced — either wire
   it to `LocalPlaybookAdapter`'s output or delete it.
7. **`SUBDOMAIN_TO_CATEGORY` mapping** (`harness.py:144-213`) stays applied at the harness.py
   integration call site exactly as it is today (`harness.py:434-436`) — the pipeline's
   `SkillSelectorOutput.selected[].skill_category` is left as the *raw subdomain string* on purpose
   (Section 3.4 note); do not move this mapping into `casky_pipeline/`.
8. **`copilot` CLI provisioning**: Agent E's `casky.sh` branch assumes a `copilot` binary is on
   `PATH`; the image's `package.json`/Dockerfile currently install only `@anthropic-ai/claude-code`
   and `@google/gemini-cli`. Add the real copilot CLI package (or document that `--agent copilot`
   requires a manually-installed binary) as part of integration.
9. Run `pytest casky_pipeline/tests/` and the existing `tests/run-tests.sh` before merging.
