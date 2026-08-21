#!/usr/bin/env python3
"""
Casky Agentic Harness

Fetches an investigation plan from casky.ai (platform mode) or a local JSON file
(local mode), then runs all steps as parallel Claude + CVE MCP + skill-tool agents.

Each step spawns an independent 'casky run <category>' subprocess. casky.sh injects
REPORT_SECTION when CASKY_RUN_ID + CASKY_TOKEN are set, so Claude posts findings to
the correct endpoint automatically — platform or local.

Usage (inside the runner container):
    casky harness

Modes:
    Platform mode  — CASKY_API_KEY is set: fetches plans from casky.ai, reports back
    Local mode     — CASKY_API_KEY empty:  loads ~/.casky/plans/*.json, saves to /var/casky/reports/
"""

from __future__ import annotations

import asyncio
import collections
import json
import os
import re
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

# Phase 1 pipeline — context adapters + 4-stage classifier + BYO-LLM provider layer.
# See PHASE1_CONTRACT.md for the interface contract these modules implement.
from casky_pipeline.adapters.base import AdapterConfig, AdapterEntities, run_adapters
from casky_pipeline.adapters.cve_mcp_adapter import CveMcpAdapter
from casky_pipeline.adapters.local_playbook_adapter import LocalPlaybookAdapter
from casky_pipeline.llm_providers import build_provider_from_env
from casky_pipeline.pipeline import ClassifierInput, PipelineEntities, run_pipeline
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markup import escape as rmarkup
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

console = Console()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Step:
    id: str
    skill_slug: str
    skill_category: str
    skill_document: str
    technique_id: str
    technique_name: str
    rationale: str
    evidence_focus: str
    step_order: int
    status: str = "pending"


@dataclass
class ExtractedEntities:
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@dataclass
class CveEnrichment:
    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str = ""
    is_kev: bool = False
    technique_ids: list[str] = field(default_factory=list)
    skill_ids: list[str] = field(default_factory=list)
    ai_analysis: str = ""


@dataclass
class Plan:
    id: str
    domain: str
    evidence_text: str
    status: str
    steps: list[Step] = field(default_factory=list)
    created_at: str = ""
    cve_references: list[CveEnrichment] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class AgentResult:
    step: Step
    run_id: str
    exit_code: int
    output: str
    report_url: str


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class Config:
    api_key: str = field(default_factory=lambda: os.environ.get("CASKY_API_KEY", ""))
    app_url: str = field(default_factory=lambda: os.environ.get("CASKY_APP_URL", "https://casky.ai").rstrip("/"))
    local_port: int = field(default_factory=lambda: int(os.environ.get("CASKY_LOCAL_PORT", "8765")))
    lab_name: str = field(default_factory=lambda: os.environ.get("SKILL_LAB_NAME", "skill-lab"))
    concurrency: int = field(default_factory=lambda: int(os.environ.get("CASKY_CONCURRENCY", "4")))
    plans_dir: Path = field(default_factory=lambda: Path.home() / ".casky" / "plans")
    skills_library_path: Path = field(default_factory=lambda: Path(os.environ.get("SKILLS_LIBRARY_PATH", "/opt/skills-library")))

    @property
    def is_local_mode(self) -> bool:
        return not self.api_key

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}


config = Config()

# evidence_text gets embedded verbatim into every pipeline-stage LLM prompt (see
# casky_pipeline/pipeline.py's _build_user_prompt methods) with NO other size guard
# anywhere — and the skill index alone (800+ real skills) already consumes a real
# chunk of context budget before evidence_text is even added. Live-caught: a user
# passed an 82MB pcap-derived JSON dump via -i/--input-file, which would have blown
# past every configured provider's context window by roughly two orders of
# magnitude, either hard-failing the API call or being catastrophically slow/costly.
# 50,000 chars (~12-15K tokens) is generous for genuine pasted evidence (hundreds of
# real CloudTrail events) while catching "someone passed a raw, unfiltered capture."
MAX_EVIDENCE_CHARS = 50_000


# ── Skills library access ─────────────────────────────────────────────────────

SUBDOMAIN_TO_CATEGORY = {
    # Cloud
    "cloud-security": "cloud",
    "container-security": "cloud",
    # Identity
    "identity-access-management": "identity",
    "identity-and-access-management": "identity",
    "identity-security": "identity",
    "active-directory": "identity",
    # Web
    "web-application-security": "web-app",
    "api-security": "web-app",
    "application-security": "appsec",
    # Network
    "network-security": "network",
    "wireless-security": "network",
    "zero-trust": "network",
    "zero-trust-architecture": "network",
    # Vulnerability
    "vulnerability-management": "vuln-scan",
    "vulnerability-assessment": "vuln-scan",
    # Threat Intel
    "threat-intelligence": "threat-intel",
    "threat-hunting": "threat-hunting",
    "threat-detection": "threat-hunting",
    "ransomware-defense": "threat-hunting",
    # Incident Response
    "incident-response": "incident-response",
    "soc-operations": "incident-response",
    "security-operations": "incident-response",
    # Forensics
    "digital-forensics": "forensics",
    "firmware-analysis": "forensics",
    "malware-analysis": "malware",
    "endpoint-security": "forensics",
    # OSINT/Recon
    "osint": "osint",
    "reconnaissance": "recon",
    "open-source-intelligence": "osint",
    # Post-Exploit
    "post-exploitation": "post-exploit",
    "persistence": "post-exploit",
    "lateral-movement": "post-exploit",
    # Exploit
    "exploitation": "exploitation",
    "offensive-security": "exploitation",
    "red-teaming": "exploitation",
    "red-team": "exploitation",
    "penetration-testing": "exploitation",
    # Detection
    "detection-engineering": "detection",
    "devsecops": "devsecops",
    # Other security domains map to recon as fallback
    "blockchain-security": "recon",
    "cryptography": "recon",
    "data-protection": "recon",
    "deception-technology": "recon",
    "firmware-security": "recon",
    "governance-risk-compliance": "recon",
    "compliance-governance": "recon",
    "ai-security": "recon",
    "mobile-security": "recon",
    "ot-ics-security": "recon",
    "ot-security": "recon",
    "phishing-defense": "recon",
    "privacy-compliance": "recon",
    "purple-team": "recon",
    "social-engineering-defense": "recon",
    "supply-chain-security": "recon",
}


class LocalSkillsLibrary:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config.skills_library_path
        self._index: list[dict] | None = None

    @property
    def available(self) -> bool:
        return (self.path / "index.json").exists()

    def load_index(self) -> list[dict]:
        if self._index is None:
            # Prefer the enriched index (written by entrypoint.sh via
            # scripts/enrich_skills_index.py) — the raw index.json shipped in
            # the skills-library image has no `subdomain` field at all, which
            # silently degrades classifier quality and breaks
            # `casky skills list <subdomain>` entirely. Fall back to the raw
            # index if enrichment hasn't run (e.g. entrypoint.sh skipped it
            # because the library wasn't mounted yet) or failed.
            enriched_path = Path("/var/casky/skills-index-enriched.json")
            index_path = enriched_path if enriched_path.exists() else (self.path / "index.json")
            try:
                with open(index_path) as f:
                    data = json.load(f)
                self._index = data.get("skills", [])
            except Exception as e:
                console.print(f"[red]Error loading skills index:[/red] {rmarkup(str(e))}")
                self._index = []
        return self._index

    def get_skill_document(self, slug: str) -> str:
        p = self.path / "skills" / slug / "SKILL.md"
        return p.read_text() if p.exists() else ""

    def get_agent_script(self, slug: str) -> Path:
        return self.path / "skills" / slug / "scripts" / "agent.py"

    def subdomain_summary(self) -> str:
        lines = []
        for s in self.load_index():
            lines.append(f'{s["name"]} ({s.get("subdomain", "")}) — {s.get("description", "")[:80]}')
        return "\n".join(lines[:800])


# ── CVE enrichment pipeline ──────────────────────────────────────────────────

def extract_entities(evidence_text: str) -> ExtractedEntities:
    """Extract CVE IDs, technique IDs, IPs, and hostnames from evidence text."""
    entities = ExtractedEntities()

    cve_pattern = r'CVE-\d{4}-\d{4,}'
    entities.cve_ids = list(set(re.findall(cve_pattern, evidence_text, re.IGNORECASE)))

    technique_pattern = r'T\d{4}(?:\.\d{3})?'
    entities.technique_ids = list(set(re.findall(technique_pattern, evidence_text)))

    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    entities.ips = list(set(re.findall(ip_pattern, evidence_text)))

    hostname_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    entities.hostnames = list(set(re.findall(hostname_pattern, evidence_text, re.IGNORECASE)))

    return entities


# NOTE: the old direct-stdio enrich_with_cve_mcp() was removed in Phase 1 — its
# exact logic now lives in casky_pipeline.adapters.cve_mcp_adapter.CveMcpAdapter,
# invoked via run_adapters() in generate_local_plan() below. Nothing else called
# this function (confirmed before removal).


def fetch_platform_cve_spotlights(cve_ids: list[str]) -> dict[str, Any]:
    """Fetch CVE spotlights from platform API if CASKY_API_KEY is set."""
    if not config.api_key or not cve_ids:
        return {}

    try:
        resp = requests.get(
            f"{config.app_url}/api/v1/cve-spotlights",
            headers=config.auth_header,
            params={"cve_ids": ",".join(cve_ids)},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[yellow]Warning: platform CVE enrichment failed:[/yellow] {rmarkup(str(e))}")
        return {}


def find_similar_local_plans(evidence_text: str) -> list[dict]:
    """Find similar local plans from ~/.casky/plans/ for few-shot context."""
    similar = []
    config.plans_dir.mkdir(parents=True, exist_ok=True)

    for plan_file in sorted(config.plans_dir.glob("*.json"))[:5]:
        try:
            data = json.loads(plan_file.read_text())
            similar.append({
                "plan_id": data.get("id", ""),
                "domain": data.get("domain", ""),
                "steps_count": len(data.get("investigation_steps", [])),
            })
        except Exception:
            pass

    return similar


def fetch_platform_playbooks(technique_ids: list[str]) -> dict[str, Any]:
    """Fetch investigation playbooks from platform API if CASKY_API_KEY is set."""
    if not config.api_key or not technique_ids:
        return {}

    try:
        resp = requests.get(
            f"{config.app_url}/api/v1/playbooks",
            headers=config.auth_header,
            params={"techniques": ",".join(technique_ids)},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[yellow]Warning: platform playbook fetch failed:[/yellow] {rmarkup(str(e))}")
        return {}


def generate_local_plan(evidence_text: str) -> Plan | None:
    library = LocalSkillsLibrary()
    if not library.available:
        console.print("[red]Skills library not found at {library.path}[/red]")
        console.print("[dim]Run: docker compose up casky-skills[/dim]")
        return None

    # Independent guard from _load_evidence_from_file's size check — this one also
    # covers the interactive paste path and any future caller of this function
    # directly, not just -i. See MAX_EVIDENCE_CHARS for why the limit exists.
    if len(evidence_text) > MAX_EVIDENCE_CHARS:
        console.print(
            f"[red]Evidence is {len(evidence_text):,} characters, over the "
            f"{MAX_EVIDENCE_CHARS:,}-character limit.[/red] It's embedded verbatim into "
            "every LLM prompt in the pipeline, so this would blow past any provider's "
            "context window. Pre-process it first — extract only the relevant "
            "events/lines instead of pasting the full raw capture."
        )
        return None

    console.print("[dim]Phase A: Extracting entities…[/dim]")
    entities = extract_entities(evidence_text)

    # Built once, up front, and reused for both the LLM-assisted playbook adapter
    # below and the classifier pipeline in Phase D — one client per investigation,
    # not one per call, which also maximizes prompt-cache hit potential.
    provider = build_provider_from_env()

    console.print("[dim]Phase B: Running context adapters…[/dim]")
    adapter_entities = AdapterEntities(
        cve_ids=entities.cve_ids,
        technique_ids=entities.technique_ids,
        ips=entities.ips,
        hostnames=entities.hostnames,
    )
    adapter_results = asyncio.run(run_adapters(
        [CveMcpAdapter(), LocalPlaybookAdapter(provider=provider)],
        adapter_entities,
        AdapterConfig(extra={"evidence_text": evidence_text}),
    ))

    context_nodes = []
    context_edges = []
    context_gaps: list[str] = []
    for r in adapter_results:
        context_nodes.extend(r.nodes)
        context_edges.extend(r.edges)
        context_gaps.extend(r.gaps)
        if r.error:
            console.print(f"[yellow]Warning: {rmarkup(r.adapter_name)} adapter degraded:[/yellow] {rmarkup(r.error)}")

    # Derive the legacy cve_enrichment shape from CveMcpAdapter's graph nodes/edges
    # (same underlying stdio MCP call as before, now routed through the adapter —
    # cve_refs below still consumes this exact dict shape, unchanged).
    cve_enrichment: dict[str, Any] = {}
    for node in context_nodes:
        if node.type == "cve":
            technique_ids = [
                e.target_id.split(":", 1)[1]
                for e in context_edges
                if e.source_id == node.id and e.relation == "maps_to"
            ]
            cve_enrichment[node.label] = {
                "cvss_score": node.properties.get("cvss_score"),
                "cvss_severity": node.properties.get("cvss_severity", ""),
                "is_kev": node.properties.get("is_kev", False),
                "technique_ids": technique_ids,
                "skill_ids": [],
            }
    if config.api_key and entities.cve_ids:
        platform_cves = fetch_platform_cve_spotlights(entities.cve_ids)
        if platform_cves:
            cve_enrichment.update(platform_cves)

    console.print("[dim]Phase C: Finding similar plans (platform, informational)…[/dim]")
    # NOTE: local-history similarity (customer-owned investigation memory) is Phase 2
    # (LocalHistoryAdapter, requires the Postgres investigation-object store). For now
    # this stays as the pre-existing platform-mode-only lookup, informational only —
    # it does not yet feed the classifier pipeline below.
    similar_plans = find_similar_local_plans(evidence_text)
    if config.api_key:
        fetch_platform_playbooks(entities.technique_ids)  # informational only, unchanged from before
    if similar_plans:
        console.print(f"[dim]Similar plans in history: {len(similar_plans)}[/dim]")

    try:
        console.print("[dim]Phase D: Running classifier pipeline…[/dim]")
        pipeline_entities = PipelineEntities(
            cve_ids=entities.cve_ids,
            technique_ids=entities.technique_ids,
            ips=entities.ips,
            hostnames=entities.hostnames,
        )
        classifier_input = ClassifierInput(
            evidence_text=evidence_text,
            entities=pipeline_entities,
            context_nodes=context_nodes,
            context_edges=context_edges,
            context_gaps=context_gaps,
            skill_index=library.load_index(),
        )
        output = asyncio.run(run_pipeline(
            classifier_input,
            provider,
            on_progress=lambda msg: console.print(f"  [dim]→ {msg}[/dim]"),
        ))

        selected_skills = output.steps
        if not isinstance(selected_skills, list):
            console.print("[red]Pipeline returned invalid output[/red]")
            return None
        if not selected_skills:
            # Not necessarily a bug — but never let this be silent. Check
            # stderr for a "[casky_pipeline:pipeline] ... degraded" or
            # "all N proposed skill_slug(s) failed to match" line, which
            # explains exactly which stage produced nothing and why.
            # console.print() is Rich — it treats bare [...] as markup, so the literal
            # marker name below MUST be escaped (leading \[) or Rich silently swallows
            # it as an unrecognized style tag. Live-caught: without the escape this
            # rendered as "check the '' warnings above" — the marker name vanished
            # entirely, actively misleading anyone trying to find the real diagnostic.
            console.print(
                "[yellow]No investigation steps were selected.[/yellow] This can happen if "
                "the classifier's proposed skills didn't match the local skill library, if "
                "a pipeline stage's response failed to parse, or if the model itself "
                "returned zero validated techniques for this evidence (a legitimate, if "
                "conservative, outcome — check the evidence_gaps below) — check for a "
                "'\\[casky_pipeline:pipeline]' warning above for the specific cause. "
                "Try running again; LLM output varies between calls."
            )

        steps: list[Step] = []
        confidence_scores = []
        evidence_gaps = list(output.evidence_gaps)

        for item in selected_skills:
            slug = item.get("skill_slug", "")
            subdomain = item.get("skill_category", "")
            category = SUBDOMAIN_TO_CATEGORY.get(subdomain, "recon")
            if subdomain and subdomain not in SUBDOMAIN_TO_CATEGORY:
                console.print(f"[yellow]Warning: unknown subdomain '{rmarkup(subdomain)}', using 'recon'[/yellow]")

            skill_document = library.get_skill_document(slug)
            steps.append(Step(
                id=str(uuid.uuid4()),
                skill_slug=slug,
                skill_category=category,
                skill_document=skill_document,
                technique_id=item.get("technique_id", ""),
                technique_name=item.get("technique_name", ""),
                rationale=item.get("rationale", ""),
                evidence_focus=item.get("evidence_focus", ""),
                step_order=item.get("step_order", len(steps) + 1),
            ))

            confidence_scores.append(item.get("confidence", 0.0))
            if item.get("evidence_gaps"):
                evidence_gaps.extend(item.get("evidence_gaps", []))

        cve_refs = []
        if cve_enrichment and isinstance(cve_enrichment, dict):
            for cve_id in entities.cve_ids:
                if cve_id in cve_enrichment:
                    cve_data = cve_enrichment[cve_id]
                    cve_refs.append(CveEnrichment(
                        cve_id=cve_id,
                        cvss_score=cve_data.get("cvss_score"),
                        cvss_severity=cve_data.get("cvss_severity", ""),
                        is_kev=cve_data.get("is_kev", False),
                        technique_ids=cve_data.get("technique_ids", []),
                        skill_ids=cve_data.get("skill_ids", []),
                    ))

        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0

        # Domain should describe *what kind of investigation this is* (e.g. "cloud",
        # "identity") for display in the steps table title / report heading — not the
        # raw evidence text. A prior version used `evidence_text[:50]`, which meant
        # pasting a CloudTrail JSON blob produced a title like
        # 'Investigation Steps — {"Records": [{ "eventVersion": ...' instead of
        # 'Investigation Steps — cloud'. Derive it from the categories the classifier
        # actually selected (majority vote among steps), matching how platform-mode
        # plans already show a clean single-word domain.
        if steps:
            category_counts = collections.Counter(s.skill_category for s in steps if s.skill_category)
            domain = category_counts.most_common(1)[0][0] if category_counts else "Local Investigation"
        else:
            domain = "Local Investigation"

        plan = Plan(
            id=str(uuid.uuid4()),
            domain=domain,
            evidence_text=evidence_text,
            status="approved",
            steps=steps,
            created_at=datetime.now().isoformat(),
            cve_references=cve_refs,
            evidence_gaps=list(set(evidence_gaps)),
            confidence=avg_confidence,
        )

        config.plans_dir.mkdir(parents=True, exist_ok=True)
        plan_file = config.plans_dir / f"{plan.id}.json"
        plan_data = {
            "id": plan.id,
            "domain": plan.domain,
            "evidence_text": plan.evidence_text,
            "status": plan.status,
            "created_at": plan.created_at,
            "cve_references": [
                {
                    "cve_id": r.cve_id,
                    "cvss_score": r.cvss_score,
                    "cvss_severity": r.cvss_severity,
                    "is_kev": r.is_kev,
                    "technique_ids": r.technique_ids,
                    "skill_ids": r.skill_ids,
                }
                for r in plan.cve_references
            ],
            "evidence_gaps": plan.evidence_gaps,
            "confidence": plan.confidence,
            "investigation_steps": [
                {
                    "id": s.id,
                    "skill_slug": s.skill_slug,
                    "skill_category": s.skill_category,
                    "skill_document": s.skill_document,
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "rationale": s.rationale,
                    "evidence_focus": s.evidence_focus,
                    "step_order": s.step_order,
                    "status": s.status,
                }
                for s in plan.steps
            ],
        }
        plan_file.write_text(json.dumps(plan_data, indent=2))
        console.print(f"[green]Plan saved:[/green] {plan_file}")
        console.print(f"[green]Confidence:[/green] {avg_confidence:.1%}")
        if plan.evidence_gaps:
            console.print(f"[yellow]Evidence gaps:[/yellow] {rmarkup(', '.join(plan.evidence_gaps[:3]))}")
        return plan

    except json.JSONDecodeError as e:
        # {e} can echo back a slice of the raw (possibly malformed-JSON, possibly
        # bracket-containing) LLM response text — escape it, same reasoning as above.
        console.print(f"[red]Failed to parse classifier response:[/red] {rmarkup(str(e))}")
        return None
    except Exception as e:
        console.print(f"[red]Error generating plan:[/red] {rmarkup(str(e))}")
        return None


# ── Local report server ───────────────────────────────────────────────────────

_local_reports: dict[str, Any] = {}
_local_plan_id: str = ""


class _ReportHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # silence request logs — harness UI handles display

    def do_POST(self) -> None:
        # POST /api/runs/{run_id}/report
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400); self.end_headers()
            return

        parts = self.path.strip("/").split("/")
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "runs" and parts[3] == "report":
            run_id = parts[2]
            _local_reports[run_id] = data
            # Persist to disk
            reports_dir = Path("/var/casky/reports") / _local_plan_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            (reports_dir / f"{run_id}.json").write_text(json.dumps(data, indent=2))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        self.send_response(404); self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/api/reports":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(_local_reports.keys())).encode())
        elif self.path.startswith("/api/reports/"):
            run_id = self.path.split("/")[-1]
            if run_id in _local_reports:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(_local_reports[run_id]).encode())
            else:
                self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()


class LocalReportServer(threading.Thread):
    def __init__(self, plan_id: str) -> None:
        super().__init__(daemon=True)
        global _local_plan_id
        _local_plan_id = plan_id
        self._server = HTTPServer(("0.0.0.0", config.local_port), _ReportHandler)

    def run(self) -> None:
        self._server.serve_forever()

    @property
    def base_url(self) -> str:
        # Use container hostname so skill-lab can POST findings back
        # (localhost won't work across docker networks)
        return f"http://casky-runner:{config.local_port}"


# ── Platform API client ───────────────────────────────────────────────────────

class PlatformClient:
    def list_plans(self) -> list[Plan]:
        try:
            resp = requests.get(
                f"{config.app_url}/api/v1/plans",
                headers=config.auth_header,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return [self._parse_plan(p) for p in data.get("plans", [])]
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach {config.app_url}: {exc}") from exc

    def create_run(self, plan_id: str, skill_slug: str, step_order: int) -> dict[str, str]:
        resp = requests.post(
            f"{config.app_url}/api/v1/runs",
            headers=config.auth_header,
            json={"plan_id": plan_id, "skill_slug": skill_slug, "step_order": step_order},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def load_local_plan(self, path: Path) -> Plan:
        data = json.loads(path.read_text())
        return self._parse_plan(data)

    def list_local_plans(self) -> list[tuple[Path, Plan]]:
        config.plans_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for p in sorted(config.plans_dir.glob("*.json")):
            try:
                results.append((p, self.load_local_plan(p)))
            except Exception:
                pass
        return results

    def _parse_plan(self, data: dict) -> Plan:
        steps = [
            Step(
                id=s.get("id", str(uuid.uuid4())),
                skill_slug=s.get("skill_slug", ""),
                skill_category=s.get("skill_category", "web-app"),
                skill_document=s.get("skill_document", ""),
                technique_id=s.get("technique_id", ""),
                technique_name=s.get("technique_name", ""),
                rationale=s.get("rationale", ""),
                evidence_focus=s.get("evidence_focus", ""),
                step_order=s.get("step_order", i),
                status=s.get("status", "pending"),
            )
            for i, s in enumerate(data.get("investigation_steps", []))
        ]

        cve_refs = [
            CveEnrichment(
                cve_id=r.get("cve_id", ""),
                cvss_score=r.get("cvss_score"),
                cvss_severity=r.get("cvss_severity", ""),
                is_kev=r.get("is_kev", False),
                technique_ids=r.get("technique_ids", []),
                skill_ids=r.get("skill_ids", []),
            )
            for r in data.get("cve_references", [])
        ]

        return Plan(
            id=data.get("id", ""),
            domain=data.get("domain", ""),
            evidence_text=data.get("evidence_text", ""),
            status=data.get("status", ""),
            steps=steps,
            created_at=data.get("created_at", ""),
            cve_references=cve_refs,
            evidence_gaps=data.get("evidence_gaps", []),
            confidence=data.get("confidence", 0.0),
        )


# ── Skill prompt assembly ─────────────────────────────────────────────────────

def assemble_prompt(plan: Plan, step: Step) -> str:
    """
    Assembles the full prompt that casky.sh pipes to 'claude --print'.
    The skill document is the investigation playbook (prerequisites, tool commands,
    methodology). Evidence and technique context are appended so Claude understands
    exactly what to investigate and why.
    """
    parts = []

    if step.skill_document:
        parts.append(step.skill_document)
        parts.append("\n---\n")

    parts.append("## Evidence for this investigation\n")
    parts.append(plan.evidence_text or "(no evidence provided)")
    parts.append("\n")

    if step.technique_id or step.technique_name:
        parts.append("\n## Technique context\n")
        if step.technique_id and step.technique_name:
            parts.append(f"**Technique:** {step.technique_name} ({step.technique_id})\n")
        elif step.technique_name:
            parts.append(f"**Technique:** {step.technique_name}\n")
        if step.rationale:
            parts.append(f"**Rationale:** {step.rationale}\n")
        if step.evidence_focus:
            parts.append(f"**Focus:** {step.evidence_focus}\n")

    return "".join(parts)


# ── Agent worker ──────────────────────────────────────────────────────────────

class AgentWorker:
    """Wraps one 'casky run <category>' subprocess — one per investigation step."""

    async def execute(
        self,
        plan: Plan,
        step: Step,
        report_base_url: str,
        output_lines: list[str],
    ) -> AgentResult:
        run_id = str(uuid.uuid4())
        token = "local"

        if not config.is_local_mode:
            client = PlatformClient()
            run_data = client.create_run(plan.id, step.skill_slug, step.step_order)
            run_id = run_data["run_id"]
            token = run_data["token"]

        prompt = assemble_prompt(plan, step)

        env = {
            **os.environ,
            "CASKY_RUN_ID": run_id,
            "CASKY_TOKEN": token,
            "CASKY_APP_URL": report_base_url,
        }

        proc = await asyncio.create_subprocess_exec(
            "casky",
            "run",
            step.skill_category,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )

        assert proc.stdin is not None
        proc.stdin.write(prompt.encode())
        proc.stdin.close()

        assert proc.stdout is not None
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").rstrip()
            output_lines.append(line)

        await proc.wait()

        return AgentResult(
            step=step,
            run_id=run_id,
            exit_code=proc.returncode or 0,
            output="\n".join(output_lines),
            report_url=f"{report_base_url}/api/runs/{run_id}/report",
        )


# ── Orchestrator ──────────────────────────────────────────────────────────────

class CaskyHarness:
    def __init__(self, plan: Plan, steps: list[Step], report_url: str) -> None:
        self.plan = plan
        self.steps = steps
        self.report_url = report_url
        # Per-step live output buffers (index → lines)
        self.output_buffers: dict[int, list[str]] = {i: [] for i in range(len(steps))}
        # Per-step status: pending / running / done / failed
        self.step_status: dict[int, str] = {i: "pending" for i in range(len(steps))}
        self.results: list[AgentResult | BaseException] = []

    async def run(self) -> None:
        sem = asyncio.Semaphore(config.concurrency)
        tasks = [
            asyncio.create_task(self._run_step(i, step, sem))
            for i, step in enumerate(self.steps)
        ]
        self.results = await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_step(self, idx: int, step: Step, sem: asyncio.Semaphore) -> AgentResult:
        async with sem:
            self.step_status[idx] = "running"
            worker = AgentWorker()
            try:
                result = await worker.execute(
                    self.plan, step, self.report_url, self.output_buffers[idx]
                )
                self.step_status[idx] = "done" if result.exit_code == 0 else "failed"
                return result
            except Exception as exc:
                self.step_status[idx] = "failed"
                self.output_buffers[idx].append(f"[ERROR] {exc}")
                raise


# ── Consolidated report generator ─────────────────────────────────────────────

def generate_consolidated_report(plan: Plan, results: list[Any]) -> Path:
    reports_dir = Path("/var/casky/reports") / plan.id
    reports_dir.mkdir(parents=True, exist_ok=True)

    findings_all: list[dict] = []
    summaries: list[str] = []

    for r in results:
        if isinstance(r, AgentResult):
            report_file = reports_dir / f"{r.run_id}.json"
            if report_file.exists():
                try:
                    data = json.loads(report_file.read_text())
                    findings_all.extend(data.get("findings", []))
                    if data.get("summary"):
                        summaries.append(data["summary"])
                except Exception:
                    pass

    # Severity ordering for sorting
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings_all.sort(key=lambda f: sev_order.get(str(f.get("severity", "")).lower(), 99))

    # Markdown report
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    md_lines = [
        f"# Investigation Report — {plan.domain}",
        f"",
        f"**Plan ID:** {plan.id}",
        f"**Generated:** {now}",
        f"**Steps:** {len(results)} | **Findings:** {len(findings_all)}",
        f"",
        f"## Executive Summary",
        f"",
    ]
    for s in summaries:
        md_lines.append(f"- {s}")
    if not summaries:
        md_lines.append("No summaries provided.")

    md_lines += ["", "## Findings", ""]
    if findings_all:
        md_lines.append("| # | Severity | Title | Technique |")
        md_lines.append("|---|---|---|---|")
        for i, f in enumerate(findings_all, 1):
            sev = f.get("severity", "")
            title = f.get("title", f.get("description", ""))
            tech = f.get("technique_id", "")
            md_lines.append(f"| {i} | {sev} | {title} | {tech} |")
    else:
        md_lines.append("No findings recorded.")

    report_md = reports_dir / "REPORT.md"
    report_md.write_text("\n".join(md_lines))

    # JSON consolidated
    consolidated = {
        "plan_id": plan.id,
        "domain": plan.domain,
        "generated_at": now,
        "steps_run": len(results),
        "findings": findings_all,
        "summaries": summaries,
    }
    (reports_dir / "consolidated.json").write_text(json.dumps(consolidated, indent=2))

    return report_md


# ── Terminal UI ───────────────────────────────────────────────────────────────

class HarnessUI:
    def show_welcome(self) -> None:
        mode = "[yellow]LOCAL MODE[/yellow]" if config.is_local_mode else f"[green]PLATFORM MODE[/green] · {config.app_url}"
        console.print(Panel(
            f"[bold white]Casky.AI Agentic Harness[/bold white]\n{mode}",
            border_style="cyan",
        ))

    def ask_plan_source(self) -> str:
        console.print("\n[cyan]Plan Source[/cyan]")
        console.print("  [bold]g[/bold]  Generate new plan from evidence (requires skills library)")
        console.print("  [bold]p[/bold]  Load plan from platform")
        console.print("  [bold]l[/bold]  Load local plan file")
        choice = Prompt.ask("Choose", choices=["g", "p", "l"], default="l", console=console)
        return choice

    def show_plan_list_platform(self, plans: list[Plan]) -> Plan | None:
        if not plans:
            console.print("[yellow]No approved or running investigation plans found.[/yellow]")
            console.print(f"Approve a plan at {config.app_url} first.")
            return None

        table = Table(title="Investigation Plans", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Domain")
        table.add_column("Status")
        table.add_column("Steps", justify="right")
        table.add_column("Created")

        for i, p in enumerate(plans, 1):
            table.add_row(
                str(i),
                rmarkup(p.domain) or p.id[:12],
                p.status,
                str(len(p.steps)),
                p.created_at[:10] if p.created_at else "",
            )

        console.print(table)
        choice = IntPrompt.ask("Select plan", default=1, console=console)
        idx = max(1, min(choice, len(plans))) - 1
        return plans[idx]

    def show_plan_list_local(self, plans: list[tuple[Path, Plan]]) -> Plan | None:
        if not plans:
            console.print(f"[yellow]No local plans found in {config.plans_dir}[/yellow]")
            console.print("Export a plan from casky.ai and save it as:")
            console.print(f"  {config.plans_dir}/<plan-id>.json")
            return None

        table = Table(title=f"Local Plans ({config.plans_dir})", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("File")
        table.add_column("Domain")
        table.add_column("Steps", justify="right")

        for i, (path, p) in enumerate(plans, 1):
            table.add_row(str(i), path.name, rmarkup(p.domain) or p.id[:12], str(len(p.steps)))

        console.print(table)
        choice = IntPrompt.ask("Select plan", default=1, console=console)
        idx = max(1, min(choice, len(plans))) - 1
        return plans[idx][1]

    def show_step_select(self, plan: Plan) -> list[Step]:
        # Table.add_row()/title both parse Rich markup too — plan.domain and
        # technique_name/skill_slug can carry LLM-generated or (for plans on disk
        # from before the domain-derivation fix) raw evidence text, so escape them
        # here as well, not just in print_interactive_runbook.
        table = Table(title=f"Investigation Steps — {rmarkup(plan.domain)}", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Technique")
        table.add_column("Skill")
        table.add_column("Category")
        table.add_column("Status")

        for i, s in enumerate(plan.steps, 1):
            tech = f"{s.technique_name} ({s.technique_id})" if s.technique_id else s.technique_name
            table.add_row(str(i), rmarkup(tech) or "—", rmarkup(s.skill_slug) or "—", s.skill_category, s.status)

        console.print(table)
        console.print("\n[dim]Enter step numbers to run (e.g. 1,3) or press Enter to run all[/dim]")
        try:
            raw = Prompt.ask("Steps", default="all", console=console)
        except EOFError:
            # No interactive stdin at all (e.g. a scripted/headless invocation using
            # -i/--input-file with stdin closed or redirected from /dev/null) — the
            # whole point of -i is to support exactly that non-interactive path, so
            # default to running every step instead of crashing with a raw traceback.
            console.print("[dim]No interactive input available — running all steps.[/dim]")
            raw = "all"

        if raw.strip().lower() in ("", "all"):
            return plan.steps

        selected = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit():
                i = int(tok) - 1
                if 0 <= i < len(plan.steps):
                    selected.append(plan.steps[i])
        return selected or plan.steps

    def show_skill_preview(self, step: Step) -> None:
        if not step.skill_document:
            return
        # Show first 10 lines of the skill document. Panel content is Rich markup
        # too, and this is real third-party SKILL.md text (markdown links, code
        # snippets) we don't control — escape it before appending our own
        # intentional "[dim]…[/dim]" markup tag, so that one still renders as a
        # style rather than getting escaped along with everything else.
        preview_lines = step.skill_document.splitlines()[:10]
        preview = rmarkup("\n".join(preview_lines))
        if len(step.skill_document.splitlines()) > 10:
            preview += "\n[dim]…[/dim]"
        console.print(Panel(preview, title=f"Skill: {rmarkup(step.skill_slug)}", border_style="blue"))

    def build_dashboard(self, harness: CaskyHarness) -> Layout:
        layout = Layout()
        header = Panel(
            f"[bold]Casky.AI Agentic Harness[/bold] · [cyan]{rmarkup(harness.plan.domain)}[/cyan]",
            border_style="cyan",
            height=3,
        )
        layout.split_column(Layout(header, size=3), Layout(name="agents"))

        panels = []
        for i, step in enumerate(harness.steps):
            status = harness.step_status.get(i, "pending")
            status_color = {"pending": "dim", "running": "yellow", "done": "green", "failed": "red"}.get(status, "dim")
            tech = step.technique_id or step.skill_slug or f"Step {i+1}"
            title = f"[{status_color}]{rmarkup(tech)} ({step.skill_category}) — {status.upper()}[/{status_color}]"
            lines = harness.output_buffers.get(i, [])
            # Show last 5 lines of output in panel. This is real subprocess stdout
            # from the actual 'casky run <skill> --agent ...' invocation — arbitrary,
            # untrusted text (code blocks, tool output, JSON) — escape it; the
            # "[dim]waiting…[/dim]" fallback below is our own literal, not escaped.
            visible = rmarkup("\n".join(lines[-5:])) if lines else "[dim]waiting…[/dim]"
            panels.append(Panel(visible, title=title, border_style=status_color))

        # Render panels vertically
        layout["agents"].split_column(*[Layout(p, size=8) for p in panels]) if panels else None
        return layout

    def show_summary(self, harness: CaskyHarness, report_path: Path | None = None) -> None:
        table = Table(title="Results", border_style="cyan")
        table.add_column("Step")
        table.add_column("Status")
        table.add_column("Run ID")
        table.add_column("Findings")

        for r in harness.results:
            if isinstance(r, AgentResult):
                status_color = "green" if r.exit_code == 0 else "red"
                status_label = "DONE" if r.exit_code == 0 else "FAILED"
                # Count findings from local store if available
                findings_count = len(_local_reports.get(r.run_id, {}).get("findings", []))
                tech = r.step.technique_id or r.step.skill_slug or "?"
                table.add_row(
                    rmarkup(tech),
                    f"[{status_color}]{status_label}[/{status_color}]",
                    r.run_id[:12] + "…",
                    str(findings_count) if findings_count else "—",
                )
            else:
                table.add_row("?", "[red]ERROR[/red]", "—", "—")

        console.print(table)

        if report_path and report_path.exists():
            console.print(f"\n[green]Consolidated report:[/green] {report_path}")
        elif not config.is_local_mode:
            console.print(f"\n[green]View full report:[/green] {config.app_url}/investigations/{harness.plan.id}")


# ── Main entry point ──────────────────────────────────────────────────────────

async def _run_harness(plan: Plan, steps: list[Step]) -> None:
    ui = HarnessUI()

    report_url = config.app_url
    server: LocalReportServer | None = None

    if config.is_local_mode:
        server = LocalReportServer(plan.id)
        server.start()
        report_url = server.base_url
        console.print(f"[dim]Local report server started on {report_url}[/dim]")

    harness = CaskyHarness(plan, steps, report_url)

    # Show skill previews for each selected step
    for step in steps:
        ui.show_skill_preview(step)

    console.print(f"\n[cyan]Running {len(steps)} agent(s) with concurrency={config.concurrency}…[/cyan]\n")

    # Live dashboard while agents run
    with Live(refresh_per_second=4, console=console) as live:
        run_task = asyncio.create_task(harness.run())
        while not run_task.done():
            live.update(ui.build_dashboard(harness))
            await asyncio.sleep(0.25)
        live.update(ui.build_dashboard(harness))
        await run_task  # re-raise exceptions if any

    console.print()

    # Consolidated report (local mode)
    report_path: Path | None = None
    if config.is_local_mode:
        report_path = generate_consolidated_report(plan, harness.results)

    ui.show_summary(harness, report_path)


# ── Interactive guided investigation ──────────────────────────────────────────

# Matches a plain Python assignment/tuple-unpack statement as a *whole line*
# ("data, _ = netflow.parse_packet(...)", "ts = datetime.fromisoformat(...)").
# Requires at least one space BEFORE the '=' — real bash assignments in this corpus
# are written with no space ("region=$(aws s3api get-bucket-location ...)"), and
# treating those as Python source was a real, live-caught regression: it silently
# dropped a legitimate command line out of the S3-audit skill's working for-loop.
# Python style (and every real corpus example) always spaces the '=' in an
# assignment, so requiring a space cleanly separates the two.
_PY_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s+=\s*\S")

# A quoted-string dict key immediately followed by ':' — e.g. 'source_ip': '',  —
# a Python dict-literal continuation line (from a multi-line {...} spanning several
# lines). Distinct from a real multi-line shell command's JSON *argument* body
# (e.g. --policy-document '{ "Version":"2012-10-17", ...) because that only ever
# shows up mid-buffer (an already-open multi-line command), never as the line that
# *starts* a fresh command — this check only ever runs on buffer-starting lines.
_PY_DICT_ENTRY_RE = re.compile(r"""^['"][^'"]*['"]\s*:\s*\S""")

_PY_BLOCK_KEYWORDS = ("for ", "if ", "while ", "with ", "try", "except", "elif ", "else")


def _looks_like_python_source_line(piece: str) -> bool:
    """True for a standalone line that's clearly Python *source code* (import,
    class/def, docstring, decorator, assignment, a block-opening line) rather than
    something meant to be typed at a shell prompt. See reason 4 in
    _extract_commands_from_skill_doc's docstring for the bug this guards against."""
    p = piece.strip()
    if p.startswith((
        "import ", "from ", "def ", "class ", "@", '"""', "'''", "#!",
        "print(", "return ", "yield ", "raise ", "self.", "async def ",
    )):
        return True
    # Python block syntax ends its opening line with a bare ':' — a real bash
    # for/if/while (e.g. "for f in *.txt; do") never does, so this stays narrow.
    if p.endswith(":") and p.startswith(_PY_BLOCK_KEYWORDS):
        return True
    if _PY_ASSIGNMENT_RE.match(p) or _PY_DICT_ENTRY_RE.match(p):
        return True
    return False


def _extract_commands_from_skill_doc(skill_document: str) -> list[str]:
    """Extract example shell commands from a SKILL.md document.

    Reads the actual lines *inside* fenced code blocks, joining backslash line-
    continuations into one runnable command, and skips fences tagged as a non-command
    format (json/yaml/sql/...) rather than a shell/script snippet. Three real bugs,
    all live-caught against actual shipped SKILL.md files:

    1. A prior version only matched lines starting with ``` or $, which meant it
       captured the *opening fence's language tag* (e.g. "```python" -> "python" after
       stripping backticks) as a bogus command and never read the real command lines
       inside the fence at all — e.g. `performing-cloud-log-forensics-with-athena`'s
       real `## Examples` block (`python agent.py --action full_investigation ...`)
       always degraded to a single fake "python" step.
    2. After fixing (1), `analyzing-cloud-storage-access-patterns` surfaced a second
       bug: its `## Examples` section's fence is ```json sample CloudTrail *input
       data*, not a command — while its real runnable command lived under a
       different heading entirely. Fixed by filtering on fence language, not just
       heading name.
    3. Auditing several real skills (ScoutSuite, Security Hub, S3-audit,
       incident-response) showed their actual runnable commands live under
       `## Workflow`, `## Installation and Setup`, `## Running ScoutSuite`, etc. — an
       open-ended set of headings, not a fixed handful. An allow-list of heading names
       was fundamentally the wrong shape here (it's why nearly every step in real
       investigation runs degraded to the generic 2-line cloud fallback even after
       fixes 1-2). Flipped to a block-list of headings that are reliably *not*
       actionable (Overview, Prerequisites, References, Output Format, ...) — every
       other heading is scanned, relying on the fence-language filter above to keep
       non-command fences out regardless of which heading they're under.
    4. A ```python-tagged fence isn't always a single command invocation — some
       skills (e.g. `detecting-network-scanning-with-ids-signatures`) embed a whole
       illustrative Python *script* (imports, a class, a module docstring) with no
       bare invocation line at all. Every line of it was getting grabbed as its own
       bogus "command" (import json, a bare docstring line, for flow in data.flows:).
       Filtered via _looks_like_python_source_line() — applied only when *starting* a
       new buffered command (never mid multi-line-command continuation), and
       deliberately narrow: e.g. `for X in Y:` (Python) is excluded only when the line
       actually ends in `:`, so a real bash `for f in *.txt; do ... done` loop (a
       genuinely different, already-working case — see the S3-audit test) is untouched.
    """
    commands: list[str] = []
    in_commands_section = True  # default in; flipped off only by a known non-actionable heading
    in_fence = False
    skip_fence = False
    buffer = ""
    # Allow-list, not block-list: `conducting-cloud-incident-response` live-showed a
    # corpus pattern of *untagged* ``` fences used purely as a prose/checklist
    # formatting device ("CloudTrail suspicious events to investigate: - ConsoleLogin
    # from unexpected geolocation...") right alongside properly ```bash-tagged real
    # commands elsewhere in the same doc. Every real command observed across this
    # corpus survey was consistently language-tagged, so require an explicit
    # known-command language rather than defaulting untagged fences to "allowed" —
    # worst case on a miss is a graceful fallback to the generic category commands,
    # same as before this whole fix; the alternative (prose shown as a command) is worse.
    COMMAND_LANGS = {"bash", "sh", "shell", "zsh", "console", "python", "py", "powershell", "ps1"}
    # Headings that reliably describe/reference rather than instruct — everything
    # else (Workflow, Steps, Instructions, Commands, Usage, Examples, Installation
    # and Setup, Running <Tool>, Integration with CI/CD, ...) is scanned.
    NON_ACTIONABLE_HEADINGS = (
        "overview", "when to use", "prerequisites", "key concepts",
        "tools & systems", "tools and systems", "common scenarios",
        "output format", "references", "expected output",
        "interpreting findings", "report analysis", "remediation",
    )

    def flush() -> None:
        nonlocal buffer
        cmd = buffer.strip()
        if cmd and not cmd.startswith("#"):
            commands.append(cmd)
        buffer = ""

    lines = skill_document.split("\n")
    for idx, line in enumerate(lines):
        if len(commands) >= 5:
            break
        if line.startswith("## "):
            heading_text = line[3:].strip().lower()
            in_commands_section = not any(
                heading_text.startswith(marker) for marker in NON_ACTIONABLE_HEADINGS
            )
            in_fence = False
            skip_fence = False
            flush()
            continue
        if not in_commands_section:
            continue

        stripped = line.strip()
        if stripped.startswith("```"):
            if in_fence:
                flush()
                skip_fence = False
            else:
                lang = stripped[3:].strip().lower()
                skip_fence = lang not in COMMAND_LANGS
                if not skip_fence:
                    # Peek ahead to the matching closing fence: a body containing a
                    # class/def line is a whole illustrative script (module
                    # docstring, imports, dict literals, control flow, bare
                    # `continue`/closing-bracket lines — an open-ended set of
                    # statement shapes), not a single command example. Skip the
                    # ENTIRE fence rather than chasing every individual statement
                    # shape line-by-line — live-caught against
                    # detecting-network-scanning-with-ids-signatures's full
                    # ScanDetector class, where per-line filtering alone still let
                    # stray fragments ('})', 'continue', a bare method-chain line)
                    # through.
                    body_end = idx + 1
                    while body_end < len(lines) and not lines[body_end].strip().startswith("```"):
                        body_end += 1
                    fence_body = lines[idx + 1:body_end]
                    if any(
                        l.strip().startswith(("class ", "def ", "async def "))
                        for l in fence_body
                    ):
                        skip_fence = True
            in_fence = not in_fence
            continue

        if in_fence and skip_fence:
            continue

        if in_fence:
            piece = stripped[:-1].strip() if stripped.endswith("\\") else stripped
            if buffer:
                buffer += " " + piece
            elif piece and not piece.startswith("#") and not _looks_like_python_source_line(piece):
                buffer = piece
            # A real multi-line command can also continue via an *open, unterminated
            # quoted string* with no trailing backslash at all — e.g. a JSON
            # --policy-document '{ ... }' argument spanning several lines. Live-
            # caught: without this, each line of the JSON became its own broken
            # pseudo-command instead of one runnable one. Only flush once quotes are
            # balanced (even count of each quote char) AND there's no trailing '\'.
            inside_open_quote = buffer.count("'") % 2 == 1 or buffer.count('"') % 2 == 1
            if not stripped.endswith("\\") and not inside_open_quote:
                flush()
        elif stripped.startswith("$"):
            cmd = stripped.lstrip("$").strip()
            if cmd:
                commands.append(cmd)

    flush()
    return commands[:5]  # Return first 5 commands


def _get_fallback_commands(category: str) -> list[str]:
    """Return generic commands by skill category."""
    fallbacks = {
        "web-app": [
            "curl -s -I http://casky-target/ | head -10",
            "httpx -u http://casky-target -silent",
            "nuclei -u http://casky-target -silent -severity medium",
            "ffuf -u http://casky-target/FUZZ -w /usr/share/wordlists/dirb/common.txt -silent -mc 200,301,302",
            "nikto -h casky-target -nossl",
        ],
        "cloud": [
            "aws s3 ls --profile default 2>/dev/null || echo 'AWS not configured'",
            "aws ec2 describe-instances --region us-east-1 2>/dev/null || echo 'AWS not configured'",
        ],
        "recon": [
            "curl -s http://casky-target/ | head -20",
            "httpx -u http://casky-target -silent",
            "nuclei -u http://casky-target -silent",
        ],
        "network": [
            "ip addr show",
            "netstat -tlnp 2>/dev/null || ss -tlnp",
        ],
    }
    return fallbacks.get(category, ["echo 'Run appropriate security tools for this skill'"])


def print_interactive_runbook(plan: Plan, steps: list[Step]) -> None:
    """Print step-by-step runbook for interactive investigation."""
    console.print(Panel(
        "[bold cyan]Open a skill-lab shell in a new terminal:[/bold cyan]\n\n"
        "  [cyan]docker exec -it skill-lab bash[/cyan]\n\n"
        "[dim]Then follow each step below. Paste the output back to this window when done.[/dim]",
        title="Interactive Investigation Runbook",
        border_style="cyan"
    ))

    # step.technique_name / .rationale / .evidence_focus are LLM-generated free text,
    # and cmd below comes from a third-party skill doc corpus we don't control — any
    # of these can contain a literal '[' that Rich's markup parser would otherwise
    # try to interpret as a style tag (silently swallowing it, or worse). Escape all
    # of them; only the static style tags in these f-strings stay unescaped.
    for i, step in enumerate(steps, 1):
        console.print(f"\n[bold cyan]Step {i}: {rmarkup(step.skill_slug)}[/bold cyan]")
        console.print(
            f"[dim]MITRE Technique:[/dim] {rmarkup(step.technique_id)} — {rmarkup(step.technique_name)}"
        )
        if step.rationale:
            console.print(f"[dim]Goal:[/dim] {rmarkup(step.rationale)}")

        console.print(f"\n[bold]Run in skill-lab:[/bold]")

        # Extract commands from skill document or use fallback
        commands = _extract_commands_from_skill_doc(step.skill_document)
        if not commands:
            commands = _get_fallback_commands(step.skill_category)

        for cmd in commands:
            console.print(f"  [cyan]{rmarkup(cmd)}[/cyan]")

        if step.evidence_focus:
            console.print(f"\n[dim]Look for in output:[/dim] {rmarkup(step.evidence_focus)}")

        console.print("\n" + "─" * 70)

    console.print("\n[green]✓ Paste the output from each step back to this window.[/green]")
    console.print("[green]✓ Provide context about what you found and what it means.[/green]")
    console.print("[green]✓ Claude will analyze and synthesize findings into a report.[/green]\n")


def _load_evidence_from_file(path: Path) -> str:
    """Read evidence text from a file for --input-file/-i, instead of the
    interactive paste prompt. Raises with messages meant to be shown directly to
    the user (FileNotFoundError for a missing path, ValueError for an empty or
    oversized file)."""
    if not path.exists():
        raise FileNotFoundError(
            f"input file not found: {path} — this path is resolved INSIDE THE CONTAINER, "
            "which has its own isolated filesystem, not your host machine's. A host path "
            "like ~/Downloads/... will never exist here unless it's explicitly bind-mounted. "
            "Copy the file into ./evidence/ on the host first (bind-mounted read-only to "
            "/var/casky/evidence — see docker-compose.yml), then pass the in-container path, "
            "e.g.: cp yourfile.json evidence/ && "
            "casky harness -i /var/casky/evidence/yourfile.json"
        )
    # Check the size via stat() BEFORE reading — an oversized file (live-caught: an
    # 82MB pcap-derived JSON dump) should be rejected without first loading all of
    # it into memory. See MAX_EVIDENCE_CHARS for why this limit exists at all.
    size = path.stat().st_size
    if size > MAX_EVIDENCE_CHARS:
        raise ValueError(
            f"input file is {size:,} bytes, over the {MAX_EVIDENCE_CHARS:,}-byte limit: {path} — "
            "evidence is embedded verbatim into every LLM prompt in the pipeline, so a raw, "
            "unfiltered capture this large would blow past any provider's context window. "
            "Pre-process it first — extract only the relevant events/lines (e.g. 'jq' for JSON, "
            "'tshark'/'grep' for pcap-derived text) instead of passing the full raw file."
        )
    text = path.read_text().strip()
    if not text:
        raise ValueError(f"input file is empty: {path}")
    return text


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Casky Agentic Harness")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-execute skills via Claude subprocesses (advanced)")
    parser.add_argument(
        "-i", "--input-file", type=str, default=None,
        help="Read evidence from a file instead of the interactive paste prompt "
             "(e.g. -i /var/casky/evidence/cloudtrail.json — get a file into the "
             "container first via a bind mount or 'docker cp'). Skips the Plan "
             "Source menu and generates a local plan directly from the file's "
             "contents, regardless of platform mode.",
    )
    args = parser.parse_args()

    ui = HarnessUI()
    ui.show_welcome()
    console.print()

    client = PlatformClient()
    plan: Plan | None = None

    # -i/--input-file takes priority over everything else — evidence from a file
    # generates a local plan directly, regardless of platform mode, and skips the
    # interactive Plan Source menu / paste prompt entirely.
    if args.input_file:
        input_path = Path(args.input_file)
        try:
            evidence_text = _load_evidence_from_file(input_path)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {rmarkup(str(exc))}")
            sys.exit(1)
        except ValueError as exc:
            console.print(f"[yellow]{rmarkup(str(exc))}[/yellow]")
            sys.exit(0)

        console.print(f"[dim]Loaded evidence from {rmarkup(str(input_path))} ({len(evidence_text)} bytes)[/dim]")
        console.print("\n[dim]Generating investigation plan…[/dim]")
        plan = generate_local_plan(evidence_text)
        if plan is None:
            sys.exit(1)

    # Check for plan generation or selection
    elif config.is_local_mode:
        source = ui.ask_plan_source()
        console.print()

        if source == "g":
            # Generate plan from evidence.
            #
            # Terminating on Ctrl+D alone is ambiguous on a real interactive TTY:
            # in canonical terminal mode, Ctrl+D only signals true EOF when pressed
            # on an EMPTY line. If pasted evidence doesn't end with a trailing
            # newline (very common — copying from an editor/browser rarely leaves
            # one), the first Ctrl+D just flushes that last partial line to the
            # reading process instead of ending input; you'd need a SECOND Ctrl+D,
            # now on a truly empty line, to actually finish. That's a kernel TTY
            # line-discipline behavior — no amount of Python-side buffering or
            # choice of read() vs input() changes it, so it's not something to
            # "fix" by reading stdin differently.
            #
            # The actual fix: don't rely on ambiguous EOF signaling at all. Accept
            # a literal sentinel line ("END" or "." alone) as the primary way to
            # finish, which is unambiguous regardless of terminal/paste behavior.
            # True EOF (Ctrl+D, or a pipe/redirect closing) still works too — e.g.
            # scripted, non-interactive input with no sentinel line included.
            console.print(
                "[cyan]Paste evidence below. When done, type END alone on its own "
                "line and press Enter (or press Ctrl+D):[/cyan]"
            )
            lines: list[str] = []
            try:
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    lines.append(line)
            except EOFError:
                pass
            evidence_text = "\n".join(lines)

            if not evidence_text.strip():
                console.print("[yellow]No evidence provided.[/yellow]")
                sys.exit(0)

            console.print("\n[dim]Received evidence — generating investigation plan…[/dim]")
            plan = generate_local_plan(evidence_text)
            if plan is None:
                sys.exit(1)

        elif source == "p":
            # Load from platform
            try:
                platform_plans = client.list_plans()
            except RuntimeError as exc:
                console.print(f"[red]Error:[/red] {rmarkup(str(exc))}")
                sys.exit(1)
            plan = ui.show_plan_list_platform(platform_plans)

        else:
            # Load local plan file
            local_plans = client.list_local_plans()
            plan = ui.show_plan_list_local(local_plans)
    else:
        # Platform mode — always load from platform
        try:
            platform_plans = client.list_plans()
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {rmarkup(str(exc))}")
            sys.exit(1)
        plan = ui.show_plan_list_platform(platform_plans)

    if plan is None:
        sys.exit(0)

    if not plan.steps:
        console.print("[yellow]This plan has no investigation steps.[/yellow]")
        sys.exit(0)

    console.print()
    steps = ui.show_step_select(plan)

    if not steps:
        console.print("[yellow]No steps selected.[/yellow]")
        sys.exit(0)

    console.print()

    # Default: interactive guided investigation
    # For power users: --auto flag to enable autonomous execution
    if args.auto:
        # Auto-execute: spawn Claude subprocesses for each skill
        asyncio.run(_run_harness(plan, steps))
    else:
        # Interactive: print runbook and let investigator run commands manually
        print_interactive_runbook(plan, steps)


if __name__ == "__main__":
    main()
