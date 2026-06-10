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
import json
import os
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
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
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
class Plan:
    id: str
    domain: str
    evidence_text: str
    status: str
    steps: list[Step] = field(default_factory=list)
    created_at: str = ""


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
    app_url: str = field(default_factory=lambda: os.environ.get("CASKY_APP_URL", "https://app.casky.ai").rstrip("/"))
    local_port: int = field(default_factory=lambda: int(os.environ.get("CASKY_LOCAL_PORT", "8765")))
    lab_name: str = field(default_factory=lambda: os.environ.get("SKILL_LAB_NAME", "skill-lab"))
    concurrency: int = field(default_factory=lambda: int(os.environ.get("CASKY_CONCURRENCY", "4")))
    plans_dir: Path = field(default_factory=lambda: Path.home() / ".casky" / "plans")

    @property
    def is_local_mode(self) -> bool:
        return not self.api_key

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}


config = Config()


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
        return f"http://localhost:{config.local_port}"


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
        return Plan(
            id=data.get("id", ""),
            domain=data.get("domain", ""),
            evidence_text=data.get("evidence_text", ""),
            status=data.get("status", ""),
            steps=steps,
            created_at=data.get("created_at", ""),
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
                p.domain or p.id[:12],
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
            console.print("Export a plan from app.casky.ai and save it as:")
            console.print(f"  {config.plans_dir}/<plan-id>.json")
            return None

        table = Table(title=f"Local Plans ({config.plans_dir})", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("File")
        table.add_column("Domain")
        table.add_column("Steps", justify="right")

        for i, (path, p) in enumerate(plans, 1):
            table.add_row(str(i), path.name, p.domain or p.id[:12], str(len(p.steps)))

        console.print(table)
        choice = IntPrompt.ask("Select plan", default=1, console=console)
        idx = max(1, min(choice, len(plans))) - 1
        return plans[idx][1]

    def show_step_select(self, plan: Plan) -> list[Step]:
        table = Table(title=f"Investigation Steps — {plan.domain}", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Technique")
        table.add_column("Skill")
        table.add_column("Category")
        table.add_column("Status")

        for i, s in enumerate(plan.steps, 1):
            tech = f"{s.technique_name} ({s.technique_id})" if s.technique_id else s.technique_name
            table.add_row(str(i), tech or "—", s.skill_slug or "—", s.skill_category, s.status)

        console.print(table)
        console.print("\n[dim]Enter step numbers to run (e.g. 1,3) or press Enter to run all[/dim]")
        raw = Prompt.ask("Steps", default="all", console=console)

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
        # Show first 10 lines of the skill document
        preview_lines = step.skill_document.splitlines()[:10]
        preview = "\n".join(preview_lines)
        if len(step.skill_document.splitlines()) > 10:
            preview += "\n[dim]…[/dim]"
        console.print(Panel(preview, title=f"Skill: {step.skill_slug}", border_style="blue"))

    def build_dashboard(self, harness: CaskyHarness) -> Layout:
        layout = Layout()
        header = Panel(
            f"[bold]Casky.AI Agentic Harness[/bold] · [cyan]{harness.plan.domain}[/cyan]",
            border_style="cyan",
            height=3,
        )
        layout.split_column(Layout(header, size=3), Layout(name="agents"))

        panels = []
        for i, step in enumerate(harness.steps):
            status = harness.step_status.get(i, "pending")
            status_color = {"pending": "dim", "running": "yellow", "done": "green", "failed": "red"}.get(status, "dim")
            tech = step.technique_id or step.skill_slug or f"Step {i+1}"
            title = f"[{status_color}]{tech} ({step.skill_category}) — {status.upper()}[/{status_color}]"
            lines = harness.output_buffers.get(i, [])
            # Show last 5 lines of output in panel
            visible = "\n".join(lines[-5:]) if lines else "[dim]waiting…[/dim]"
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
                    tech,
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


def main() -> None:
    ui = HarnessUI()
    ui.show_welcome()
    console.print()

    client = PlatformClient()

    # Plan selection
    plan: Plan | None = None
    if config.is_local_mode:
        local_plans = client.list_local_plans()
        plan = ui.show_plan_list_local(local_plans)
    else:
        try:
            platform_plans = client.list_plans()
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {exc}")
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
    asyncio.run(_run_harness(plan, steps))


if __name__ == "__main__":
    main()
