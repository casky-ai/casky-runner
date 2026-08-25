"""One-time importer: pre-Postgres on-disk JSON (plans_dir/*.json,
reports_dir/<plan_id>/*.json) -> the Postgres store.

Never raises on a single bad file — a malformed plan or report JSON is
collected into the returned summary's `errors` list and the import
continues, matching this repo's existing "independent guard" philosophy
(see harness.py's MAX_EVIDENCE_CHARS / evidence-size-limit docstrings for the
same design principle applied elsewhere).

Wired as `casky db migrate-json` (see casky.sh's `db` subcommand).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from casky_db import store


def _load_plan_dict(plan_file: Path) -> dict:
    """Reshapes the on-disk plan JSON (harness.py's `investigation_steps` key
    for the step list) into the dict shape store.create_investigation()
    expects (a `steps` key, item field names unchanged)."""
    data = json.loads(plan_file.read_text())
    return {
        "id": data.get("id", ""),
        "domain": data.get("domain", ""),
        "evidence_text": data.get("evidence_text", ""),
        "status": data.get("status", "draft"),
        "created_at": data.get("created_at", ""),
        "confidence": data.get("confidence", 0.0),
        "evidence_gaps": data.get("evidence_gaps", []),
        "steps": data.get("investigation_steps", []),
        "cve_references": data.get("cve_references", []),
    }


def import_json_plans(plans_dir: Path, reports_dir: Path, database_url: str | None = None) -> dict:
    """Imports every plans_dir/*.json plan and its matching
    reports_dir/<plan_id>/*.json run reports + consolidated report (if any).

    Returns {plans_imported, plans_skipped_existing, findings_imported,
    reports_imported, errors: list[str]}."""
    summary = {
        "plans_imported": 0,
        "plans_skipped_existing": 0,
        "findings_imported": 0,
        "reports_imported": 0,
        "errors": [],
    }

    if not plans_dir.exists():
        summary["errors"].append(f"plans_dir does not exist: {plans_dir}")
        return summary

    for plan_file in sorted(plans_dir.glob("*.json")):
        try:
            plan_dict = _load_plan_dict(plan_file)
        except Exception as exc:
            summary["errors"].append(f"{plan_file}: could not parse plan JSON: {exc}")
            continue

        plan_id = plan_dict.get("id", "")
        if not plan_id:
            summary["errors"].append(f"{plan_file}: plan JSON has no 'id' field, skipped")
            continue

        try:
            existing = store.get_investigation(plan_id, database_url=database_url)
        except store.DatabaseUnavailable:
            raise  # not a per-file problem — the whole import can't proceed
        except Exception as exc:
            summary["errors"].append(f"{plan_file}: could not check for existing investigation: {exc}")
            continue

        if existing is not None:
            summary["plans_skipped_existing"] += 1
            continue

        try:
            store.create_investigation(plan_dict, database_url=database_url)
            summary["plans_imported"] += 1
        except store.DatabaseUnavailable:
            raise
        except Exception as exc:
            summary["errors"].append(f"{plan_file}: could not import plan: {exc}")
            continue

        _import_reports_for_plan(plan_id, reports_dir / plan_id, summary, database_url)

    return summary


def _import_reports_for_plan(
    plan_id: str, plan_reports_dir: Path, summary: dict, database_url: str | None
) -> None:
    if not plan_reports_dir.exists():
        return

    for report_file in sorted(plan_reports_dir.glob("*.json")):
        if report_file.name in ("consolidated.json",):
            continue  # derived artifact, handled separately below

        run_id = report_file.stem
        try:
            data = json.loads(report_file.read_text())
        except Exception as exc:
            summary["errors"].append(f"{report_file}: could not parse report JSON: {exc}")
            continue

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            summary["errors"].append(f"{report_file}: 'findings' is not a list, skipped")
            continue

        try:
            # skill_execution_id: the JSON report shape has no execution
            # record of its own (see harness.py's _ReportHandler.do_POST) —
            # findings are linked directly to the investigation, with no
            # skill_execution_id, rather than inventing execution metadata
            # (agent/model/timing) this importer has no way to know.
            store.record_findings(plan_id, None, findings, database_url=database_url)
            summary["findings_imported"] += len(findings)
            summary["reports_imported"] += 1
        except store.DatabaseUnavailable:
            raise
        except Exception as exc:
            summary["errors"].append(f"{report_file}: could not import findings: {exc}")

    consolidated_file = plan_reports_dir / "consolidated.json"
    if consolidated_file.exists():
        try:
            consolidated = json.loads(consolidated_file.read_text())
            # Prefer the synthesized "summary" (harness.py's
            # generate_consolidated_report() started writing this alongside
            # the pre-existing "summaries" list — one real LLM-synthesized
            # narrative instead of every step's raw summary concatenated).
            # Older consolidated.json files have no "summary" key, so fall
            # back to joining "summaries" for those.
            summary_text = consolidated.get("summary") or "\n".join(consolidated.get("summaries", []))
            store.save_consolidated_report(
                investigation_id=plan_id,
                summary=summary_text,
                risk_rating=None,
                markdown="",
                report_json=consolidated,
                database_url=database_url,
            )
        except store.DatabaseUnavailable:
            raise
        except Exception as exc:
            summary["errors"].append(f"{consolidated_file}: could not import consolidated report: {exc}")


def main(argv: list[str] | None = None) -> int:
    import os

    argv = sys.argv[1:] if argv is None else argv
    plans_dir = Path(argv[0]) if len(argv) > 0 else Path.home() / ".casky" / "plans"
    reports_dir = Path(argv[1]) if len(argv) > 1 else Path("/var/casky/reports")
    database_url = os.environ.get("DATABASE_URL", "")

    try:
        summary = import_json_plans(plans_dir, reports_dir, database_url=database_url)
    except store.DatabaseUnavailable as exc:
        print(f"[casky_db.json_import] {exc}", file=sys.stderr)
        return 1

    print(
        f"[casky_db.json_import] plans_imported={summary['plans_imported']} "
        f"plans_skipped_existing={summary['plans_skipped_existing']} "
        f"findings_imported={summary['findings_imported']} "
        f"reports_imported={summary['reports_imported']} "
        f"errors={len(summary['errors'])}"
    )
    for err in summary["errors"]:
        print(f"  [error] {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
