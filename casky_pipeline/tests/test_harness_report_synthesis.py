"""Tests for generate_consolidated_report()'s dedup + executive-summary
synthesis. Live-caught bug this closes (audited against a real 7-step
investigation the night before a 27-person workshop, plan
bbc00d70-fe65-42a3-b7e8-d0d6f7a53da0): every step-agent sees the *same*
shared evidence file, so a multi-step investigation over one coherent
incident had each of its 7 steps independently narrate the whole incident
end-to-end. generate_consolidated_report() just concatenated every step's
own "summary" field verbatim as a separate Executive Summary bullet with
zero cross-step dedup, producing 7 near-identical paragraphs and (in the
findings table) 19 "critical" findings that were really ~5 distinct facts
restated in different words — two of them ("Account and IAM reconnaissance
performed with stolen role credentials") were word-for-word identical.

Two independent fixes, tested separately:
  1. _dedupe_findings() — deterministic, code-only clustering of
     near-duplicate findings by title-token similarity. No LLM involved, so
     it can never fail or add latency/cost to the critical run path.
  2. _synthesize_executive_summary() — one real LLM call (same BYO-provider
     pattern as _synthesize_manual_findings) that writes ONE coherent
     executive summary from the deduplicated findings + raw per-step
     summaries, instead of the report just concatenating raw summaries.
     Guarded: generate_consolidated_report() must fall back to the single
     most detailed raw summary (never crash the whole report) if this call
     fails — verified below, not assumed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402


def _plan(**overrides) -> "harness.Plan":
    base = dict(
        id="plan-1", domain="cloud", evidence_text="SSRF -> IMDSv1 -> S3 exfil evidence",
        status="approved", steps=[], created_at="2026-08-24T00:00:00",
        cve_references=[], evidence_gaps=[], confidence=0.83,
    )
    base.update(overrides)
    return harness.Plan(**base)


def _step(**overrides) -> "harness.Step":
    base = dict(
        id="step-1", skill_slug="exploiting-server-side-request-forgery",
        skill_category="web-app", skill_document="", technique_id="T1190",
        technique_name="Exploit Public-Facing Application", rationale="",
        evidence_focus="", step_order=0, status="done",
    )
    base.update(overrides)
    return harness.Step(**base)


def _agent_result(run_id: str, **overrides) -> "harness.AgentResult":
    return harness.AgentResult(
        step=overrides.pop("step", _step()), run_id=run_id, exit_code=0,
        output="", report_url="http://casky-runner:8765",
    )


# ── _dedupe_findings ─────────────────────────────────────────────────────────

def test_dedupe_collapses_near_duplicate_titles_and_records_corroboration():
    findings = [
        {"title": "SSRF on public proxy endpoint used to steal AWS IAM role credentials from IMDSv1",
         "severity": "critical", "description": "short"},
        {"title": "SSRF-driven theft of EC2 IAM role credentials from IMDS (IMDSv1)",
         "severity": "critical", "description": "a much longer, more detailed description of the same fact"},
        {"title": "IMDSv1 reachable via application SSRF - EC2 role credentials stolen from host i-0abc123",
         "severity": "high", "description": "medium length description"},
    ]
    deduped = harness._dedupe_findings(findings)

    assert len(deduped) == 1
    survivor = deduped[0]
    assert survivor["corroborated_by"] == 3
    # keeps the most detailed (longest description) as the representative
    assert survivor["description"] == "a much longer, more detailed description of the same fact"
    # never silently downgrades — the cluster's best (critical) severity wins
    assert survivor["severity"] == "critical"


def test_dedupe_leaves_genuinely_distinct_findings_separate():
    findings = [
        {"title": "SSRF on public proxy endpoint used to steal AWS IAM role credentials",
         "severity": "critical", "description": "d1"},
        {"title": "No GuardDuty detector enabled in the account",
         "severity": "medium", "description": "d2"},
        {"title": "Malformed ops-admin identity records with long-term key prefix",
         "severity": "low", "description": "d3"},
    ]
    deduped = harness._dedupe_findings(findings)

    assert len(deduped) == 3
    assert all("corroborated_by" not in f for f in deduped)


def test_dedupe_on_the_real_live_caught_workshop_findings():
    """The exact finding titles pulled from the real bbc00d70 investigation
    that surfaced this bug — 19 raw "critical" findings that were really 5
    distinct facts. Asserts the fix actually collapses them, not just that
    it runs."""
    titles = [
        "SSRF on public proxy endpoint used to steal AWS IAM role credentials from IMDSv1",
        "Stolen instance-role credentials replayed from external attacker IP (off-instance valid-account abuse)",
        "Bulk S3 exfiltration of customer PII, payment tokens, SSN index and DB backups via stolen credentials",
        "SSRF-driven theft of EC2 IAM role credentials from IMDS (IMDSv1)",
        "Instance role credentials used from outside AWS (credential exfiltration / abuse)",
        "Bulk exfiltration of customer PII, payment tokens, and DB backup from S3",
        "Stolen EC2 instance-role credential used from external IP for systematic cloud enumeration (T1526)",
        "SSRF against IMDS confirmed as the credential source, correlated to the enumerating IP",
        "Enumeration pivoted to bulk collection of PII, payment and backup data within 10 seconds",
        "S3 exfiltration of PII, payment tokens and DB backup from external IP using stolen instance-role credentials",
        "EC2 instance-role credential presented from outside the VPC (definitive credential theft)",
        "SSRF against /proxy endpoint used to steal IAM role credentials from IMDSv1",
        "IMDS instance-role credentials stolen via SSRF and reused from external IP (Application Access Token abuse)",
        "Bulk exfiltration of customer PII, payment tokens, and database backup from S3",
        "IMDSv1 reachable via application SSRF - EC2 role credentials stolen from host i-0abc123",
        "Bulk collection of customer PII, payment tokens and a database backup from S3 using the stolen role",
        "Application role holds account-wide IAM read permissions, enabling full security-posture discovery",
        "acme-webapp-role can read every prefix of acme-customer-data including PII, bulk exports and database backups",
        "IMDSv1 enabled: SSRF returned EC2 role credentials in a single unauthenticated GET",
    ]
    findings = [{"title": t, "severity": "critical", "description": t} for t in titles]

    deduped = harness._dedupe_findings(findings)

    # This was 19 near-duplicate "critical" findings; the fix must produce
    # meaningfully fewer distinct clusters, not a no-op.
    assert len(deduped) < 10
    assert len(deduped) < len(findings)


def test_dedupe_exact_duplicate_titles():
    """The real report had two findings with byte-for-byte identical titles
    ("Account and IAM reconnaissance performed with stolen role
    credentials") — the simplest possible case, must not survive as two."""
    findings = [
        {"title": "Account and IAM reconnaissance performed with stolen role credentials",
         "severity": "high", "description": "x"},
        {"title": "Account and IAM reconnaissance performed with stolen role credentials",
         "severity": "high", "description": "y"},
    ]
    deduped = harness._dedupe_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["corroborated_by"] == 2


def test_dedupe_empty_list():
    assert harness._dedupe_findings([]) == []


def test_dedupe_corroboration_counts_distinct_steps_not_raw_findings():
    """Live-caught while re-verifying this fix against the real bbc00d70
    workshop investigation: a single step's own report can list the same
    fact more than once internally. Before this test, corroborated_by
    counted raw findings, so one step repeating itself 3 times looked
    identical to 3 independent steps confirming it — real output read
    "confirmed independently by 15 steps" on a 7-step investigation, which
    is impossible and misleading. Findings from the SAME step must not
    inflate the count."""
    findings = [
        {"title": "Stolen credential used from external IP for enumeration",
         "severity": "critical", "description": "d1", "_source_run_id": "run-A"},
        {"title": "Stolen credential used from external IP for cloud enumeration",
         "severity": "critical", "description": "d2 — same step restating itself",
         "_source_run_id": "run-A"},
        {"title": "Stolen instance-role credential used from an external IP for enumeration",
         "severity": "critical", "description": "d3 — a genuinely different step",
         "_source_run_id": "run-B"},
    ]
    deduped = harness._dedupe_findings(findings)

    assert len(deduped) == 1
    # 2 distinct steps (run-A, run-B) corroborated this, not 3 raw findings
    assert deduped[0]["corroborated_by"] == 2


def test_dedupe_same_step_duplicate_alone_gets_no_corroboration_label():
    """A single step repeating itself twice, with no second step involved,
    is not "independent confirmation" — must not carry corroborated_by at
    all (which the report renders as a misleading "_(confirmed
    independently by N steps)_" label)."""
    findings = [
        {"title": "Stolen credential replayed from external IP",
         "severity": "critical", "description": "short", "_source_run_id": "run-A"},
        {"title": "Stolen credential replayed from an external IP address",
         "severity": "critical", "description": "longer, same step restating itself",
         "_source_run_id": "run-A"},
    ]
    deduped = harness._dedupe_findings(findings)

    assert len(deduped) == 1
    assert "corroborated_by" not in deduped[0]


def test_dedupe_strips_internal_source_run_id_from_output():
    findings = [{"title": "x", "severity": "low", "description": "d", "_source_run_id": "run-A"}]
    deduped = harness._dedupe_findings(findings)
    assert "_source_run_id" not in deduped[0]


# ── _synthesize_executive_summary ────────────────────────────────────────────

class _FakeProvider:
    def __init__(self, raw: str):
        self._raw = raw
        self.calls: list[tuple[str, str]] = []

    async def complete(self, system_prompt, user_prompt, max_tokens=1024, cacheable_system=True):
        self.calls.append((system_prompt, user_prompt))
        return self._raw


@pytest.mark.asyncio
async def test_synthesize_executive_summary_parses_provider_response(monkeypatch):
    raw = '{"summary": "One coherent incident narrative.", "risk_rating": "critical"}'
    fake = _FakeProvider(raw)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: fake)

    result = await harness._synthesize_executive_summary(
        _plan(),
        [{"title": "SSRF credential theft", "severity": "critical", "description": "d",
          "corroborated_by": 5}],
        ["raw summary one", "raw summary two"],
    )

    assert result["summary"] == "One coherent incident narrative."
    assert result["risk_rating"] == "critical"
    # the corroboration count and raw summaries must actually reach the prompt
    _, user_prompt = fake.calls[0]
    assert "confirmed independently by 5 steps" in user_prompt
    assert "raw summary one" in user_prompt
    assert "raw summary two" in user_prompt


@pytest.mark.asyncio
async def test_synthesize_executive_summary_strips_code_fences(monkeypatch):
    raw = '```json\n{"summary": "Fenced.", "risk_rating": "high"}\n```'
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: _FakeProvider(raw))

    result = await harness._synthesize_executive_summary(_plan(), [], [])
    assert result["summary"] == "Fenced."


# ── generate_consolidated_report (end-to-end) ────────────────────────────────

def _write_step_report(reports_dir: Path, plan_id: str, run_id: str, summary: str,
                        findings: list[dict]) -> None:
    plan_dir = reports_dir / plan_id
    plan_dir.mkdir(parents=True, exist_ok=True)
    (plan_dir / f"{run_id}.json").write_text(json.dumps({"summary": summary, "findings": findings}))


@pytest.mark.asyncio
async def test_generate_consolidated_report_writes_one_synthesized_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(harness.config, "database_url", "")

    plan = _plan(id="plan-synth")
    _write_step_report(
        tmp_path, plan.id, "run-1", "Full incident narrative from step 1 covering SSRF and exfil.",
        [{"title": "SSRF theft of IMDSv1 credentials", "severity": "critical", "description": "d1"}],
    )
    _write_step_report(
        tmp_path, plan.id, "run-2", "Full incident narrative from step 2 covering the same SSRF and exfil.",
        [{"title": "SSRF-driven theft of EC2 role credentials from IMDS", "severity": "critical", "description": "d2"}],
    )

    fake = _FakeProvider('{"summary": "Synthesized single narrative.", "risk_rating": "critical"}')
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: fake)

    results = [_agent_result("run-1"), _agent_result("run-2")]
    report_path = await harness.generate_consolidated_report(plan, results)

    text = report_path.read_text()
    # exactly one synthesized summary, not both raw step summaries concatenated
    assert "Synthesized single narrative." in text
    assert "Full incident narrative from step 1" not in text
    assert "Full incident narrative from step 2" not in text
    # the two near-duplicate SSRF findings collapsed into one, with corroboration noted
    assert text.count("SSRF") <= 3  # heading/table cell occurrences, not one row per raw finding
    assert "confirmed independently by 2 steps" in text


@pytest.mark.asyncio
async def test_generate_consolidated_report_one_steps_internal_duplicates_dont_inflate_corroboration(tmp_path, monkeypatch):
    """A single step's own report listing the same fact twice must not
    render a "confirmed independently by 2 steps" label — only genuinely
    distinct steps count as corroboration."""
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(harness.config, "database_url", "")

    plan = _plan(id="plan-self-dup")
    _write_step_report(
        tmp_path, plan.id, "run-1", "one step's summary",
        [
            {"title": "Stolen credential replayed from external IP", "severity": "critical", "description": "short"},
            {"title": "Stolen credential replayed from an external IP address",
             "severity": "critical", "description": "longer, same step restating itself"},
        ],
    )
    fake = _FakeProvider('{"summary": "Synthesized.", "risk_rating": "critical"}')
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: fake)

    report_path = await harness.generate_consolidated_report(plan, [_agent_result("run-1")])

    text = report_path.read_text()
    assert "confirmed independently by" not in text


@pytest.mark.asyncio
async def test_generate_consolidated_report_falls_back_when_synthesis_fails(tmp_path, monkeypatch):
    """The guard: a provider outage/timeout must not crash the whole report
    — it must fall back to the single most detailed raw summary instead."""
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(harness.config, "database_url", "")

    plan = _plan(id="plan-fallback")
    _write_step_report(tmp_path, plan.id, "run-1", "short", [])
    _write_step_report(tmp_path, plan.id, "run-2", "the longest and most detailed raw summary available", [])

    async def raise_timeout(*args, **kwargs):
        raise TimeoutError("provider unreachable")

    monkeypatch.setattr(harness, "_synthesize_executive_summary", raise_timeout)

    results = [_agent_result("run-1"), _agent_result("run-2")]
    report_path = await harness.generate_consolidated_report(plan, results)

    text = report_path.read_text()
    assert "the longest and most detailed raw summary available" in text


@pytest.mark.asyncio
async def test_generate_consolidated_report_no_step_summaries_no_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(harness.config, "database_url", "")

    def fail_if_called():
        raise AssertionError("build_provider_from_env should not be called with zero summaries")

    monkeypatch.setattr(harness, "build_provider_from_env", fail_if_called)

    plan = _plan(id="plan-empty")
    report_path = await harness.generate_consolidated_report(plan, [])

    assert "No summaries provided." in report_path.read_text()


@pytest.mark.asyncio
async def test_generate_consolidated_report_consolidated_json_keeps_backward_compat_summaries_key(tmp_path, monkeypatch):
    """casky_db/json_import.py reads consolidated.json's "summaries" list
    (raw, pre-synthesis) as a fallback import path — must not disappear."""
    monkeypatch.setattr(harness, "_LOCAL_REPORTS_DIR", tmp_path)
    monkeypatch.setattr(harness.config, "database_url", "")

    plan = _plan(id="plan-compat")
    _write_step_report(tmp_path, plan.id, "run-1", "raw summary", [])
    monkeypatch.setattr(harness, "build_provider_from_env",
                         lambda: _FakeProvider('{"summary": "synth", "risk_rating": "low"}'))

    await harness.generate_consolidated_report(plan, [_agent_result("run-1")])

    consolidated = json.loads((tmp_path / plan.id / "consolidated.json").read_text())
    assert consolidated["summaries"] == ["raw summary"]
    assert consolidated["summary"] == "synth"
