"""End-to-end integration test for the Phase 1 wiring in harness.py.

Exercises generate_local_plan() through the real casky_pipeline adapter fan-out
and pipeline orchestration, with only the LLM-facing edges mocked:
  - No CVE IDs / MITRE technique IDs in the evidence text, so CveMcpAdapter and
    LocalPlaybookAdapter both take their real, already-tested empty-input
    short-circuit paths (see test_cve_mcp_adapter.py / test_local_playbook_adapter.py)
    with zero network/subprocess calls — nothing to mock there.
  - casky_pipeline.pipeline.run_pipeline is monkeypatched to a canned
    ClassifierOutput, isolating this test to the harness.py <-> casky_pipeline
    integration boundary (the pipeline's own internal stage logic is already
    covered by test_pipeline.py).

Per PHASE1_CONTRACT.md Section 6 item 5, this proves:
  (a) the Plan/Step objects and the on-disk investigation_steps JSON shape are
      unchanged from the pre-Phase-1 contract, and
  (b) PlatformClient._parse_plan can still round-trip the written file.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import harness  # noqa: E402  (path insert must happen first)
from casky_pipeline.pipeline import ClassifierOutput  # noqa: E402


@pytest.fixture
def skills_library(tmp_path: Path) -> Path:
    lib = tmp_path / "skills-library"
    (lib / "skills" / "web-app-recon-basics" / "scripts").mkdir(parents=True)
    (lib / "skills" / "web-app-recon-basics" / "SKILL.md").write_text(
        "# Web App Recon Basics\n\nDo recon things.\n"
    )
    index = {
        "skills": [
            {
                "name": "web-app-recon-basics",
                "subdomain": "web-app",
                "description": "Basic web application reconnaissance",
            }
        ]
    }
    (lib / "index.json").write_text(json.dumps(index))
    return lib


@pytest.fixture
def isolated_config(tmp_path: Path, skills_library: Path, monkeypatch):
    """Point the module-level `config` singleton at temp dirs so this test
    never touches a real skills library, real plans dir, or the network."""
    monkeypatch.setattr(harness.config, "skills_library_path", skills_library)
    monkeypatch.setattr(harness.config, "plans_dir", tmp_path / "plans")
    monkeypatch.setattr(harness.config, "api_key", "")  # force local mode
    # Force the pre-Postgres JSON-file fallback regardless of whatever
    # DATABASE_URL happens to be set in the ambient environment this test
    # runs in — this file asserts on the on-disk investigation_steps JSON
    # shape specifically (see Part B's own test_harness_db_fallback.py for
    # the DB-backed-vs-JSON-fallback behavior itself).
    monkeypatch.setattr(harness.config, "database_url", "")
    return harness.config


@pytest.fixture
def canned_pipeline(monkeypatch):
    """Replace the real 4-stage pipeline with a deterministic output, so this
    test exercises harness.py's integration wiring, not the pipeline's own
    (separately tested) internals."""

    async def fake_run_pipeline(classifier_input, provider, on_progress=None):
        return ClassifierOutput(
            steps=[
                {
                    "skill_slug": "web-app-recon-basics",
                    "skill_category": "web-application-security",  # SUBDOMAIN_TO_CATEGORY key -> "web-app"
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                    "rationale": "Evidence indicates external reconnaissance activity.",
                    "evidence_focus": "Web server request logs",
                    "step_order": 1,
                    "confidence": 0.87,
                    "evidence_gaps": [],
                }
            ],
            evidence_gaps=["No WAF logs available to confirm scan origin"],
            confidence=0.87,
        )

    monkeypatch.setattr(harness, "run_pipeline", fake_run_pipeline)
    # build_provider_from_env would otherwise require ANTHROPIC_API_KEY / real
    # provider construction — stub it since fake_run_pipeline never calls
    # provider.complete() anyway.
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())


def test_generate_local_plan_end_to_end(isolated_config, canned_pipeline):
    evidence_text = "Unusual burst of GET requests against /admin from a single external IP."

    plan = harness.generate_local_plan(evidence_text)

    assert plan is not None, "generate_local_plan() returned None — pipeline wiring broke"
    assert plan.status == "approved"
    assert plan.evidence_text == evidence_text
    assert plan.confidence == pytest.approx(0.87)
    # Live-caught: domain used to be evidence_text[:50], so pasting a CloudTrail JSON
    # blob produced a table title like 'Investigation Steps — {"Records": [{ ...'.
    # It must instead reflect the investigation's actual skill category.
    assert plan.domain == "web-app"
    assert "No WAF logs available to confirm scan origin" in plan.evidence_gaps

    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.skill_slug == "web-app-recon-basics"
    assert step.skill_category == "web-app"  # SUBDOMAIN_TO_CATEGORY mapping still applied
    assert step.technique_id == "T1595"
    assert step.skill_document == "# Web App Recon Basics\n\nDo recon things.\n"
    assert step.status == "pending"

    # (a) on-disk investigation_steps JSON shape is unchanged from the
    # pre-Phase-1 contract (harness.py:483-520 in the original numbering).
    plan_file = isolated_config.plans_dir / f"{plan.id}.json"
    assert plan_file.exists()
    on_disk = json.loads(plan_file.read_text())

    assert set(on_disk.keys()) == {
        "id", "domain", "evidence_text", "status", "created_at",
        "cve_references", "evidence_gaps", "confidence", "investigation_steps",
    }
    assert len(on_disk["investigation_steps"]) == 1
    step_json = on_disk["investigation_steps"][0]
    assert set(step_json.keys()) == {
        "id", "skill_slug", "skill_category", "skill_document", "technique_id",
        "technique_name", "rationale", "evidence_focus", "step_order", "status",
    }
    assert step_json["skill_slug"] == "web-app-recon-basics"

    # (b) PlatformClient._parse_plan can still round-trip the written file.
    reloaded = harness.PlatformClient().load_local_plan(plan_file)
    assert reloaded.id == plan.id
    assert len(reloaded.steps) == 1
    assert reloaded.steps[0].skill_slug == "web-app-recon-basics"
    assert reloaded.steps[0].technique_id == "T1595"
    assert reloaded.confidence == pytest.approx(0.87)


def test_generate_local_plan_no_skills_library_returns_none(tmp_path, monkeypatch):
    """Sanity check the pre-existing missing-library guard still fires before
    any Phase 1 code runs (harness.py:360-363 in the original numbering)."""
    monkeypatch.setattr(harness.config, "skills_library_path", tmp_path / "does-not-exist")
    assert harness.generate_local_plan("some evidence") is None


def test_generate_local_plan_domain_is_majority_skill_category(isolated_config, monkeypatch):
    """plan.domain must reflect what the classifier actually selected (majority
    category among steps), not the raw pasted evidence text — see the docstring
    at harness.py's Plan construction for the live-caught garbled-title bug."""

    async def fake_run_pipeline(classifier_input, provider, on_progress=None):
        return ClassifierOutput(
            steps=[
                {
                    "skill_slug": "web-app-recon-basics",
                    "skill_category": "cloud-security",  # -> "cloud"
                    "technique_id": "T1578.001",
                    "technique_name": "Create Cloud Instance",
                    "rationale": "r",
                    "evidence_focus": "e",
                    "step_order": 1,
                    "confidence": 0.8,
                    "evidence_gaps": [],
                },
                {
                    "skill_slug": "web-app-recon-basics",
                    "skill_category": "cloud-security",  # -> "cloud"
                    "technique_id": "T1578.001",
                    "technique_name": "Create Cloud Instance",
                    "rationale": "r",
                    "evidence_focus": "e",
                    "step_order": 2,
                    "confidence": 0.8,
                    "evidence_gaps": [],
                },
                {
                    "skill_slug": "web-app-recon-basics",
                    "skill_category": "web-application-security",  # -> "web-app"
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                    "rationale": "r",
                    "evidence_focus": "e",
                    "step_order": 3,
                    "confidence": 0.8,
                    "evidence_gaps": [],
                },
            ],
            evidence_gaps=[],
            confidence=0.8,
        )

    monkeypatch.setattr(harness, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())

    plan = harness.generate_local_plan('{"Records": [{"eventName": "StartInstances"}]}')

    assert plan is not None
    assert plan.domain == "cloud"  # 2 of 3 steps are cloud, 1 is web-app


def test_zero_steps_warning_does_not_swallow_the_diagnostic_marker(isolated_config, monkeypatch):
    """Live-caught: console.print() is Rich, which treats bare [...] as markup.
    The zero-steps warning's literal '[casky_pipeline:pipeline]' marker name was
    unescaped, so Rich silently swallowed it as an unrecognized style tag — the
    user saw "check the '' warnings above" with the marker name just gone. Must
    render literally now."""
    from rich.console import Console
    import io

    async def fake_run_pipeline(classifier_input, provider, on_progress=None):
        return ClassifierOutput(steps=[], evidence_gaps=["some gap"], confidence=0.0)

    monkeypatch.setattr(harness, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(harness, "build_provider_from_env", lambda: object())

    buf = io.StringIO()
    monkeypatch.setattr(harness, "console", Console(file=buf, width=200, force_terminal=False))

    harness.generate_local_plan("some evidence with no clear technique")

    rendered = buf.getvalue()
    assert "[casky_pipeline:pipeline]" in rendered
    assert "check the '' warnings" not in rendered  # the old, silently-swallowed shape


# ── _extract_commands_from_skill_doc regression tests ────────────────────────
#
# Three real bugs, all live-caught against actual shipped SKILL.md files across
# two separate investigation runs. See harness.py's docstring for the full story
# of each; summarized in the test names below.

def test_extract_commands_reads_inside_fence_not_the_delimiter():
    doc = (
        "## Examples\n\n"
        "```python\n"
        "python agent.py --action full_investigation\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == ["python agent.py --action full_investigation"]
    # The old bug: the fence's own language tag leaking through as a command.
    assert "python" not in commands


def test_extract_commands_joins_backslash_continuations():
    doc = (
        "## Examples\n\n"
        "```bash\n"
        "python agent.py \\\n"
        "    --action full_investigation \\\n"
        "    --database cloud_forensics\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == ["python agent.py --action full_investigation --database cloud_forensics"]


def test_extract_commands_joins_open_quoted_string_across_lines_without_backslash():
    # Live-caught: `conducting-cloud-incident-response`'s real
    # `--policy-document '{ ... }'` argument spans multiple lines via an open,
    # unterminated single-quoted string — no trailing '\' on any of those lines.
    # Without quote-parity tracking, each line became its own broken pseudo-command
    # instead of one runnable one.
    doc = (
        "## Workflow\n\n"
        "```bash\n"
        "aws iam put-role-policy --role-name compromised-role \\\n"
        "  --policy-name RevokeOlderSessions --policy-document '{\n"
        '    "Version":"2012-10-17",\n'
        '    "Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]\n'
        "  }'\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == [
        "aws iam put-role-policy --role-name compromised-role --policy-name RevokeOlderSessions "
        '--policy-document \'{ "Version":"2012-10-17", "Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}] }\''
    ]


def test_extract_commands_skips_comment_lines_inside_fence():
    doc = (
        "## Examples\n\n"
        "```bash\n"
        "# this is a comment, not a command\n"
        "nmap -sV target\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == ["nmap -sV target"]


def test_extract_commands_dollar_prefixed_line_outside_fence():
    doc = "## Usage\n\n$ curl -s http://target/\n"
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == ["curl -s http://target/"]


def test_extract_commands_skips_non_command_fence_language_regardless_of_heading():
    # sql (and json/yaml/...) is a query/data language, not a literal shell command —
    # excluded even under a heading that's otherwise scanned, like ## Instructions.
    doc = "## Instructions\n\n```sql\nSELECT * FROM cloudtrail_logs;\n```\n"
    assert harness._extract_commands_from_skill_doc(doc) == []


def test_extract_commands_caps_at_five():
    fence_lines = "\n".join(f"cmd{i}" for i in range(10))
    doc = f"## Commands\n\n```bash\n{fence_lines}\n```\n"
    commands = harness._extract_commands_from_skill_doc(doc)
    assert len(commands) == 5
    assert commands == ["cmd0", "cmd1", "cmd2", "cmd3", "cmd4"]


def test_extract_commands_scans_headings_outside_the_old_fixed_allowlist():
    # Live-caught: real corpus skills (ScoutSuite, Security Hub, S3-audit,
    # incident-response) put their actual commands under headings like "## Workflow"
    # or "## Installation and Setup" — never matched by a fixed allow-list of
    # ## Commands/Usage/Examples/Instructions. Any heading not on the known
    # non-actionable block-list must be scanned.
    doc = "## Workflow\n\n```bash\nscout --version\n```\n"
    assert harness._extract_commands_from_skill_doc(doc) == ["scout --version"]


def test_extract_commands_skips_known_non_actionable_headings():
    doc = "## Prerequisites\n\n```bash\npip install scoutsuite\n```\n"
    assert harness._extract_commands_from_skill_doc(doc) == []


def test_extract_commands_skips_untagged_fence_used_as_prose_formatting():
    # Live-caught: `conducting-cloud-incident-response` uses bare ``` fences purely
    # as a checklist/prose formatting device ("CloudTrail suspicious events to
    # investigate: - ConsoleLogin from unexpected geolocation...") right alongside
    # properly ```bash-tagged real commands elsewhere in the same doc. Every real
    # command observed in this corpus was language-tagged, so an untagged fence is
    # treated as prose, not a command.
    doc = (
        "## Workflow\n\n"
        "```\n"
        "CloudTrail suspicious events to investigate:\n"
        "- ConsoleLogin from unexpected geolocation\n"
        "```\n\n"
        "```bash\n"
        "aws iam update-access-key --user-name compromised-user --status Inactive\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == ["aws iam update-access-key --user-name compromised-user --status Inactive"]


# ── _looks_like_python_source_line / whole-fence class-def skip ─────────────
#
# Live-caught: `detecting-network-scanning-with-ids-signatures` embeds a full
# illustrative Python script (module docstring, imports, a ScanDetector class)
# inside a single ```python fence with no bare command invocation anywhere. Every
# line of it — import json, a bare docstring line, for flow in data.flows:, dict
# entries like 'source_ip': '', stray closing brackets, bare `continue` — was
# getting grabbed as its own bogus "command".

@pytest.mark.parametrize("piece", [
    "import json",
    "from collections import defaultdict",
    "def process_eve_json(self, filepath: str):",
    "class ScanDetector:",
    "async def run():",
    "@dataclass",
    '"""Analyze IDS alerts for network scanning activity."""',
    "print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR)",
    "return scan_events",
    "data, _ = netflow.parse_packet(raw_bytes, templates={})",
    "ts = datetime.fromisoformat(event['timestamp'])",
    "for flow in data.flows:",
    "'source_ip': '',",
    '"target_ips": set(),',
])
def test_looks_like_python_source_line_true_cases(piece):
    assert harness._looks_like_python_source_line(piece) is True


@pytest.mark.parametrize("piece", [
    "aws s3 ls --profile default",
    "export AWS_ACCESS_KEY_ID=<your-key>",
    "region=$(aws s3api get-bucket-location --bucket \"$bucket\" --query 'LocationConstraint')",
    "for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name'); do",  # bash for-loop, no ':'
    "nmap -sV target",
    "python scripts/agent.py --flow-file captured_flows.json",
])
def test_looks_like_python_source_line_false_cases_real_shell_commands(piece):
    """Regression guard: these are all real, live-verified shell command lines from
    the actual skill corpus. In particular, region=$(...) with NO space before '='
    was a live-caught regression — the assignment-detection regex initially caught
    it too, silently dropping a working line out of the S3-audit skill's for-loop."""
    assert harness._looks_like_python_source_line(piece) is False


def test_extract_commands_skips_whole_fence_containing_a_class_definition():
    # A trimmed reproduction of the real ids-signatures skill's shape: module
    # docstring, imports, a class with a method — no bare invocation line at all.
    doc = (
        "## Workflow\n\n"
        "```python\n"
        "#!/usr/bin/env python3\n"
        '"""Analyze IDS alerts for network scanning activity."""\n'
        "\n"
        "import json\n"
        "from collections import defaultdict\n"
        "\n"
        "\n"
        "class ScanDetector:\n"
        "    def __init__(self):\n"
        "        self.scan_events = defaultdict(lambda: {\n"
        "            'source_ip': '',\n"
        "            'target_ports': set(),\n"
        "        })\n"
        "\n"
        "    def process(self, filepath):\n"
        "        with open(filepath) as f:\n"
        "            for line in f:\n"
        "                event = json.loads(line)\n"
        "                if event.get('event_type') != 'alert':\n"
        "                    continue\n"
        "```\n"
    )
    assert harness._extract_commands_from_skill_doc(doc) == []


def test_extract_commands_still_extracts_real_command_alongside_illustrative_snippet():
    # The netflow skill's real shape: a real ```bash command in one fence, then a
    # SEPARATE small illustrative ```python snippet (no class/def) later in the same
    # section — the snippet has no class/def so isn't whole-fence-skipped, but every
    # one of its lines should still be filtered individually.
    doc = (
        "## Workflow\n\n"
        "```bash\n"
        "python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json\n"
        "```\n\n"
        "```python\n"
        "import netflow\n"
        "data, _ = netflow.parse_packet(raw_bytes, templates={})\n"
        "for flow in data.flows:\n"
        "    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)\n"
        "```\n"
    )
    commands = harness._extract_commands_from_skill_doc(doc)
    assert commands == [
        "python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json"
    ]


# ── _load_evidence_from_file (-i/--input-file) ───────────────────────────────

def test_load_evidence_from_file_reads_and_strips_contents(tmp_path):
    f = tmp_path / "evidence.json"
    f.write_text('  {"eventName": "StartInstances"}  \n')
    assert harness._load_evidence_from_file(f) == '{"eventName": "StartInstances"}'


def test_load_evidence_from_file_missing_path_raises_file_not_found(tmp_path):
    """Live-caught: a user passed a host path (~/Downloads/...) that doesn't exist
    inside the container's isolated filesystem. The error must explain *why*, not
    just *that* — point at the host/container filesystem split and the fix."""
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(FileNotFoundError, match="input file not found") as exc_info:
        harness._load_evidence_from_file(missing)
    message = str(exc_info.value)
    assert "isolated filesystem" in message
    assert "evidence/" in message


def test_load_evidence_from_file_empty_file_raises_value_error(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("   \n  ")
    with pytest.raises(ValueError, match="input file is empty"):
        harness._load_evidence_from_file(f)


def test_load_evidence_from_file_oversized_file_rejected_without_reading_it(tmp_path, monkeypatch):
    """Live-caught: a user passed an 82MB pcap-derived JSON dump via -i. evidence_text
    is embedded verbatim into every LLM prompt with no other size guard anywhere —
    this would blow past any provider's context window by ~2 orders of magnitude.
    Must reject by stat() size BEFORE reading the file, not after loading it all."""
    f = tmp_path / "huge.json"
    f.write_text("x" * 100)  # small on disk — we fake stat() to claim it's huge

    real_stat = Path.stat

    def fake_stat(self, *a, **kw):
        if self == f:
            class FakeStatResult:
                st_size = harness.MAX_EVIDENCE_CHARS + 1
            return FakeStatResult()
        return real_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", fake_stat)

    read_calls = []
    real_read_text = Path.read_text
    monkeypatch.setattr(
        Path, "read_text",
        lambda self, *a, **kw: (read_calls.append(self), real_read_text(self, *a, **kw))[1],
    )

    with pytest.raises(ValueError, match="over the .* limit"):
        harness._load_evidence_from_file(f)

    assert read_calls == []  # never read the file contents at all


def test_generate_local_plan_rejects_oversized_evidence_text(isolated_config):
    """Defense-in-depth: this guard is independent of _load_evidence_from_file's —
    it also covers the interactive paste path and any future direct caller."""
    plan = harness.generate_local_plan("x" * (harness.MAX_EVIDENCE_CHARS + 1))
    assert plan is None


def test_main_dash_i_reaches_generate_local_plan_and_skips_the_paste_menu(tmp_path, monkeypatch):
    """Proves the -i/--input-file argparse wiring in main() actually works end to
    end: evidence comes from the file, generate_local_plan() is called with its
    contents, and the interactive Plan Source menu (ask_plan_source / the paste
    prompt) is never reached at all."""
    evidence_file = tmp_path / "cloudtrail.json"
    evidence_file.write_text('{"eventName": "StopInstances"}')

    monkeypatch.setattr(sys, "argv", ["casky-harness", "-i", str(evidence_file)])

    captured_evidence = {}

    def fake_generate_local_plan(evidence_text):
        captured_evidence["value"] = evidence_text
        return harness.Plan(id="p1", domain="cloud", evidence_text=evidence_text, status="approved", steps=[])

    monkeypatch.setattr(harness, "generate_local_plan", fake_generate_local_plan)

    def fail_if_called(*a, **kw):
        raise AssertionError("ask_plan_source() should not be called when -i is given")

    monkeypatch.setattr(harness.HarnessUI, "ask_plan_source", fail_if_called)

    # plan.steps == [] -> main() prints "no investigation steps" and exits(0) cleanly.
    with pytest.raises(SystemExit) as exc_info:
        harness.main()
    assert exc_info.value.code == 0

    assert captured_evidence["value"] == '{"eventName": "StopInstances"}'


def test_show_step_select_falls_back_to_all_steps_on_eof(monkeypatch):
    """Live-caught: piping/redirecting stdin closed (a real scenario for -i's
    scripted/headless use case) made Prompt.ask() raise EOFError, crashing with a
    raw Python traceback instead of a sane default."""
    step = harness.Step(
        id="s1", skill_slug="web-app-recon-basics", skill_category="web-app",
        skill_document="", technique_id="T1595", technique_name="Active Scanning",
        rationale="", evidence_focus="", step_order=1,
    )
    plan = harness.Plan(id="p1", domain="web-app", evidence_text="e", status="approved", steps=[step])

    def fake_ask(*a, **kw):
        raise EOFError

    monkeypatch.setattr(harness.Prompt, "ask", fake_ask)

    selected = harness.HarnessUI().show_step_select(plan)

    assert selected == [step]
