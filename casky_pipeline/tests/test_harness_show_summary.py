"""Tests for HarnessUI.show_summary()'s report-printing behavior.

Boundary contract: when a report_path exists, its content must be printed to
the terminal (Rich-rendered, not just the file path) — a real live-caught gap:
`casky harness --auto` printed "Consolidated report: <path>" and stopped,
leaving the analyst to `docker exec ... cat <path>` themselves to actually see
findings/remediation. When report_path is None or missing, nothing should be
printed beyond the path branch (no crash, no empty Panel).
"""
from __future__ import annotations

from types import SimpleNamespace

import harness


def _empty_harness() -> SimpleNamespace:
    return SimpleNamespace(results=[])


def test_report_content_is_printed_when_report_path_exists(tmp_path, capsys):
    report = tmp_path / "REPORT.md"
    report.write_text("# Investigation Report\n\n## Executive Summary\n\nSomething critical happened.\n")

    harness.HarnessUI().show_summary(_empty_harness(), report)

    out = capsys.readouterr().out
    assert "Consolidated report:" in out
    # Rich wraps long paths across lines at terminal width in captured output,
    # so check the filename rather than the full path as one unbroken string.
    assert "REPORT.md" in out
    # The actual report content, not just the path — this is the fix.
    assert "Executive Summary" in out
    assert "Something critical happened" in out


def test_no_report_panel_printed_when_report_path_is_none(capsys):
    harness.HarnessUI().show_summary(_empty_harness(), None)

    out = capsys.readouterr().out
    assert "Consolidated report:" not in out


def test_no_crash_when_report_path_does_not_exist(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.md"

    harness.HarnessUI().show_summary(_empty_harness(), missing)

    out = capsys.readouterr().out
    assert "Consolidated report:" not in out
