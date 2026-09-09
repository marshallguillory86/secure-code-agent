import json
from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.renderers import write_json, write_markdown, write_pr_comment
from secure_code_audit.scanner_status import (
    CoverageReport,
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
)
from secure_code_audit.scoring import GateResult, score


def _finding():
    return Finding(
        rule_id="B608",
        scanner="bandit",
        fingerprint="abc",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5",
        nist_ssdf="PW.5",
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=Path("app.py"),
        line_start=4,
        line_end=5,
        code_snippet="query = user_input",
        message="possible injection",
        short_desc="SQL injection",
        fix_hint="parameterize",
        is_new=True,
        cwe_top25=True,
    )


def _coverage():
    return CoverageReport(
        status=CoverageStatus.FAILED,
        required=("bandit", "pip_audit"),
        executions=(
            ScannerExecution(
                "bandit",
                ScannerOutcome.COMPLETED,
                ("/tools/bandit",),
                "bandit 1.9.4",
                1,
                scope="mode=requirements; inputs=requirements-audit.txt; extra_args=--no-deps",
            ),
        ),
        failures=("required scanner 'pip_audit' was not selected",),
    )


def test_all_report_formats_include_gate_coverage_and_provenance(tmp_path):
    finding = _finding()
    report = score([finding], 100)
    gate = GateResult(False, ("pip-audit missing",), ("require_scanners",))
    coverage = _coverage()
    markdown = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    comment = tmp_path / "comment.md"

    write_markdown([finding], report, gate, markdown, ["bandit"], [], coverage)
    write_json([finding], report, gate, json_path, coverage)
    write_pr_comment([finding], report, gate, comment, coverage)

    markdown_text = markdown.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "Coverage: **FAILED**" in markdown_text
    # Without a verdict no output may claim a grade — the conservative
    # default, so an unwired caller cannot accidentally present one.
    assert "Finding score (not a verified grade)" in markdown_text
    assert "bandit 1.9.4" in markdown_text
    assert "inputs=requirements-audit.txt" in markdown_text
    assert "CWE-89" in markdown_text
    assert payload["coverage"]["scanners"][0]["command"] == ["/tools/bandit"]
    assert payload["coverage"]["scanners"][0]["scope"].startswith("mode=requirements")
    assert payload["score"]["coverage_complete"] is False
    # `qualification` was a label; `verified_grade` is the claim itself, and
    # withholding it is what stops a thinner scan from earning a better letter.
    assert payload["score"]["verified_grade"] is None
    assert payload["score"]["evidence_status"] == "incomplete"
    assert "Scanner coverage: **FAILED**" in comment.read_text(encoding="utf-8")
    assert "not a verified grade" in comment.read_text(encoding="utf-8")


def test_empty_markdown_report_and_no_coverage(tmp_path):
    report = score([], 0)
    gate = GateResult(True, ())
    path = tmp_path / "empty.md"

    write_markdown([], report, gate, path, [], [], None)
    write_json([], report, gate, tmp_path / "empty.json")

    assert "_None._" in path.read_text(encoding="utf-8")
    assert json.loads((tmp_path / "empty.json").read_text(encoding="utf-8"))["coverage"] is None
