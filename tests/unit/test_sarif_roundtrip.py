"""SARIF emit → ingest roundtrip — the schema we promise to consumers."""

import json
from pathlib import Path

from secure_code_audit import sarif
from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from secure_code_audit.scanner_status import (
    CoverageReport,
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)


def _f(rule_id="bandit.B608", severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=Finding.make_fingerprint(
            canonical_cwe="CWE-89",
            rule_id=rule_id,
            file_path=Path("a.py"),
            code_snippet="select * from x",
        ),
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3.5",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("a.py"),
        line_start=5,
        line_end=5,
        code_snippet="select * from x",
        message="possible SQLi",
        cwe_top25=True,
    )


def test_emit_contains_required_sarif_fields():
    doc = sarif.emit([_f()])
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "secure-code-agent"
    assert any(r["id"] == "bandit.B608" for r in driver["rules"])
    assert run["results"][0]["ruleId"] == "bandit.B608"
    assert run["results"][0]["fingerprints"]["secure-code-agent/v1"]
    assert "invocations" not in run


def test_emit_severity_mapping():
    doc = sarif.emit([_f(severity=Severity.HIGH), _f(rule_id="x", severity=Severity.LOW)])
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert "error" in levels
    assert "note" in levels


def test_emit_marks_failed_scanner_coverage_as_unsuccessful_execution():
    coverage = CoverageReport(
        status=CoverageStatus.FAILED,
        required=("bandit",),
        executions=(
            ScannerExecution(
                "bandit",
                ScannerOutcome.UNAVAILABLE,
                scope="mode=requirements; inputs=requirements-audit.txt",
            ),
        ),
        failures=("required scanner 'bandit' did not complete: unavailable",),
    )

    invocation = sarif.emit([], coverage)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["coverageStatus"] == "failed"
    assert invocation["properties"]["scannerExecutions"][0]["scope"].startswith("mode=")
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"


def test_roundtrip_via_temp_file(tmp_path):
    out = tmp_path / "out.sarif"
    findings = [_f()]
    sarif.write(findings, out)
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"

    re_ingested = sarif.ingest(out)
    assert re_ingested
    assert re_ingested[0].canonical_cwe == "CWE-89"


def test_missing_import_reports_failed_coverage_instead_of_silence(tmp_path):
    findings, executions = sarif.ingest_with_coverage(tmp_path / "missing.sarif")

    assert [f.rule_id for f in findings] == ["external_sarif.tool_error"]
    assert [e.outcome for e in executions] == [ScannerOutcome.FAILED]
    assert "could not read" in executions[0].reason


def test_malformed_import_reports_failed_coverage_instead_of_silence(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("{not json", encoding="utf-8")

    findings, executions = sarif.ingest_with_coverage(p)

    assert [f.rule_id for f in findings] == ["external_sarif.tool_error"]
    assert [e.outcome for e in executions] == [ScannerOutcome.FAILED]
    assert "not valid JSON" in executions[0].reason


def test_empty_import_cannot_pass_as_coverage(tmp_path):
    p = tmp_path / "empty.sarif"
    p.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")

    _, executions = sarif.ingest_with_coverage(p)

    assert executions[0].outcome is ScannerOutcome.FAILED
    assert "no runs" in executions[0].reason


def test_import_satisfies_required_scanner_coverage(tmp_path):
    p = tmp_path / "trivy.sarif"
    p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Trivy", "version": "0.60.0", "rules": []}},
                        "results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    _, executions = sarif.ingest_with_coverage(p)
    report = evaluate_coverage(executions, ["trivy"])

    assert executions[0].name == "trivy"
    assert executions[0].version == "0.60.0"
    assert executions[0].scope == "sarif-import:trivy.sarif"
    assert report.status is CoverageStatus.COMPLETE
    assert report.failures == ()


def test_import_honors_the_exporting_tools_own_failure(tmp_path):
    p = tmp_path / "gitleaks.sarif"
    p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "gitleaks", "rules": []}},
                        "invocations": [{"executionSuccessful": False}],
                        "results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    _, executions = sarif.ingest_with_coverage(p)

    assert executions[0].outcome is ScannerOutcome.FAILED
    assert evaluate_coverage(executions, ["gitleaks"]).status is CoverageStatus.FAILED


def test_hyphenated_driver_names_normalize_to_scanner_ids(tmp_path):
    p = tmp_path / "osv.sarif"
    p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "OSV-Scanner", "rules": []}}, "results": []}],
            }
        ),
        encoding="utf-8",
    )

    _, executions = sarif.ingest_with_coverage(p)

    assert executions[0].name == "osv_scanner"


def test_explicit_name_overrides_an_unrecognized_driver(tmp_path):
    p = tmp_path / "vendor.sarif"
    p.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {"tool": {"driver": {"name": "Vendor SAST 9000", "rules": []}}, "results": []}
                ],
            }
        ),
        encoding="utf-8",
    )

    _, executions = sarif.ingest_with_coverage(p, override_scanner="semgrep")

    assert executions[0].name == "semgrep"
