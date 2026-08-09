from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    classify_execution,
    evaluate_coverage,
)
from secure_code_audit.scoring import evaluate_gates, score


def _control(rule_id: str, message: str = "control") -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner=rule_id.split(".", 1)[0],
        fingerprint=rule_id,
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.POLICY_DOCS,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        file_path=Path("."),
        line_start=0,
        line_end=None,
        code_snippet=None,
        message=message,
    )


def test_required_unavailable_scanner_fails_coverage_and_gate():
    execution = classify_execution("bandit", [_control("bandit.tool_unavailable")])
    coverage = evaluate_coverage([execution], ["bandit"])
    report = score([], 100)
    gate = evaluate_gates([], report, {"require_scanners": ["bandit"]}, coverage)

    assert coverage.status is CoverageStatus.FAILED
    assert gate.passed is False
    assert "require_scanners" in gate.tripped


def test_optional_unavailable_scanner_is_partial_but_does_not_fail_gate():
    execution = ScannerExecution("trivy", ScannerOutcome.UNAVAILABLE)
    coverage = evaluate_coverage([execution], [])
    gate = evaluate_gates([], score([], 100), {}, coverage)

    assert coverage.status is CoverageStatus.PARTIAL
    assert gate.passed is True


def test_required_not_applicable_scanner_fails_coverage():
    execution = classify_execution("pip_audit", [_control("pip_audit.no_dependency_input")])
    coverage = evaluate_coverage([execution], ["pip_audit"])

    assert execution.outcome is ScannerOutcome.NOT_APPLICABLE
    assert coverage.status is CoverageStatus.FAILED


def test_required_scanner_not_selected_fails_coverage():
    coverage = evaluate_coverage([], ["bandit"])

    assert coverage.status is CoverageStatus.FAILED
    assert "was not selected" in coverage.failures[0]
