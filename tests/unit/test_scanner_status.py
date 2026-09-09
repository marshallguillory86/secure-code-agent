from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
    worst_by_name,
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
    execution = ScannerExecution(
        "bandit", ScannerOutcome.UNAVAILABLE, reason="could not resolve bandit"
    )
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
    execution = ScannerExecution(
        "pip_audit", ScannerOutcome.NOT_APPLICABLE, reason="no dependency input"
    )
    coverage = evaluate_coverage([execution], ["pip_audit"])

    assert execution.outcome is ScannerOutcome.NOT_APPLICABLE
    assert coverage.status is CoverageStatus.FAILED


def test_required_scanner_not_selected_fails_coverage():
    coverage = evaluate_coverage([], ["bandit"])

    assert coverage.status is CoverageStatus.FAILED
    assert "was not selected" in coverage.failures[0]


def _execution(name: str, outcome: ScannerOutcome) -> ScannerExecution:
    return ScannerExecution(name=name, outcome=outcome)


def test_a_clean_import_cannot_mask_a_failed_local_run_of_the_same_scanner():
    coverage = evaluate_coverage(
        [
            _execution("trivy", ScannerOutcome.FAILED),
            _execution("trivy", ScannerOutcome.COMPLETED),
        ],
        ["trivy"],
    )

    assert coverage.status is CoverageStatus.FAILED
    assert "did not complete" in coverage.failures[0]


def test_duplicate_names_collapse_to_the_worst_outcome_in_either_order():
    for pair in (
        (ScannerOutcome.COMPLETED, ScannerOutcome.UNAVAILABLE),
        (ScannerOutcome.UNAVAILABLE, ScannerOutcome.COMPLETED),
    ):
        collapsed = worst_by_name([_execution("bandit", pair[0]), _execution("bandit", pair[1])])
        assert collapsed["bandit"].outcome is ScannerOutcome.UNAVAILABLE
