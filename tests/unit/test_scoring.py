"""Scoring + gate evaluation."""

from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import (
    active_gates,
    evaluate_gates,
    finding_score,
    letter_grade,
    score,
)


def _f(
    severity,
    category,
    *,
    cwe_top25=False,
    suppressed=False,
    is_new=True,
    confidence=Confidence.HIGH,
):
    return Finding(
        rule_id="r",
        scanner="t",
        fingerprint="abc123",
        canonical_cwe="CWE-89" if cwe_top25 else "CWE-1234",
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=severity,
        confidence=confidence,
        file_path=Path("x.py"),
        line_start=1,
        line_end=None,
        code_snippet=None,
        message="m",
        suppressed=suppressed,
        is_new=is_new,
        cwe_top25=cwe_top25,
    )


def test_letter_grade_boundaries():
    assert letter_grade(5.0) == "A+"
    assert letter_grade(4.85) == "A+"
    assert letter_grade(4.84) == "A"
    assert letter_grade(4.0) == "A-"
    assert letter_grade(3.0) == "B"
    assert letter_grade(0.0) == "F"


def test_clean_repo_scores_aplus():
    r = score([], loc_scanned=10_000)
    assert r.overall == 5.0
    assert r.letter == "A+"
    assert r.worst_category is None


def test_one_high_sqli_drops_grade():
    findings = [_f(Severity.HIGH, Category.CODE_VULNERABILITIES, cwe_top25=True)]
    r = score(findings, loc_scanned=12_000)
    # Single HIGH SQLi (top25) on a 12k repo → high but not catastrophic
    assert 3.0 < r.overall < 4.5
    assert r.worst_category is Category.CODE_VULNERABILITIES


def test_suppressed_findings_dont_score():
    findings = [
        _f(Severity.CRITICAL, Category.SECRETS, suppressed=True),
        _f(Severity.LOW, Category.LOGGING_OBSERVABILITY, suppressed=False),
    ]
    r = score(findings, loc_scanned=10_000)
    # Suppressed CRITICAL ignored; LOW logging finding is the worst.
    assert r.worst_category is Category.LOGGING_OBSERVABILITY


def test_worst_category_drives_overall():
    findings = [
        _f(Severity.LOW, Category.LOGGING_OBSERVABILITY),
        _f(Severity.CRITICAL, Category.SECRETS),
    ]
    r = score(findings, loc_scanned=10_000)
    # SECRETS should be the worst.
    assert r.worst_category is Category.SECRETS
    assert r.per_category[Category.SECRETS] < r.per_category[Category.LOGGING_OBSERVABILITY]


def test_top25_bonus_applied():
    base = _f(Severity.HIGH, Category.CODE_VULNERABILITIES, cwe_top25=False)
    boosted = _f(Severity.HIGH, Category.CODE_VULNERABILITIES, cwe_top25=True)
    assert finding_score(boosted) > finding_score(base)


def test_gate_fail_on_severity():
    findings = [_f(Severity.HIGH, Category.SECRETS)]
    r = score(findings, loc_scanned=10_000)
    gate = evaluate_gates(findings, r, {"fail_on_severity": ["high"]})
    assert not gate.passed
    assert "fail_on_severity" in gate.tripped


def test_gate_pass_when_findings_below_threshold():
    findings = [_f(Severity.LOW, Category.LOGGING_OBSERVABILITY)]
    r = score(findings, loc_scanned=10_000)
    gate = evaluate_gates(findings, r, {"fail_on_severity": ["critical", "high"]})
    assert gate.passed


def test_gate_fail_on_new():
    findings = [_f(Severity.MEDIUM, Category.DEPENDENCIES, is_new=True)]
    r = score(findings, loc_scanned=10_000)
    gate = evaluate_gates(findings, r, {"fail_on_new": True})
    assert not gate.passed


def test_gate_max_unsuppressed():
    findings = [_f(Severity.HIGH, Category.SECRETS)] * 3
    r = score(findings, loc_scanned=10_000)
    gate = evaluate_gates(findings, r, {"max_unsuppressed": {"high": 2}})
    assert not gate.passed
    assert any("max_unsuppressed" in t for t in gate.tripped)


def test_gate_min_score():
    findings = [_f(Severity.CRITICAL, Category.SECRETS)] * 5
    r = score(findings, loc_scanned=5_000)
    gate = evaluate_gates(findings, r, {"min_score": 4.0})
    assert not gate.passed


def test_absent_gate_config_has_no_active_gates():
    assert active_gates({}) == ()


def test_gate_keys_that_cannot_trip_do_not_count_as_configured():
    # Each of these is present but inert: nothing matches an empty list, an
    # empty cap map caps nothing, and no score can fall below 0.
    inert = {
        "fail_on_severity": [],
        "fail_on_category": [],
        "fail_on_new": False,
        "min_score": 0,
        "require_scanners": [],
        "max_unsuppressed": {},
    }

    assert active_gates(inert) == ()


def test_a_single_real_gate_is_enough():
    assert active_gates({"min_score": 4.0}) == ("min_score",)
    assert active_gates({"fail_on_severity": ["high"]}) == ("fail_on_severity",)
    assert active_gates({"require_scanners": ["bandit"]}) == ("require_scanners",)


def test_active_gates_reports_every_configured_gate():
    assert active_gates(
        {"fail_on_new": True, "min_score": 4.0, "max_unsuppressed": {"critical": 0}}
    ) == ("fail_on_new", "min_score", "max_unsuppressed")
