"""Scoring + gate evaluation."""

from dataclasses import replace
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import (
    active_gates,
    category_subtotal,
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


# ---------------------------------------------------------------------------
# Repeats of one rule saturate
# ---------------------------------------------------------------------------


def _rule_finding(rule_id: str, line: int = 1, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=f"{rule_id}:{line}",
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path(f"src/m{line}.py"),
        line_start=line,
        line_end=line,
        code_snippet=None,
        message="m",
    )


def test_one_finding_is_unchanged_by_saturation():
    """mean * sqrt(1) is the weight itself. The common case must not move."""
    one = [_rule_finding("B608")]

    assert category_subtotal(one, Category.CODE_VULNERABILITIES) == finding_score(one[0])


def test_repeats_of_one_rule_saturate_rather_than_growing_linearly():
    """Bandit found `mark_safe` 56 times in the framework that defines it.
    That is one fact observed 56 times, not 56 independent defects."""
    unit = finding_score(_rule_finding("B703"))
    many = [_rule_finding("B703", line=n) for n in range(100)]

    subtotal = category_subtotal(many, Category.CODE_VULNERABILITIES)

    # Rank discount: sum of 1/sqrt(k) for k = 1..100, about 2*sqrt(n).
    assert subtotal == pytest.approx(unit * 18.59, rel=0.01)
    assert subtotal < unit * 100


def test_an_extra_finding_can_never_improve_the_score():
    """P3: withholding evidence cannot improve the reported grade.

    The first attempt at saturation broke exactly this. Scoring a rule as
    `mean(weight) * sqrt(n)` made one CRITICAL plus nine LOW hits score 6.88
    against 15.0 for the CRITICAL alone — so deleting nine real findings
    would have raised the grade, and a scanner that reported less would have
    looked better than one that reported more.
    """
    worst = _rule_finding("B1", line=0, severity=Severity.CRITICAL)
    running = [worst]
    previous = category_subtotal(running, Category.CODE_VULNERABILITIES)

    for n in range(1, 25):
        running.append(_rule_finding("B1", line=n, severity=Severity.LOW))
        current = category_subtotal(running, Category.CODE_VULNERABILITIES)
        assert current >= previous, f"adding finding {n} lowered the subtotal"
        previous = current


def test_the_worst_hit_of_a_rule_always_counts_in_full():
    """However many low-severity repeats surround it."""
    critical_only = [_rule_finding("B1", line=0, severity=Severity.CRITICAL)]
    buried = critical_only + [
        _rule_finding("B1", line=n, severity=Severity.LOW) for n in range(1, 30)
    ]

    assert category_subtotal(buried, Category.CODE_VULNERABILITIES) >= category_subtotal(
        critical_only, Category.CODE_VULNERABILITIES
    )


def test_distinct_rules_still_add_in_full():
    """Saturation is per rule. Independent evidence is still independent —
    ten different weaknesses are worse than one weakness ten times."""
    ten_of_one = [_rule_finding("B608", line=n) for n in range(10)]
    ten_distinct = [_rule_finding(f"R{n}", line=n) for n in range(10)]

    assert category_subtotal(ten_distinct, Category.CODE_VULNERABILITIES) > category_subtotal(
        ten_of_one, Category.CODE_VULNERABILITIES
    )
    assert category_subtotal(ten_distinct, Category.CODE_VULNERABILITIES) == pytest.approx(
        finding_score(ten_distinct[0]) * 10
    )


def test_a_mixed_rule_sits_between_its_worst_hit_and_the_naive_sum():
    """A rule firing once as CRITICAL and nine times as LOW is worse than the
    CRITICAL alone and nowhere near ten CRITICALs."""
    mixed = [_rule_finding("B1", line=0, severity=Severity.CRITICAL)] + [
        _rule_finding("B1", line=n, severity=Severity.LOW) for n in range(1, 10)
    ]

    subtotal = category_subtotal(mixed, Category.CODE_VULNERABILITIES)
    worst = finding_score(_rule_finding("B1", severity=Severity.CRITICAL))

    assert subtotal > worst
    assert subtotal < worst * 10


def test_a_suppressed_repeat_does_not_inflate_the_count():
    """Suppressed findings are excluded before the count, not after, or
    accepting one would still raise the sqrt term."""
    live = [_rule_finding("B608", line=n) for n in range(4)]
    with_suppressed = live + [
        replace(_rule_finding("B608", line=99), suppressed=True),
    ]

    assert category_subtotal(with_suppressed, Category.CODE_VULNERABILITIES) == pytest.approx(
        category_subtotal(live, Category.CODE_VULNERABILITIES)
    )
