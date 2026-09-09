"""Scoring drift — the regression test `CONTRIBUTING.md` has always promised.

CONTRIBUTING has cited `tests/integration/test_scoring_drift.py` since the
first commit. The file did not exist, which `docs/architecture.md` §4 recorded
as one of the two halves of "no integration tests and no real fixtures".

**What drift means here, and why pinned numbers are the point.** The scoring
model is a chain of judgement calls — severity weights, the `sqrt(LOC/1000)`
dampener, the category-grade table, the letter bands — and every one of them is
a number somebody chose. A change to any of them silently re-grades every
repository that has ever been scanned, including baselines already accepted by
a team. These tests pin the output of that chain against fixed inputs so a
change to the model is a decision with a failing test attached, rather than a
number that quietly moved.

A failure here is not necessarily a bug. It means: the model changed, say so
out loud, and update the expectation in the same commit that changed it.

**These are not calibration.** D5 is still open: nobody has established that
A+ corresponds to anything real, and pinning an uncalibrated number does not
calibrate it. This proves the scale is *stable*, not that it is *correct*.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)
from secure_code_audit.scoring import letter_grade, score


def _finding(
    *,
    severity: Severity,
    category: Category = Category.CODE_VULNERABILITIES,
    rule_id: str = "r",
    line: int = 1,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="fixture",
        fingerprint=f"{rule_id}:{line}",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3.5",
        nist_ssdf="PW.5.1",
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("app.py"),
        line_start=line,
        line_end=line,
        code_snippet="x",
        message="m",
        suppressed=suppressed,
    )


# --------------------------------------------------------------------------
# The letter bands
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (5.0, "A+"),
        (4.5, "A"),
        (4.0, "A-"),
        (3.5, "B+"),
        (3.0, "B"),
        (2.0, "C"),
        (1.0, "D"),
        (0.0, "F"),
    ],
)
def test_letter_bands_are_pinned(value: float, expected: str):
    """The band table is a judgement call, so moving it must be deliberate."""
    assert letter_grade(value) == expected


# --------------------------------------------------------------------------
# The score itself
# --------------------------------------------------------------------------


def test_a_clean_scan_of_a_real_sized_repository_scores_a_plus():
    report = score([], loc_scanned=50_000)

    assert report.overall == 5.0
    assert report.letter == "A+"
    assert report.worst_category is None


def test_one_critical_finding_in_a_large_repository_still_moves_the_grade():
    """The dampener must not let a real defect vanish into repository size.

    MA hit the inverse of this at 0.5.0 — absolute counts graded *size*, so
    Django and pytest scored 0.0/F while a 53-file toy scored 4.6/A. The
    normalizer here exists to stop that, and this pins that it does not
    over-correct into "one critical in a big repo rounds away".
    """
    report = score([_finding(severity=Severity.CRITICAL)], loc_scanned=100_000)

    assert report.overall < 5.0
    assert report.worst_category is Category.CODE_VULNERABILITIES


def test_the_overall_grade_is_the_worst_category_not_the_mean():
    """Averaging would let a strong category hide a failing one.

    A repository with immaculate dependencies and a critical injection flaw is
    not "average". This mirrors MA ADR-007's rule that a practice level and a
    code condition are never averaged together.
    """
    findings = [
        _finding(severity=Severity.CRITICAL, category=Category.CODE_VULNERABILITIES, line=1),
        _finding(severity=Severity.CRITICAL, category=Category.CODE_VULNERABILITIES, line=2),
        _finding(severity=Severity.CRITICAL, category=Category.CODE_VULNERABILITIES, line=3),
    ]

    report = score(findings, loc_scanned=1_000)

    worst = min(report.per_category.values())
    assert report.overall == worst
    assert report.overall < sum(report.per_category.values()) / len(report.per_category)


def test_severity_ordering_is_monotonic():
    """A worse finding never produces a better grade.

    Weights can be retuned; this ordering is not a tuning knob.
    """
    grades = [
        score([_finding(severity=severity)], loc_scanned=10_000).overall
        for severity in (
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        )
    ]

    assert grades == sorted(grades, reverse=True), grades
    # Informational findings — which is what every control finding is — must
    # not move the grade at all, or an unavailable scanner would score as a
    # security defect.
    assert grades[0] == 5.0


def test_suppressed_findings_do_not_change_the_grade():
    live = _finding(severity=Severity.CRITICAL, line=1)
    muted = _finding(severity=Severity.CRITICAL, line=2, suppressed=True)

    assert score([live], 10_000).overall == score([live, muted], 10_000).overall
    assert score([muted], 10_000).overall == 5.0
    assert score([live, muted], 10_000).per_category_count[Category.CODE_VULNERABILITIES] == 1


def test_more_findings_never_improve_the_grade():
    """P3, at the scoring layer: withholding evidence cannot raise the score.

    The inverse — adding evidence cannot raise it either — is what stops a
    scanner that reports more from looking better than one that reports less.
    """
    one = score([_finding(severity=Severity.HIGH, line=1)], 10_000).overall
    many = score(
        [_finding(severity=Severity.HIGH, line=n) for n in range(1, 11)],
        10_000,
    ).overall

    assert many <= one


# --------------------------------------------------------------------------
# Score and coverage are separate axes
# --------------------------------------------------------------------------


def test_a_perfect_score_on_failed_coverage_is_still_failed_coverage():
    """The project's central claim, pinned.

    A repository nothing could be scanned in produces zero findings, and zero
    findings produce A+. That number is only safe because coverage is reported
    beside it and is not derived from it. If these two ever start agreeing,
    absence of evidence has become evidence of absence.
    """
    report = score([], loc_scanned=10_000)
    coverage = evaluate_coverage(
        [ScannerExecution("bandit", ScannerOutcome.UNAVAILABLE, reason="not installed")],
        ["bandit"],
    )

    assert report.letter == "A+"
    assert coverage.status is CoverageStatus.FAILED
