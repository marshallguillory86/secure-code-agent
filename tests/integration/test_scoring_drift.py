"""Scoring drift — the regression test `CONTRIBUTING.md` has always promised.

CONTRIBUTING has cited `tests/integration/test_scoring_drift.py` since the
first commit. The file did not exist, which `docs/architecture.md` §4 recorded
as one of the two halves of "no integration tests and no real fixtures".

**What drift means here, and why pinned numbers are the point.** The scoring
model is a chain of judgement calls — severity weights, the per-kLOC
normalizer, the grade slope, the letter bands — and every one of them is
a number somebody chose. A change to any of them silently re-grades every
repository that has ever been scanned, including baselines already accepted by
a team. These tests pin the output of that chain against fixed inputs so a
change to the model is a decision with a failing test attached, rather than a
number that quietly moved.

A failure here is not necessarily a bug. It means: the model changed, say so
out loud, and update the expectation in the same commit that changed it.

**Everything here was once relational** — `< 5.0`, `<= one`, "sorted
descending" — and relational assertions cannot detect drift, only inversion.
The normalizer moved from `sqrt(LOC/1000)` to `LOC/1000` and the slope from
0.5 to 1.5, re-grading every repository in the calibration corpus and moving
its median from 3.36 to 3.20, and this file passed untouched. The pinned
block below is the part that actually does the job the module docstring
claims; the relational tests are kept because they pin different properties
(ordering, monotonicity, P3) that must hold under *any* tuning.

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
from secure_code_audit.scoring import SCORING_MODEL, letter_grade, score


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


# --------------------------------------------------------------------------
# The numbers themselves
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "loc", "expected"),
    [
        (Severity.CRITICAL, 1_000, 0.00),
        (Severity.CRITICAL, 10_000, 3.05),
        (Severity.CRITICAL, 100_000, 4.805),
        (Severity.HIGH, 1_000, 0.00),
        (Severity.HIGH, 10_000, 4.22),
        (Severity.HIGH, 100_000, 4.922),
        (Severity.MEDIUM, 1_000, 2.075),
        (Severity.MEDIUM, 10_000, 4.7075),
        (Severity.LOW, 1_000, 4.025),
        (Severity.LOW, 10_000, 4.9025),
    ],
)
def test_one_finding_scores_exactly_this(severity: Severity, loc: int, expected: float):
    """One finding, one size, one number — the whole chain in a single value.

    These are not derived from anything; they are what the current model
    outputs. Touching a severity weight, the normalizer or the slope moves
    them, which is the point.
    """
    assert score([_finding(severity=severity)], loc_scanned=loc).overall == pytest.approx(expected)


def test_the_rank_discount_is_pinned():
    """Ten hits of one rule, not ten times one hit.

    The k-th hit of a rule counts `weight / sqrt(k)`, so ten sum to about
    5.02x a single hit rather than 10x. If saturation is ever retuned, this
    is the number that moves.
    """
    findings = [_finding(severity=Severity.HIGH, line=n) for n in range(1, 11)]

    assert score(findings, loc_scanned=10_000).overall == pytest.approx(1.0836, abs=1e-4)


def test_a_high_finding_in_a_very_large_repository_rounds_to_a_plus():
    """The stated cost of density normalization, written down rather than
    discovered later.

    Under `LOC/1000` a single HIGH finding in a 100,000-line repository
    normalizes to 0.06 and grades 4.92 — A+. That is correct as a *density*
    and useless as an alarm, which is why the default `fail_on_new` gate,
    not the grade, is what fails a build. A grade is for comparing and for
    trend; it was never the thing that catches a vulnerability.

    `secrets` is the documented exception and is pinned separately below.
    """
    report = score([_finding(severity=Severity.HIGH)], loc_scanned=100_000)

    assert report.letter == "A+"
    assert report.overall < 5.0  # it did move, just not far enough to matter


# --------------------------------------------------------------------------
# Secrets are a count, not a rate (D17)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("loc", "expected_letter"),
    [
        (1_000, "F"),
        (10_000, "F"),
        (100_000, "B"),
        (1_000_000, "A-"),
    ],
)
def test_one_committed_credential_does_not_dilute_away(loc: int, expected_letter: str):
    """The Juice Shop case, pinned.

    Four hardcoded API keys and three private keys in 115,340 lines graded
    **B+** while the repository was a training application written to be
    insecure. Dividing a committed credential by repository size is what did
    it. `secrets` normalizes by `sqrt(LOC/1000)` instead.

    A million-line repository with exactly one credential still reaches A-,
    and that is the deliberate limit of the softening: `secrets` is damped,
    not exempted, because an absolute count failed Django on two
    low-confidence hits. What stops a credential being ignored is the gate —
    `secrets` escalates from *any* axis — not the grade.
    """
    finding = _finding(severity=Severity.CRITICAL, category=Category.SECRETS)

    assert score([finding], loc_scanned=loc).letter == expected_letter


def test_secrets_are_damped_relative_to_everything_else():
    """The same weight in another category dilutes faster, which is the whole
    distinction: an injection sink is a rate, a credential is a count."""
    loc = 100_000
    secret = score([_finding(severity=Severity.CRITICAL, category=Category.SECRETS)], loc).overall
    sink = score(
        [_finding(severity=Severity.CRITICAL, category=Category.CODE_VULNERABILITIES)], loc
    ).overall

    assert secret < sink


# --------------------------------------------------------------------------
# The declared scoring model must match the actual one
# --------------------------------------------------------------------------
#
# `SCORING_MODEL` is a hand-maintained integer, and a number a human must
# remember to bump will eventually not get bumped. This project has already
# shipped that exact defect once: `pyproject.toml` said 0.4.0 while
# `__version__` said 0.3.0, and the release verified the half that was right.
#
# The failure here is the bad kind. If the model changes and the integer does
# not, `maintainability-agent` splices two scoring models into one series and
# presents it as a trend — invisibly, because every field still validates.
#
# So the integer is pinned to a digest of the model itself: the weight tables,
# the bonus, the slope, the letter bands, the count-like categories, and the
# output of the real `score()` over a fixed matrix. Constants are digested for
# a legible failure; the outputs are digested because a formula can change
# with no constant moving — `normalize()` did exactly that.


def _model_digest() -> str:
    import hashlib

    from secure_code_audit.scoring import (
        CATEGORY_WEIGHT,
        CONFIDENCE_WEIGHT,
        COUNT_LIKE_CATEGORIES,
        CWE_TOP25_BONUS,
        GRADE_SLOPE,
        SEVERITY_WEIGHT,
    )

    parts: list[str] = [
        f"severity={sorted((k.value, v) for k, v in SEVERITY_WEIGHT.items())}",
        f"confidence={sorted((k.value, v) for k, v in CONFIDENCE_WEIGHT.items())}",
        f"category={sorted((k.value, v) for k, v in CATEGORY_WEIGHT.items())}",
        f"top25_bonus={CWE_TOP25_BONUS}",
        f"slope={GRADE_SLOPE}",
        f"count_like={sorted(COUNT_LIKE_CATEGORIES)}",
        f"bands={[letter_grade(v / 100) for v in range(0, 501)]}",
    ]
    # The formula, exercised rather than described.
    for category in sorted(Category, key=lambda c: c.value):
        for severity in sorted(Severity, key=lambda s: s.value):
            for loc in (1_000, 10_000, 100_000, 1_000_000):
                findings = [
                    _finding(severity=severity, category=category, line=n) for n in range(1, 4)
                ]
                value = score(findings, loc_scanned=loc).overall
                parts.append(f"{category.value}/{severity.value}/{loc}={value:.6f}")

    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


#: digest → the `SCORING_MODEL` that produced it.
#:
#: Adding a row is how a model change is declared. Editing an existing row is
#: redefining what that model number meant, which is a lie a reviewer can see.
_MODEL_DIGESTS: dict[int, str] = {
    2: "2488327bbd1ace3e",  # D16 + D17: density normalizer, secrets count-like, slope 1.3
}


def test_the_declared_scoring_model_matches_the_actual_model():
    """If this fails, the scoring model changed.

    Bump `SCORING_MODEL`, add a row to `_MODEL_DIGESTS` for the new number,
    and leave the old rows alone. Then tell the `maintainability-agent`
    maintainer, because MA opens a new trend series at that boundary and its
    CI pins this tool by exact version.
    """
    assert SCORING_MODEL in _MODEL_DIGESTS, (
        f"SCORING_MODEL is {SCORING_MODEL} with no recorded digest; add one"
    )
    assert _model_digest() == _MODEL_DIGESTS[SCORING_MODEL], (
        "the scoring model changed but SCORING_MODEL did not. A consumer "
        "keeping a trend will splice the old and new models into one line "
        "and call it knowledge. Bump SCORING_MODEL and add a digest row."
    )


def test_the_reserved_model_number_is_never_emitted():
    """1 denotes "before this field existed", and those releases do not share
    one model. Back-filling a 1 would assert they did."""
    assert SCORING_MODEL >= 2
    assert 1 not in _MODEL_DIGESTS
