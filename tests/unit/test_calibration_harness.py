"""The calibration harness must score findings the way the product does.

`calibration/calibrate.py` re-derives per-category subtotals from the JSON
report rather than reading the grades off it, because `category_grade` clamps
at 0 and every repository worse than `normalized = 10` therefore reports the
same 0.0 — destroying exactly the tail that decides whether the normalizer
works.

Re-deriving means the harness carries its own copy of `finding_score`, over the
JSON shape instead of the dataclass. That is a second source of truth for the
scoring formula, and a silent one: if the weights change and the harness does
not, the study still runs, still prints a distribution, and quietly measures a
model the product no longer uses. A calibration that is wrong in a way nobody
notices is worse than no calibration, because the bands chosen from it acquire
an authority they never earned.

These tests hold the two together.

**It has drifted twice.** The harness summed each category flat, which was
right until the product started saturating repeats of one rule; after that
the study's subtotal for Django read 488.06 against the product's 218.5 and
nothing failed. It also kept its own `sqrt(LOC/1000)` divisor and its own
`0.5` slope after the product moved to a straight density at slope 1.5. The
divisor and the slope are imported now; the saturation still cannot be,
because `category_subtotal` takes `Finding` objects and a saved report holds
dicts — so it is pinned below instead.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import (
    GRADE_SLOPE,
    category_subtotal,
    finding_score,
    normalize,
)

REPO = Path(__file__).resolve().parent.parent.parent
HARNESS = REPO / "calibration" / "calibrate.py"


def _harness():
    spec = importlib.util.spec_from_file_location("calibrate", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(severity: Severity, confidence: Confidence, category: Category, top25: bool):
    return Finding(
        rule_id="r",
        scanner="s",
        fingerprint="f",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5",
        nist_ssdf="PW.5.1",
        category=category,
        severity=severity,
        confidence=confidence,
        file_path=Path("a.py"),
        line_start=1,
        line_end=1,
        code_snippet="x",
        message="m",
        cwe_top25=top25,
    )


def _as_json(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "category": finding.category.value,
        "cwe_top25": finding.cwe_top25,
        "suppressed": finding.suppressed,
    }


def test_the_harness_exists_where_the_study_says_it_does():
    assert HARNESS.exists(), "the calibration harness has moved; the study cannot be re-run"


def test_the_harness_scores_every_finding_shape_exactly_as_the_product_does():
    """Every combination, not a sample.

    The weight tables are small enough to enumerate completely, and a sampled
    agreement would let a single changed weight through — which is the whole
    failure mode this guards.
    """
    harness = _harness()

    checked = 0
    for severity in Severity:
        for confidence in Confidence:
            for category in Category:
                for top25 in (False, True):
                    finding = _finding(severity, confidence, category, top25)
                    assert harness._finding_score(_as_json(finding)) == pytest.approx(
                        finding_score(finding)
                    ), f"{severity.value}/{confidence.value}/{category.value}/top25={top25}"
                    checked += 1

    assert checked == len(Severity) * len(Confidence) * len(Category) * 2
    assert checked > 100, "the enumeration collapsed; this would pass vacuously"


def test_a_suppressed_finding_scores_zero_in_both():
    harness = _harness()
    finding = _finding(Severity.CRITICAL, Confidence.HIGH, Category.SECRETS, True)
    payload = _as_json(finding) | {"suppressed": True}

    assert harness._finding_score(payload) == 0.0


def test_the_harness_keeps_the_tail_the_product_clamps_away():
    """The reason the harness recomputes rather than reading grades.

    A repository bad enough to drive `normalized` past 10 reports 0.0 from the
    product, and so does one twice as bad. Calibration needs to tell those
    apart, so the harness reports an unclamped value that may go negative.
    """
    harness = _harness()
    payload = {
        "score": {
            "loc_scanned": 1000,
            "overall": 0.0,
            "letter": "F",
            "worst_category": "secrets",
            "per_severity_count": {},
        },
        "findings": [
            _as_json(_finding(Severity.CRITICAL, Confidence.HIGH, Category.SECRETS, True))
            for _ in range(50)
        ],
        "coverage": {"status": "complete"},
    }

    measured = harness.measure(payload)

    assert measured["unclamped_overall"] < 0.0, measured
    assert measured["reported_overall"] == 0.0
    assert measured["worst_normalized"] > 10.0


def test_the_harness_saturates_repeats_exactly_as_the_product_does():
    """The drift that went unnoticed, pinned.

    Both sides must apply the rank discount, both must group by rule within
    a category, and distinct rules must still add in full.
    """
    harness = _harness()

    for count in (1, 2, 5, 50):
        findings = [
            _finding(Severity.HIGH, Confidence.HIGH, Category.CODE_VULNERABILITIES, False)
            for _ in range(count)
        ]
        expected = category_subtotal(findings, Category.CODE_VULNERABILITIES)
        actual = harness._subtotals([_as_json(f) for f in findings])

        assert actual["code_vulnerabilities"] == pytest.approx(expected), count

    # A flat sum would agree at count=1 and nowhere else.
    one = harness._subtotals(
        [_as_json(_finding(Severity.HIGH, Confidence.HIGH, Category.CODE_VULNERABILITIES, False))]
    )["code_vulnerabilities"]
    fifty = harness._subtotals(
        [
            _as_json(_finding(Severity.HIGH, Confidence.HIGH, Category.CODE_VULNERABILITIES, False))
            for _ in range(50)
        ]
    )["code_vulnerabilities"]
    assert fifty < one * 50 * 0.5, "the harness is not saturating at all"


def test_distinct_rules_are_not_saturated_against_each_other():
    """Saturation is per rule. Collapsing across rules would hide independent
    evidence, which is the opposite of what the discount is for."""
    harness = _harness()

    def one(rule_id: str) -> dict:
        finding = _finding(Severity.HIGH, Confidence.HIGH, Category.CODE_VULNERABILITIES, False)
        return _as_json(finding) | {"rule_id": rule_id}

    same = harness._subtotals([one("A"), one("A")])["code_vulnerabilities"]
    distinct = harness._subtotals([one("A"), one("B")])["code_vulnerabilities"]

    assert distinct > same


def test_the_harness_normalizes_and_slopes_through_the_product():
    """Not a second copy of the formula — the product's own.

    Reimplementing these is what let the study report `subtotal/sqrt(kLOC)`
    for a full corpus run after the product had stopped using it.
    """
    harness = _harness()
    payload = {
        "score": {
            "loc_scanned": 20_000,
            "overall": 0.0,
            "letter": "F",
            "worst_category": "code_vulnerabilities",
            "per_severity_count": {},
        },
        "findings": [
            _as_json(_finding(Severity.HIGH, Confidence.HIGH, Category.CODE_VULNERABILITIES, False))
        ],
        "coverage": {"status": "complete"},
    }

    measured = harness.measure(payload)
    subtotal = measured["subtotals"]["code_vulnerabilities"]

    assert measured["normalized"]["code_vulnerabilities"] == pytest.approx(
        normalize(subtotal, 20_000), abs=1e-3
    )
    assert measured["unclamped_overall"] == pytest.approx(
        5.0 - normalize(subtotal, 20_000) * GRADE_SLOPE, abs=1e-3
    )


def test_percentiles_do_not_invent_a_distribution_from_nothing():
    harness = _harness()

    assert harness.percentiles([]) == {}
    single = harness.percentiles([2.0])
    assert single["min"] == single["median"] == single["max"] == 2.0


def test_a_stale_report_cannot_stand_in_for_a_failed_audit(tmp_path):
    """The harness reproduced the exact defect it was built to measure.

    `audit()` checked only whether the report file existed. On the first corpus
    pass the CLI rejected the calibration config for every repository — the
    loader refuses unknown keys (D2) and the config carried a `$comment` — and
    the one repository with a report left over from an earlier smoke run
    reported a score anyway. A failed audit read as a clean result, which is
    the absence-of-evidence failure the gosec adapter exists to prevent,
    reproduced in the tool that measures it.

    The stale report is now removed before the run, so a failed audit has
    nothing to be mistaken for.
    """
    harness = _harness()
    report = tmp_path / "report.json"
    report.write_text('{"score": {"overall": 5.0}}', encoding="utf-8")

    with pytest.raises(RuntimeError, match="no report produced"):
        harness.audit(tmp_path / "absent-target", report, tmp_path / "absent-config.json")

    assert not report.exists(), "the stale report survived a failed audit"


# ---------------------------------------------------------------------------
# Unexamined is not clean
# ---------------------------------------------------------------------------


def _row(language: str, completed: list[str], overall: float = 5.0) -> dict:
    return {
        "name": "r",
        "language": language,
        "coverage": {"scanners": [{"name": n, "outcome": "completed"} for n in completed]},
        "measure": {
            "reported_overall": overall,
            "reported_letter": "A+",
            "worst_normalized": 0.0,
            "unclamped_overall": overall,
            "loc_scanned": 1000,
        },
    }


def test_a_language_with_its_scanner_is_examined():
    harness = _harness()

    assert harness.examined(_row("python", ["bandit", "gitleaks"])) is True
    assert harness.examined(_row("javascript", ["njsscan"])) is True
    assert harness.examined(_row("ruby", ["rubocop"])) is True


def test_a_language_without_its_scanner_is_not_examined():
    """gitleaks and a twenty-rule offline Semgrep profile are not coverage.

    Before njsscan and RuboCop were installed, Python repositories in this
    corpus produced 712 to 5,107 real findings each and everything else
    produced nought to four. That gap is the floor's language coverage, not
    those projects being thirty times cleaner.
    """
    harness = _harness()

    assert harness.examined(_row("javascript", ["gitleaks", "semgrep"])) is False
    assert harness.examined(_row("ruby", ["gitleaks", "semgrep"])) is False


def test_go_without_the_toolchain_is_not_examined():
    """D12: gosec analyses Go by invoking the target's own build tooling."""
    harness = _harness()

    assert harness.examined(_row("go", ["gitleaks", "semgrep", "bandit"])) is False
    assert harness.examined(_row("go", ["gosec"])) is True


def test_java_is_never_examined_by_this_floor():
    """D12: PMD covers none of the patterns, SpotBugs needs bytecode. There
    is no scanner to install that would change this."""
    harness = _harness()

    assert harness.examined(_row("java", ["gitleaks", "semgrep", "bandit"])) is False


def test_the_distribution_excludes_what_was_not_examined():
    """The four unexamined repositories had a median of 5.00 — four perfect
    scores for repositories nobody looked at — and they were holding the
    corpus median up from 3.38 to 4.37."""
    harness = _harness()
    rows = [
        _row("python", ["bandit"], overall=1.0),
        _row("python", ["bandit"], overall=3.0),
        _row("java", [], overall=5.0),
        _row("go", [], overall=5.0),
    ]
    for r in rows:
        r["examined"] = harness.examined(r)

    summary = harness.summarize(rows)

    assert summary["examined"] == 2
    assert sorted(summary["unexamined"]) == ["r", "r"]
    assert summary["examined_overall"]["median"] == 2.0
    # The whole-corpus figure is still reported, just not the one to calibrate from.
    assert summary["reported_overall"]["median"] == 4.0


def test_an_all_unexamined_corpus_reports_no_distribution_rather_than_zero():
    """Saying nothing is correct. Inventing a median over an unread corpus
    is the failure this gate exists to prevent."""
    harness = _harness()
    rows = [_row("java", [], overall=5.0)]
    rows[0]["examined"] = harness.examined(rows[0])

    summary = harness.summarize(rows)

    assert summary["examined"] == 0
    assert summary["examined_overall"] is None
