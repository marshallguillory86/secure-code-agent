"""The test tree is reported beside the score, not folded into it.

A project graded on its test fixtures is graded on the wrong thing. The
calibration corpus measured how badly: including test directories moved the
median normalized subtotal from 4.36 to 50.15 and put ten of fourteen
well-maintained open-source projects at F. Across six large repositories the
test trees held 7,688 Bandit `B101` assert findings — against 17 real secrets.

The fix is not to discard them. `password="hunter2"` in a test double and a
committed private key are both "findings in a test file", and only one is a
defect. So the tree is a third axis beside findings and coverage, for the same
reason those two are separate: averaging things that mean different things
destroys both.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit import config as config_mod
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.git_tools import is_test_path, loc_under
from secure_code_audit.scoring import (
    ALWAYS_SCORED_CATEGORIES,
    partition_by_tree,
    score,
    summarize_test_tree,
)


def _finding(path: str, category: Category = Category.CODE_VULNERABILITIES, **kw) -> Finding:
    return Finding(
        rule_id=kw.get("rule_id", "B101"),
        scanner="bandit",
        fingerprint=path,
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=kw.get("severity", Severity.LOW),
        confidence=Confidence.HIGH,
        file_path=Path(path),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="m",
    )


def _is_test(root: Path, patterns):
    return lambda f: is_test_path(f.file_path, root, patterns)


def test_test_tree_findings_are_partitioned_out_of_the_score(tmp_path):
    patterns = config_mod.DEFAULT_TEST_PATTERNS
    findings = [
        _finding(str(tmp_path / "src" / "app.py")),
        _finding(str(tmp_path / "tests" / "test_app.py")),
        _finding(str(tmp_path / "tests" / "helpers.py")),
    ]

    primary, test = partition_by_tree(findings, _is_test(tmp_path, patterns))

    assert [str(f.file_path) for f in primary] == [str(tmp_path / "src" / "app.py")]
    assert len(test) == 2


def test_a_secret_in_a_test_file_is_still_scored(tmp_path):
    """The exemption that keeps this from being a loophole.

    A committed credential is a leak wherever it lives, and the corpus backs
    it: every `secrets` finding inside a test tree came from gitleaks — private
    keys, JWTs, API keys — and none from Bandit's hardcoded-password
    heuristics, which are categorised `code_vulnerabilities` and are the actual
    noise.
    """
    assert Category.SECRETS in ALWAYS_SCORED_CATEGORIES

    findings = [
        _finding(
            str(tmp_path / "tests" / "conftest.py"),
            Category.SECRETS,
            severity=Severity.CRITICAL,
            rule_id="gitleaks.private-key",
        ),
        _finding(str(tmp_path / "tests" / "test_app.py")),
    ]

    primary, test = partition_by_tree(
        findings, _is_test(tmp_path, config_mod.DEFAULT_TEST_PATTERNS)
    )

    assert [f.rule_id for f in primary] == ["gitleaks.private-key"]
    assert [f.rule_id for f in test] == ["B101"]


def test_the_score_ignores_test_findings_entirely(tmp_path):
    """Seven hundred test findings must not move the number by one point."""
    primary_only = [_finding(str(tmp_path / "app.py"), severity=Severity.HIGH)]
    with_tests = primary_only + [
        _finding(str(tmp_path / "tests" / f"test_{n}.py")) for n in range(700)
    ]

    kept, dropped = partition_by_tree(
        with_tests, _is_test(tmp_path, config_mod.DEFAULT_TEST_PATTERNS)
    )

    assert len(dropped) == 700
    assert score(kept, 10_000).overall == score(primary_only, 10_000).overall


def test_loc_splits_so_the_denominator_moves_with_the_numerator(tmp_path):
    """The mistake this split would otherwise reintroduce.

    Scoring primary findings over a LOC count that still included the test tree
    would understate every repository in proportion to how well it is tested.
    An earlier revision of the calibration analysis did exactly that and made
    every figure too generous.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")

    primary, test = loc_under(tmp_path, (".py",), (), config_mod.DEFAULT_TEST_PATTERNS)

    assert primary == 3
    assert test == 2


def test_no_test_patterns_means_everything_is_primary(tmp_path):
    """Absent configuration must not silently shrink the score's denominator."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")

    primary, test = loc_under(tmp_path, (".py",), (), ())

    assert (primary, test) == (2, 0)


def test_the_report_counts_without_scoring(tmp_path):
    findings = [
        _finding(str(tmp_path / "tests" / "a.py"), severity=Severity.LOW),
        _finding(str(tmp_path / "tests" / "b.py"), severity=Severity.MEDIUM),
        _finding(str(tmp_path / "tests" / "c.py"), severity=Severity.MEDIUM),
    ]

    report = summarize_test_tree(findings, loc=4_284)

    assert report.count == 3
    assert report.loc == 4_284
    assert report.per_severity_count == {Severity.LOW: 1, Severity.MEDIUM: 2}
    assert "not scored" in report.headline()
    assert "3 finding" in report.headline()


def test_an_empty_test_tree_still_reports(tmp_path):
    """ "We looked and found nothing" and "we never looked" are different."""
    report = summarize_test_tree([], loc=1_200)

    assert report.count == 0
    assert "nothing found" in report.headline()


def test_a_suppressed_test_finding_is_not_counted():
    kept = _finding("tests/a.py")
    muted = _finding("tests/b.py")
    object.__setattr__(muted, "suppressed", True)

    assert summarize_test_tree([kept, muted], loc=10).count == 1
