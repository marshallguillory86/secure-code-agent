"""Findings are scored, reported, or gated by which tree they came from.

A project graded on its test fixtures is graded on the wrong thing. The
calibration corpus measured how badly: including test directories moved the
median normalized subtotal from 4.36 to 50.15 and put ten of fourteen
well-maintained open-source projects at F.

The fix is not to discard them. `password="hunter2"` in a test double and a
committed private key are both "findings in a test file", and only one is a
defect. So a side axis is reported in full, gated where the operator says the
category matters, and never folded into the code-condition grade.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit import config as config_mod
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.git_tools import is_test_path, loc_under
from secure_code_audit.scoring import (
    GATED_FROM_ANY_AXIS,
    gated_findings,
    partition_by_path,
    score,
    summarize_axis,
)


def _finding(path: str, category: Category = Category.CODE_VULNERABILITIES, **kw) -> Finding:
    rule_id = kw.get("rule_id", "B101")
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=path + rule_id,
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


def _classify(root: Path, patterns=config_mod.DEFAULT_TEST_PATTERNS):
    def inner(finding: Finding) -> str:
        return "test tree" if is_test_path(finding.file_path, root, patterns) else "primary"

    return inner


# --------------------------------------------------------------------------
# Partitioning
# --------------------------------------------------------------------------


def test_test_tree_findings_are_partitioned_out_of_the_score(tmp_path):
    findings = [
        _finding(str(tmp_path / "src" / "app.py")),
        _finding(str(tmp_path / "tests" / "test_app.py")),
        _finding(str(tmp_path / "tests" / "helpers.py")),
    ]

    primary, axes = partition_by_path(findings, _classify(tmp_path))

    assert [str(f.file_path) for f in primary] == [str(tmp_path / "src" / "app.py")]
    assert len(axes["test tree"]) == 2


def test_nothing_is_dropped_by_the_partition(tmp_path):
    """Every finding lands on an axis. A side axis is not a filter."""
    findings = [
        _finding(str(tmp_path / "app.py")),
        _finding(str(tmp_path / "tests" / "t.py")),
    ]

    primary, axes = partition_by_path(findings, _classify(tmp_path))

    assert len(primary) + sum(len(v) for v in axes.values()) == len(findings)


def test_the_score_ignores_test_findings_entirely(tmp_path):
    """Seven hundred test findings must not move the number by one point."""
    primary_only = [_finding(str(tmp_path / "app.py"), severity=Severity.HIGH)]
    with_tests = primary_only + [
        _finding(str(tmp_path / "tests" / f"test_{n}.py"), rule_id=f"R{n}") for n in range(700)
    ]

    kept, axes = partition_by_path(with_tests, _classify(tmp_path))

    assert len(axes["test tree"]) == 700
    assert score(kept, 10_000).overall == score(primary_only, 10_000).overall


# --------------------------------------------------------------------------
# Secrets: gated from any axis, scored only from the primary tree
# --------------------------------------------------------------------------


def test_a_secret_in_a_test_file_is_gated_but_not_scored(tmp_path):
    """The exemption was too broad, and the corpus said so.

    Secrets used to be forced back onto the primary axis wherever they were
    found, reasoning that every test-tree secret came from gitleaks rather
    than Bandit's heuristics. True, and insufficient: `requests` had four
    criticals in `tests/certs/*.key` — certificates its own suite generates —
    and FastAPI had example JWTs in four translations of one tutorial. Those
    alone held six repositories at F.

    Nothing static separates a live credential from a test certificate, so the
    answer is neither to score them nor to ignore them.
    """
    secret = _finding(
        str(tmp_path / "tests" / "conftest.py"),
        Category.SECRETS,
        severity=Severity.CRITICAL,
        rule_id="gitleaks.private-key",
    )
    smell = _finding(str(tmp_path / "tests" / "test_app.py"))

    primary, axes = partition_by_path([secret, smell], _classify(tmp_path))

    # Neither grades the code condition.
    assert primary == []
    assert {f.rule_id for f in axes["test tree"]} == {"gitleaks.private-key", "B101"}

    # The secret still reaches the gate. The code smell does not.
    gated = gated_findings([], (axes["test tree"],), {"fail_on_category": ["secrets"]})
    assert [f.rule_id for f in gated] == ["gitleaks.private-key"]
    assert Category.SECRETS in GATED_FROM_ANY_AXIS


def test_a_test_tree_smell_does_not_reach_a_severity_gate(tmp_path):
    """The other half: escalating everything would fail every build.

    A test tree holds deliberately-vulnerable fixtures — ours has ten HIGH
    findings that exist precisely to be vulnerable. Feeding those to
    `fail_on_severity` would trip on code doing its job.
    """
    smell = _finding(str(tmp_path / "tests" / "t.py"), severity=Severity.HIGH)

    assert gated_findings([], ([smell],), {"fail_on_severity": ["high"]}) == []


def test_escalation_requires_the_operator_to_have_named_the_category(tmp_path):
    """`fail_on_category` is the operator saying *these matter anywhere*.

    Without it nothing is escalated off a side axis — the tool does not invent
    a policy the configuration did not ask for.
    """
    secret = _finding(
        str(tmp_path / "tests" / "conftest.py"), Category.SECRETS, severity=Severity.CRITICAL
    )

    assert gated_findings([], ([secret],), {}) == []
    assert len(gated_findings([], ([secret],), {"fail_on_category": ["secrets"]})) == 1


def test_the_scored_set_always_reaches_the_gate(tmp_path):
    """Moving things off the score must never remove them from the gate."""
    primary = [_finding(str(tmp_path / "app.py"), severity=Severity.CRITICAL)]

    assert gated_findings(primary, (), {}) == primary


# --------------------------------------------------------------------------
# The denominator moves with the numerator
# --------------------------------------------------------------------------


def test_loc_splits_so_the_denominator_moves_with_the_numerator(tmp_path):
    """Scoring primary findings over a LOC count that still included the test
    tree would understate every repository in proportion to how well it is
    tested. An earlier revision of the calibration analysis did exactly that
    and made every figure too generous."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")

    primary, test, _docs = loc_under(tmp_path, (".py",), (), config_mod.DEFAULT_TEST_PATTERNS)

    assert primary == 3
    assert test == 2


def test_no_test_patterns_means_everything_is_primary(tmp_path):
    """Absent configuration must not silently shrink the score's denominator."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")

    assert loc_under(tmp_path, (".py",), (), ()) == (2, 0, 0)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def test_the_report_counts_without_scoring(tmp_path):
    findings = [
        _finding(str(tmp_path / "tests" / "a.py"), severity=Severity.LOW, rule_id="a"),
        _finding(str(tmp_path / "tests" / "b.py"), severity=Severity.MEDIUM, rule_id="b"),
        _finding(str(tmp_path / "tests" / "c.py"), severity=Severity.MEDIUM, rule_id="c"),
    ]

    report = summarize_axis("test tree", findings, loc=4_284)

    assert report.count == 3
    assert report.loc == 4_284
    assert report.per_severity_count == {Severity.LOW: 1, Severity.MEDIUM: 2}
    assert "not scored" in report.headline()


def test_an_empty_axis_still_reports():
    """ "We looked and found nothing" and "we never looked" are different."""
    report = summarize_axis("test tree", [], loc=1_200)

    assert report.count == 0
    assert "nothing found" in report.headline()


def test_a_documentation_axis_reports_without_a_line_count():
    """Documentation advisories are counted against prose, not a LOC figure."""
    report = summarize_axis("documentation", [_finding("docs/tutorial.md")])

    assert report.loc is None
    assert report.count == 1
    assert "documentation" in report.headline()


def test_documentation_loc_leaves_the_primary_denominator(tmp_path):
    """Documentation findings move to their own axis; its lines must move too.

    They did not. FastAPI carries 7,160 lines of `docs/en/data/` —
    translator and contributor lists — that were diluting the count its
    *code* was graded against, while any finding in them was correctly
    excluded from the numerator. Third occurrence of one mismatch, after
    the test tree and the run's own artifacts.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "src" / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    (tmp_path / "docs" / "people.yml").write_text("x: 1\ny: 2\n", encoding="utf-8")

    primary, test, docs = loc_under(
        tmp_path,
        (".py", ".yml"),
        (),
        config_mod.DEFAULT_TEST_PATTERNS,
        (),
        config_mod.DEFAULT_DOCS_PATTERNS,
    )

    assert (primary, test, docs) == (3, 0, 2)


def test_without_docs_patterns_documentation_stays_primary(tmp_path):
    """Absent configuration must not silently shrink the denominator."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "people.yml").write_text("x: 1\ny: 2\n", encoding="utf-8")

    assert loc_under(tmp_path, (".yml",), (), (), (), ()) == (2, 0, 0)


def test_a_lockfile_named_json_is_not_source(tmp_path):
    """`**/*.lock` catches poetry, Gemfile, Cargo and yarn, and misses every
    lockfile the JavaScript ecosystem actually ships. `package-lock.json`
    alone was 9,699 of axios's 17,532 non-code lines."""
    (tmp_path / "package-lock.json").write_text('{\n"a": 1,\n"b": 2\n}\n', encoding="utf-8")
    (tmp_path / "app.js").write_text("const a = 1;\n", encoding="utf-8")

    primary, _test, _docs = loc_under(
        tmp_path, (".js", ".json"), config_mod.DEFAULT_EXCLUDES, (), (), ()
    )

    assert primary == 1
