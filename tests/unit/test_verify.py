"""Proving a work order improved the code, rather than just changed it.

A work order nobody checks is a suggestion. Verification re-audits after the
agent has worked and says, per finding, whether it was repaired, is still
open, was merely silenced, or is new.

The property that makes it worth anything is that **it can fail**. A check
that always passes verifies nothing, so `improved` is deliberately strict:
something fixed, nothing introduced, nothing silenced.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.verify import compare


def _f(fingerprint: str, *, severity=Severity.HIGH, suppressed=False, line=1, path="src/app.py"):
    return Finding(
        rule_id="B602",
        scanner="bandit",
        fingerprint=fingerprint,
        canonical_cwe="CWE-78",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path(path),
        line_start=line,
        line_end=line,
        code_snippet=None,
        message="m",
        suppressed=suppressed,
    )


# ---------------------------------------------------------------------------
# The four outcomes
# ---------------------------------------------------------------------------


def test_a_repaired_finding_is_fixed():
    result = compare([_f("a"), _f("b")], [_f("b")])

    assert [f.fingerprint for f in result.fixed] == ["a"]
    assert [f.fingerprint for f in result.unresolved] == ["b"]


def test_a_new_finding_is_introduced():
    result = compare([_f("a")], [_f("a"), _f("z")])

    assert [f.fingerprint for f in result.introduced] == ["z"]


def test_a_finding_covered_by_a_new_suppression_is_not_fixed():
    """The suppression flag survives into the after-run, so the finding is
    still there — it just stopped counting."""
    result = compare([_f("a")], [_f("a", suppressed=True)])

    assert result.fixed == ()
    assert [f.fingerprint for f in result.suppressed] == ["a"]


def test_control_findings_are_not_outcomes():
    """A scanner that was unavailable before and available after did not
    fix anything, and one that broke did not introduce a vulnerability."""
    before = [_f("a", severity=Severity.INFORMATIONAL)]
    after = [_f("z", severity=Severity.INFORMATIONAL)]

    result = compare(before, after)

    assert (result.fixed, result.introduced, result.unresolved) == ((), (), ())


# ---------------------------------------------------------------------------
# `improved` has to be able to say no
# ---------------------------------------------------------------------------


def test_fixing_something_and_breaking_nothing_is_an_improvement():
    assert compare([_f("a")], []).improved is True


def test_trading_one_finding_for_another_is_not_an_improvement():
    """Five resolved and three introduced is a trade, not progress. The
    headline does not get to round in the flattering direction."""
    result = compare([_f("a"), _f("b")], [_f("z")])

    assert result.fixed and result.introduced
    assert result.improved is False


def test_changing_nothing_is_not_an_improvement():
    assert compare([_f("a")], [_f("a")]).improved is False


def test_silencing_everything_is_not_an_improvement():
    assert compare([_f("a")], [_f("a", suppressed=True)]).improved is False


def test_an_empty_repository_does_not_claim_improvement():
    """Nothing found before or after is not a success story..."""
    result = compare([], [])

    assert result.improved is False


def test_but_a_clean_repository_still_passes():
    """...and it must not fail either.

    These were one property and the conflation made a clean repository
    impossible to verify: nothing to fix meant nothing was fixed, so the
    exit code was 1 forever. A team that resolved everything would have had
    a CI step that could never go green again, which is a good way to teach
    people to delete the CI step.
    """
    result = compare([], [])

    assert result.passed is True
    assert "nothing to fix, nothing broken" in result.headline()


def test_an_unactioned_work_order_still_fails():
    """ "Nothing regressed" is not enough. Findings that were reported and
    remain reported mean the order was not done."""
    result = compare([_f("a")], [_f("a")])

    assert result.passed is False


def test_a_regression_fails_even_alongside_real_fixes():
    result = compare([_f("a"), _f("b")], [_f("z")])

    assert result.regressed is True
    assert result.passed is False


def test_silencing_fails_the_gate():
    assert compare([_f("a")], [_f("a", suppressed=True)]).passed is False


def test_doing_the_work_passes():
    assert compare([_f("a")], []).passed is True


# ---------------------------------------------------------------------------
# Inline silencing — the hole that made this module optimistic
# ---------------------------------------------------------------------------


def test_an_inline_nosec_is_silencing_not_fixing(tmp_path):
    """Measured on a fixture before this check existed: two real findings,
    both silenced with `# nosec`, reported "improved: 2 fixed" and exited 0.

    Our own `.scignore.yaml` suppressions leave the finding in the report
    flagged, where they are easy to spot. Bandit honours `# nosec` itself,
    so the finding never arrives and simply reads as fixed.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import subprocess\n\n\ndef run(c):\n    return subprocess.call(c, shell=True)  # nosec\n",
        encoding="utf-8",
    )

    result = compare([_f("a", line=5)], [], root=tmp_path)

    assert result.fixed == ()
    assert [f.fingerprint for f in result.suppressed] == ["a"]
    assert result.improved is False


def test_a_genuine_repair_is_not_mistaken_for_silencing(tmp_path):
    """The other direction matters as much. A real fix must still read as
    fixed, or the check is just a different way of always failing."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import subprocess\n\n\ndef run(c):\n    return subprocess.call([c], shell=False)\n",
        encoding="utf-8",
    )

    result = compare([_f("a", line=5)], [], root=tmp_path)

    assert [f.fingerprint for f in result.fixed] == ["a"]
    assert result.improved is True


def test_a_deleted_file_is_not_read_as_silenced(tmp_path):
    """Removing the offending code is a legitimate fix."""
    result = compare([_f("a", path="src/gone.py")], [], root=tmp_path)

    assert [f.fingerprint for f in result.fixed] == ["a"]


def test_without_a_root_the_source_check_is_skipped_not_guessed(tmp_path):
    """A caller with no tree to read gets the conservative behaviour rather
    than a fabricated answer."""
    result = compare([_f("a")], [])

    assert [f.fingerprint for f in result.fixed] == ["a"]


# ---------------------------------------------------------------------------
# What the operator reads
# ---------------------------------------------------------------------------


def test_the_headline_names_what_went_wrong():
    result = compare([_f("a"), _f("b")], [_f("b"), _f("z")])

    headline = result.headline()
    assert "not proven" in headline
    assert "introduced" in headline


def test_introducing_a_finding_is_explained_with_its_severity():
    result = compare([_f("a")], [_f("a"), _f("z", severity=Severity.CRITICAL)])

    assert any("critical" in note for note in result.notes)


def test_resolving_nothing_says_so_plainly():
    result = compare([_f("a")], [_f("a")])

    assert any("Nothing was resolved" in note for note in result.notes)


# ---------------------------------------------------------------------------
# The work order does not ask for every finding
# ---------------------------------------------------------------------------


def _test_tree(_f_):
    return "test tree"


def test_test_tree_findings_are_reported_but_not_required():
    """§ACCEPT says in as many words not to patch the test tree.

    Counting those as outstanding work made verification unpassable on any
    repository with fixtures: auditing this one produced 899 actionable
    findings, every one of them in its own test tree, so `passed` was False
    no matter how much real work had been done.
    """
    result = compare([_f("a")], [_f("a")], axis_of=_test_tree)

    assert result.unresolved == ()
    assert [f.fingerprint for f in result.deferred] == ["a"]
    assert result.passed is True


def test_a_primary_finding_is_still_required():
    """The exemption is about location, not about letting work slide."""
    result = compare([_f("a")], [_f("a")])

    assert [f.fingerprint for f in result.unresolved] == ["a"]
    assert result.passed is False


def test_a_new_test_tree_finding_still_counts_as_introduced():
    """A fresh secret in a fixture is worth knowing wherever it appears.
    Deferring existing ones must not stop new ones registering."""
    result = compare([], [_f("z")], axis_of=_test_tree)

    assert [f.fingerprint for f in result.introduced] == ["z"]
    assert result.passed is False


def test_the_headline_does_not_call_a_deferred_tree_clean():
    """Saying "clean" over 897 deferred findings is the flattering read."""
    result = compare([_f("a")], [_f("a")], axis_of=_test_tree)

    headline = result.headline()
    assert "nothing required" in headline
    assert "clean before and after" not in headline
