"""The disclosure line must not crash when there is no number to disclose.

`_declaration_delta` prints what the declared capabilities accounted for and
what the grade would have been without them — the number a reader would
otherwise have to reconstruct. It formats that second grade with `:.2f` and
guards only `undeclared_score is None`, which is the whole report being
absent, not its `overall` being absent.

**This was reachable only after D33.** Until then a run with no scanned
lines graded 5.00, so `overall` was never None on that path. D33 makes it
None, which is correct, and that turned a guard that had always been
sufficient into one that is not. The combination:

- nothing counted as scanned — an empty tree, a fully-excluded one, or a
  tree whose files are not in `paths.include_extensions`;
- every finding suppressed, so no category has a count and `overall` is
  None;
- at least one of those findings matched by a declared capability, because
  `summarize_declarations` counts every matched finding and does not skip
  suppressed ones.

Confirmed by executing it: `TypeError: unsupported format string passed to
NoneType.__format__`.

The honest rendering is to report the accounting without the number. The
declarations did account for findings — that part is true and worth saying —
and there is no "without declarations" grade to compare against, because
there is no grade either way.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit.capabilities import DeclarationReport
from secure_code_audit.cli import _declaration_delta
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import score


def _finding(*, suppressed: bool) -> Finding:
    return Finding(
        rule_id="B404",
        scanner="bandit",
        fingerprint="a" * 16,
        canonical_cwe="CWE-78",
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=Path("tool.py"),
        line_start=1,
        line_end=None,
        code_snippet=None,
        message="m",
        suppressed=suppressed,
    )


def _declared(count: int = 1) -> DeclarationReport:
    return DeclarationReport(
        declared={"subprocess execution": "this tool runs scanners"},
        accounted={"subprocess execution": count},
        unexercised=(),
    )


def test_the_premise_holds_that_this_state_is_reachable():
    """Without this, the test below could pass on an impossible input.

    Two separate facts make the combination real, and both are deliberate:
    `score` counts only unsuppressed findings, and `summarize_declarations`
    counts every matched finding including suppressed ones.
    """
    ungraded = score([_finding(suppressed=True)], loc_scanned=0)

    assert ungraded.overall is None
    assert _declared().total_accounted == 1


def test_an_ungraded_undeclared_score_does_not_raise():
    """The defect: a `:.2f` on None, in shipped code, on the summary path."""
    ungraded = score([_finding(suppressed=True)], loc_scanned=0)

    line = _declaration_delta(ungraded, ungraded, _declared())

    assert line is None or "None" not in line, line


def test_the_accounting_is_still_reported_when_there_is_no_grade():
    """What the declarations accounted for is true regardless of the grade.

    Dropping the line entirely would hide a real disclosure — the point of
    the mechanism — so it reports the count and says there is no comparison
    rather than inventing one.
    """
    ungraded = score([_finding(suppressed=True)], loc_scanned=0)

    line = _declaration_delta(ungraded, ungraded, _declared())

    assert line is not None, "the disclosure was dropped along with the number"
    assert "1 finding(s) accounted for" in line, line
    assert "subprocess execution" in line, line


def test_a_graded_run_still_prints_the_number_it_always_printed():
    """The falsifier. The disclosure's whole value is that second grade."""
    graded = score([_finding(suppressed=False)], loc_scanned=10_000)

    line = _declaration_delta(graded, graded, _declared())

    assert line is not None
    assert "without declarations" in line, line
    assert f"{graded.overall:.2f}" in line, line


def test_no_declarations_means_no_line_at_all():
    """Unchanged behaviour, pinned because the guard is being edited."""
    graded = score([_finding(suppressed=False)], loc_scanned=10_000)
    nothing_declared = DeclarationReport(declared={}, accounted={}, unexercised=())

    assert _declaration_delta(graded, graded, nothing_declared) is None
    assert _declaration_delta(graded, None, _declared()) is None
