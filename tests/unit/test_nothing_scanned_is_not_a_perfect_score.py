"""A run that scanned nothing has no grade — it does not have a perfect one.

**The defect, measured.** Pointed at an empty directory, this tool reported
`overall 5.00`, exit 0, and nothing on stderr. One bad `exclude_patterns`
entry did the same to a real tree: a file carrying `subprocess` with a
shell did it honestly at 0.00/F, and with `exclude_patterns: ["**"]` in the
tree's own config the same file, the same finding and the same scanner
reported **5.00/A+** on `loc_scanned: 0`.

No attacker is needed for this. A path typo, a failed checkout, a clone
that produced an empty directory, or a pattern that matched more than its
author meant all end the same way: CI green, grade perfect, nothing
scanned. That is the worst failure a security gate has, because it is
indistinguishable from success.

**Why it happened.** `normalize` divides the weighted subtotal by
`max(loc_scanned, 1) / 1000`. The `max(..., 1)` is there to avoid dividing
by zero, and what it actually does is answer "no denominator" with "a
denominator of one line" — so zero findings over zero lines is a density of
zero, and a density of zero is a perfect grade. Absence read as a value, in
the one place in this codebase where the doctrine against it is written
down: `score` already says *"None, not 5.0. A run where nothing could be
measured has no grade"* and enforces it through the `measurable` set, which
knows about scanners and not about whether there was any code.

That is also why disabling every scanner already behaves correctly and
returned `None` — the two paths into "nothing was measured" disagreed, and
only one of them had been closed.

**The rule.** A category with no findings *and* no scanned code was not
measured, so it grades None, exactly as a category no scanner covers does.
A category that has findings is still graded even at zero lines: a finding
is evidence that something was looked at, and `score` already says so.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit.findings import Category, Severity
from secure_code_audit.scoring import evaluate_gates, score

from .test_scoring import _f


def test_an_empty_scan_is_ungraded_rather_than_perfect():
    """The defect, at the smallest scale that shows it."""
    report = score([], loc_scanned=0)

    assert report.overall is None, (
        f"a run that scanned no code graded {report.overall}. Nothing was "
        "examined, so there is nothing to be perfect about."
    )
    assert report.letter is None, report.letter
    assert all(grade is None for grade in report.per_category.values()), report.per_category


def test_a_clean_tree_that_was_actually_scanned_still_grades_perfect():
    """The falsifier, and the reason the fix is not "zero findings is ungraded".

    A real repository with real code and no findings earns A+ and must keep
    earning it. If this test and the one above could not both pass, the fix
    would be hiding the defect rather than correcting it.
    """
    report = score([], loc_scanned=10_000)

    assert report.overall == 5.0
    assert report.letter == "A+"


def test_a_finding_is_still_graded_when_no_lines_were_counted():
    """Evidence outranks the denominator.

    LOC counts only the configured source extensions, so a scanner can
    legitimately report on a file that contributes no lines — a credential in
    a `.env`, a misconfiguration in a bare dotfile. A finding proves
    something was examined, which is precisely what the ungraded state
    denies, so these must stay graded.
    """
    report = score([_f(Severity.CRITICAL, Category.SECRETS)], loc_scanned=0)

    assert report.per_category[Category.SECRETS] is not None
    assert report.overall is not None
    assert report.overall < 5.0, report.overall


def test_a_category_with_no_findings_is_ungraded_only_when_nothing_was_scanned():
    """The condition is a conjunction, and each half is load-bearing."""
    scanned_and_clean = score([], loc_scanned=5_000)
    unscanned_and_clean = score([], loc_scanned=0)

    assert scanned_and_clean.per_category[Category.CRYPTO] == 5.0
    assert unscanned_and_clean.per_category[Category.CRYPTO] is None


def test_the_min_score_gate_refuses_a_run_that_scanned_nothing():
    """The gate half, which already existed and could never be reached.

    `_gate_min_score` has handled `overall is None` since it was written —
    "withholding evidence must not buy a pass" — but an empty scan never
    produced None, so the branch was unreachable from this direction. An
    operator with a `min_score` floor and a broken path was told PASS.
    """
    report = score([], loc_scanned=0)

    result = evaluate_gates([], report, {"min_score": 3.0})

    assert not result.passed, "a min_score floor was met by scanning nothing"
    assert "min_score" in result.tripped
    assert "nothing measurable was scanned" in " ".join(result.reasons)


def test_the_gate_still_passes_a_scanned_clean_tree_over_its_floor():
    """Falsifier for the one above: the floor must still be satisfiable."""
    report = score([], loc_scanned=5_000)

    assert evaluate_gates([], report, {"min_score": 3.0}).passed


def test_no_configured_gate_is_satisfied_by_a_run_that_measured_nothing():
    """The half CI actually keys on, and the more dangerous one.

    The grade is read by a person; the gate is read by the build. Measured
    before this test was written, on an empty directory with a real severity
    gate supplied from outside the tree:

        secure-code-agent · no score — nothing measurable was scanned · gate PASS
        exit 0

    `--fail-on-gate` was passed. The gate was configured, it was enforced,
    and it was satisfied by there being nothing to find. An operator whose
    path broke, whose checkout failed, or whose exclude pattern was too
    broad got a green build with a perfect-looking one-line summary.

    `_gate_min_score` already refused this for its own gate — "withholding
    evidence must not buy a pass" — and the other gates did not, because
    each asks only "are there offending findings" and zero findings is zero
    offenders. The condition is a property of the *run*, not of any one gate,
    which is why it sits beside the coverage check rather than inside a gate.
    """
    report = score([], loc_scanned=0)

    result = evaluate_gates([], report, {"fail_on_severity": ["critical", "high"]})

    assert not result.passed, (
        "a configured severity gate was satisfied by a run that measured nothing; "
        "the build goes green when the audit never happened"
    )
    assert "nothing_measured" in result.tripped, result.tripped
    assert "nothing" in " ".join(result.reasons).lower(), result.reasons


def test_a_run_that_measured_nothing_with_no_gates_configured_still_only_reports():
    """Falsifier, and the line D33 draws.

    With no policy configured there is nothing to fail: the run reports what
    it found, which is nothing. Tripping here would make this tool refuse to
    produce a report for an empty tree, and `--fail-on-gate` is already
    refused outright when no gate is configured, so the dangerous path is
    closed from the other end.
    """
    report = score([], loc_scanned=0)

    result = evaluate_gates([], report, {})

    assert result.passed
    assert result.tripped == ()


def test_a_scanned_tree_with_a_configured_gate_and_no_findings_still_passes():
    """The ordinary green build, which must stay green.

    This is the test that stops the fix above from degenerating into "every
    clean run fails". Real lines, real gate, no findings: pass.
    """
    report = score([], loc_scanned=5_000)

    result = evaluate_gates([], report, {"fail_on_severity": ["critical", "high"]})

    assert result.passed, result.reasons
    assert result.enforced, "the gate must still count as enforced"


def test_the_reasons_and_tripped_lists_stay_in_step():
    """`renderers` zips them with `strict=True`, so a mismatch raises there.

    Worth its own test because the new check appends to both lists from a
    different place than the per-gate evaluators do, and the renderer would
    be the first thing to notice — at report-writing time, after the audit.
    """
    report = score([], loc_scanned=0)

    result = evaluate_gates([], report, {"fail_on_severity": ["high"], "min_score": 3.0})

    assert len(result.reasons) == len(result.tripped), (result.tripped, result.reasons)


def test_a_tool_unavailable_notice_is_not_evidence_that_anything_was_examined():
    """PRODUCT BUG, found by UAT on the published 0.12.12 wheel.

    A clean `pip install secure-code-agent` ships no scanners. Run it on an
    empty tree and every adapter emits its own `{name}.tool_unavailable`
    control finding — `POLICY_DOCS`, `INFORMATIONAL`. That is a *finding*, so
    the conjunction added for D33 treated it as evidence that the category had
    been examined, graded it, and because `INFORMATIONAL` carries weight 0.0
    the subtotal was zero and the grade a perfect 5.0. Being the only graded
    category, it became the overall:

        per_category: { ...all null..., "policy_docs": 5.0 }
        overall: 5.0   letter: A+   loc_scanned: 0

    D33's reasoning was right about scanner findings and wrong about control
    findings. A credential in a `.env` is evidence that something was looked
    at. A notice saying *"this tool could not run"* is evidence of the
    opposite, and it was buying a perfect score.

    The rule that fixes it needs no knowledge of control findings at all: a
    finding whose severity weight is 0.0 cannot move the score, so it cannot
    be what justifies producing one. Only a finding that could actually move
    the number counts as evidence that the category was measured.

    This passed every local test because a development checkout has the
    scanner floor installed, so no unavailable notice is ever emitted. Only
    installing the published artifact into a clean virtualenv exposed it.
    """
    notice = _f(Severity.INFORMATIONAL, Category.POLICY_DOCS)

    report = score([notice], loc_scanned=0)

    assert report.per_category[Category.POLICY_DOCS] is None, (
        "a tool-unavailable notice graded its own category 5.0; the only "
        "'evidence' was the tool saying it could not look"
    )
    assert report.overall is None, f"overall {report.overall} on a run that scanned nothing"
    assert report.letter is None


def test_the_notice_is_still_reported_even_though_it_is_not_evidence():
    """It must not be deleted — an operator needs to see the scanner failed.

    The falsifier for the fix above: "not evidence" must mean "does not grade
    the category", not "disappears from the report". `per_category_count`
    still counts it, because the count is what the reader uses to find it.
    """
    notice = _f(Severity.INFORMATIONAL, Category.POLICY_DOCS)

    report = score([notice], loc_scanned=0)

    assert report.per_category_count[Category.POLICY_DOCS] == 1
    assert report.per_severity_count[Severity.INFORMATIONAL] == 1


def test_a_weightless_finding_does_not_grade_a_category_on_a_scanned_tree_either():
    """The same rule, where the denominator is real.

    A scanner that ran and reported only informational notes *did* look, so
    the category is measurable through `measured` and still grades — this
    pins that the fix changes the zero-LOC case and nothing else.
    """
    notice = _f(Severity.INFORMATIONAL, Category.POLICY_DOCS)

    report = score([notice], loc_scanned=5_000)

    assert report.per_category[Category.POLICY_DOCS] == 5.0
    assert report.overall == 5.0


def test_a_real_finding_over_no_counted_lines_is_still_graded():
    """D33's second half, re-pinned against the narrower evidence rule.

    The `.env` credential case: LOC counts only configured source
    extensions, so a real finding can arrive on a tree that counted no
    lines. It carries weight, so it is still evidence, and still grades.
    """
    real = _f(Severity.CRITICAL, Category.SECRETS)

    report = score([real], loc_scanned=0)

    assert report.per_category[Category.SECRETS] is not None
    assert report.overall is not None and report.overall < 5.0


def test_a_suppressed_only_run_over_no_code_is_ungraded():
    """Suppression removes a finding from the score, not evidence from the run.

    Worth pinning because it is the one shape that reads like a finding and
    counts like an absence: `score` excludes suppressed findings from every
    count, so a tree whose only findings are suppressed has count 0. With no
    lines scanned either, there is nothing left that was measured.
    """
    suppressed = _f(Severity.HIGH, Category.CODE_VULNERABILITIES, suppressed=True)

    report = score([suppressed], loc_scanned=0)

    assert report.per_category[Category.CODE_VULNERABILITIES] is None
    assert report.overall is None


def test_the_fixture_tree_used_by_the_measurement_is_what_it_claims(tmp_path):
    """Keeps the docstring's numbers honest rather than remembered.

    The measurement above says one file with a shelled-out subprocess call
    grades 0.00. This does not re-run the audit — that belongs in the
    integration suite — but it does hold the shape of the claim: a single
    HIGH code finding over a handful of lines is nowhere near perfect.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    report = score([_f(Severity.HIGH, Category.CODE_VULNERABILITIES)], loc_scanned=3)

    assert report.overall == 0.0, report.overall
    assert report.loc_scanned == 3
    assert Path(tmp_path / "app.py").exists()
