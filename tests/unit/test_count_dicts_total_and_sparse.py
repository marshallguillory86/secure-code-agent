"""Two count dicts, one type annotation, opposite population guarantees.

`ScoreReport.per_severity_count` and `AxisReport.per_severity_count` are both
`dict[Severity, int]` and they do not mean the same thing:

* `ScoreReport`'s is **total**. `score()` seeds it with
  `dict.fromkeys(Severity, 0)` and fills `per_category_count` in a
  `for cat in Category` loop, so every enum member is a key and an absent
  severity reads as an explicit 0. That is what makes `report[Severity.HIGH]`
  and `report[Category.SECRETS]` safe without a `.get(x, 0)` default.
* `AxisReport`'s is **sparse**. `summarize_axis` starts from `{}` and writes a
  key only when a live finding carried that severity or category. An absent
  key means "no finding of this kind", and the empty dict means "nothing on
  this axis at all".

The sparseness is load-bearing, not an oversight. `AxisReport.worst_severity`
is `max(self.per_severity_count, key=..., default=None)`, and `default=None`
can only fire while the dict is sparse. Seeding it with
`dict.fromkeys(Severity, 0)` — the obvious "tidy-up" that would make the two
classes look consistent — would make `max()` always find a key, and an axis
with no findings whatsoever would report a worst severity of `informational`
in `reported_not_scored` and in `headline()`. Nothing else in the suite pins
that.

**What kind of tests these are, honestly.** Characterization guards. Every
assertion here passes against `scoring.py` as it stands today; none of them is
a red test driving new behaviour. They exist because the implementer is about
to remove `.get(x, 0)` defaults that are unreachable *given* the totality
invariant, and deleting a defensive default is only safe while something else
holds the invariant the default was covering. These tests are that something.

Not duplicated from elsewhere: `tests/unit/test_test_tree.py` pins one
populated axis dict by equality, and
`tests/integration/test_gated_findings_are_reportable.py` pins suppressed
findings out of `AxisReport.count` end to end. Neither pins totality on
`ScoreReport`, the empty-axis dict, or `worst_severity`'s `None`.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import score, summarize_axis


def _finding(
    *,
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.CODE_VULNERABILITIES,
    rule_id: str = "B608",
    line: int = 1,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="fixture",
        fingerprint=f"{rule_id}:{line}",
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path(f"src/m{line}.py"),
        line_start=line,
        line_end=line,
        code_snippet=None,
        message="m",
        suppressed=suppressed,
    )


# ---------------------------------------------------------------------------
# ScoreReport: total. Every enum member is a key, always.
# ---------------------------------------------------------------------------


def test_a_clean_score_report_still_holds_a_key_for_every_severity():
    """Prevents: a reader of a clean repository's report raising KeyError.

    A run with nothing found is the case where a sparse dict would be empty,
    so it is the case that proves totality. `per_severity_count[sev]` has to
    answer 0 for all five severities rather than raise.
    """
    report = score([], loc_scanned=10_000)

    assert set(report.per_severity_count) == set(Severity)
    assert all(report.per_severity_count[sev] == 0 for sev in Severity)


def test_a_clean_score_report_still_holds_a_key_for_every_category():
    """Prevents: `as_table()` or a renderer skipping an unfound category.

    Same guarantee on the other axis of the report. All nine categories are
    keys at 0, so a table built by iterating `Category` finds a count for each
    one without a default.
    """
    report = score([], loc_scanned=10_000)

    assert set(report.per_category_count) == set(Category)
    assert all(report.per_category_count[cat] == 0 for cat in Category)


def test_a_populated_score_report_keeps_the_zeroes_for_what_was_not_found():
    """Prevents: a later rewrite of `score()` emitting only what it saw.

    One HIGH `code_vulnerabilities` finding must not shrink the dicts to one
    key each. The four other severities and eight other categories stay
    present at 0 — "we looked and found none", which is a different statement
    from a missing key.
    """
    report = score(
        [_finding(severity=Severity.HIGH, category=Category.CODE_VULNERABILITIES)],
        loc_scanned=10_000,
    )

    assert set(report.per_severity_count) == set(Severity)
    assert set(report.per_category_count) == set(Category)
    assert report.per_severity_count[Severity.HIGH] == 1
    assert report.per_severity_count[Severity.CRITICAL] == 0
    assert report.per_category_count[Category.CODE_VULNERABILITIES] == 1
    assert report.per_category_count[Category.SECRETS] == 0


def test_a_score_reports_severity_count_excludes_suppressed_findings():
    """Prevents: an accepted finding still being read in the severity totals.

    `test_scoring_drift.py` pins this for `per_category_count`; the severity
    dict is filled by a second, separate loop over the findings and needs the
    same guard. Totality must not be confused with counting everything: the
    suppressed CRITICAL leaves its key present and its value 0.
    """
    live = _finding(severity=Severity.HIGH, line=1)
    muted = _finding(severity=Severity.CRITICAL, line=2, suppressed=True)

    report = score([live, muted], loc_scanned=10_000)

    assert report.per_severity_count[Severity.HIGH] == 1
    assert Severity.CRITICAL in report.per_severity_count
    assert report.per_severity_count[Severity.CRITICAL] == 0


# ---------------------------------------------------------------------------
# AxisReport: sparse. A key exists only where a live finding put it.
# ---------------------------------------------------------------------------


def test_an_axis_counts_only_the_severities_it_actually_saw():
    """Prevents: `summarize_axis` being seeded with `dict.fromkeys(Severity, 0)`.

    Two LOW findings produce a one-key dict. Keys are evidence on this side of
    the module, which is the premise `worst_severity` is built on.
    """
    axis = summarize_axis(
        "test tree",
        [
            _finding(severity=Severity.LOW, line=1, rule_id="a"),
            _finding(severity=Severity.LOW, line=2, rule_id="b"),
        ],
        loc=4_000,
    )

    assert axis.per_severity_count == {Severity.LOW: 2}


def test_an_axis_counts_only_the_categories_it_actually_saw():
    """Prevents: the same seeding applied to the category dict.

    `for cat in Category` would make eight of the nine keys read 0 here. One
    `dependencies` finding means exactly one key.
    """
    axis = summarize_axis("dependencies", [_finding(category=Category.DEPENDENCIES)])

    assert axis.per_category_count == {Category.DEPENDENCIES: 1}


def test_an_axis_with_no_findings_counts_nothing_at_all():
    """Prevents: an empty axis growing fourteen zero-valued keys.

    Both dicts are `{}`, not `{sev: 0 for sev in Severity}`. This is the
    precondition `worst_severity`'s `default=None` depends on, and the state a
    consistency-minded tidy-up of `summarize_axis` would destroy first.
    """
    axis = summarize_axis("test tree", [], loc=1_200)

    assert axis.per_severity_count == {}
    assert axis.per_category_count == {}


def test_an_axis_of_only_suppressed_findings_counts_nothing():
    """Prevents: a suppressed finding keeping a severity key alive.

    Membership and counts split here: the finding stays in `findings` so the
    renderer can still resolve which axis it came from, while the count dicts
    drop back to empty. If suppression ever stopped emptying them, a fully
    accepted axis would still report a worst severity.
    """
    muted = _finding(severity=Severity.CRITICAL, suppressed=True)

    axis = summarize_axis("test tree", [muted])

    assert axis.findings == (muted,)
    assert axis.count == 0
    assert axis.suppressed_count == 1
    assert axis.per_severity_count == {}
    assert axis.worst_severity is None


# ---------------------------------------------------------------------------
# worst_severity: the thing the sparse dict exists to make possible.
# ---------------------------------------------------------------------------


def test_an_empty_axis_has_no_worst_severity():
    """Prevents: "test tree: nothing found" shipping a worst severity anyway.

    `max(..., default=None)` returns None only while the dict is empty. Seed
    the dict with every `Severity` and this axis reports `informational` as
    its worst — a severity attributed to an axis that holds no findings, in
    `headline()` and in the `reported_not_scored` block of the JSON report.
    """
    axis = summarize_axis("test tree", [], loc=1_200)

    assert axis.worst_severity is None
    assert "worst" not in axis.headline()


def test_worst_severity_is_the_highest_rank_present():
    """Prevents: `max()` falling back on insertion or enum order.

    The key is `Severity.rank`, not position. The CRITICAL arrives last and
    must still win over the MEDIUM and LOW that were counted first.
    """
    axis = summarize_axis(
        "test tree",
        [
            _finding(severity=Severity.LOW, line=1, rule_id="a"),
            _finding(severity=Severity.MEDIUM, line=2, rule_id="b"),
            _finding(severity=Severity.CRITICAL, line=3, rule_id="c"),
        ],
    )

    assert axis.worst_severity is Severity.CRITICAL
    assert "worst critical" in axis.headline()


def test_an_axis_of_informational_findings_reports_informational_not_none():
    """Prevents: "nothing found" and "nothing serious found" collapsing.

    The lowest-rank severity is a real answer. `None` is reserved for an empty
    axis, so a guard against the filled dict cannot be satisfied by treating
    `informational` as absence.
    """
    axis = summarize_axis("test tree", [_finding(severity=Severity.INFORMATIONAL)])

    assert axis.worst_severity is Severity.INFORMATIONAL
    assert axis.count == 1
