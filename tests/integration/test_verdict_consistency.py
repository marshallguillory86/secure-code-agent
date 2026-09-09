"""Every output qualifies the score the same way, because one thing decides it.

`docs/architecture.md` §3 row 2: five sites each decided independently how to
caveat the score, "and the SARIF site was missed entirely on the first pass".
`Verdict` was introduced to hold that decision once — but two renderers were
never wired to it and kept their own condition, which was *weaker* than
`Verdict`'s.

The consequence was live and one-directional in the worst way. `Verdict`
withholds a grade when coverage is incomplete **or** when no
`gates.require_scanners` was declared, because a number computed from whatever
happened to run is not a grade. The markdown and PR-comment renderers caveated
only on incomplete coverage. So a run with no `require_scanners` reported
`verified_grade: null` in JSON and a bare **A+** in the markdown report and the
PR comment — the two artifacts a person actually reads.

These tests assert the agreement rather than the wording, so the caveat can be
rephrased without them failing, but cannot be dropped from one output.
"""

from __future__ import annotations

import pytest

from secure_code_audit import renderers
from secure_code_audit.scanner_status import (
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)
from secure_code_audit.scoring import evaluate_gates, score, verdict

#: Every shape of run that decides whether a grade is claimable.
SCENARIOS = {
    "no require_scanners declared": (
        {},
        [ScannerExecution("builtin_rules", ScannerOutcome.COMPLETED)],
        [],
    ),
    "declared and met": (
        {"require_scanners": ["builtin_rules"]},
        [ScannerExecution("builtin_rules", ScannerOutcome.COMPLETED)],
        ["builtin_rules"],
    ),
    "declared but a scanner was unavailable": (
        {"require_scanners": ["bandit"]},
        [ScannerExecution("bandit", ScannerOutcome.UNAVAILABLE, reason="not installed")],
        ["bandit"],
    ),
    "declared but a scanner failed": (
        {"require_scanners": ["gitleaks"]},
        [ScannerExecution("gitleaks", ScannerOutcome.FAILED, reason="parse failure")],
        ["gitleaks"],
    ),
    "covered only by an unverified import": (
        {"require_scanners": ["trivy"]},
        [ScannerExecution("trivy", ScannerOutcome.UNVERIFIED, reason="sarif import")],
        ["trivy"],
    ),
}


def _run(gate_config: dict, executions: list, required: list):
    coverage = evaluate_coverage(executions, required)
    report = score([], loc_scanned=10_000)
    gate = evaluate_gates([], report, gate_config, coverage)
    return report, gate, coverage, verdict(report, gate_config, coverage)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_no_output_claims_a_grade_the_verdict_withholds(name: str):
    """The one-directional property that matters.

    Over-qualifying is a cosmetic problem. Presenting an unverified number as a
    grade is the P3 failure — withholding evidence buying a better-looking
    result — and it must be impossible in every artifact, not just the one that
    happens to be checked.
    """
    report, gate, coverage, v = _run(*SCENARIOS[name])

    payload = renderers.to_json([], report, gate, coverage, v)
    markdown = renderers._summary_section(report, gate, coverage, v)
    comment = renderers._pr_comment([], report, gate, coverage, v)

    if v.is_verified:
        return

    assert payload["score"]["verified_grade"] is None
    # Neither human-facing artifact may present the letter unqualified.
    assert "not a verified grade" in markdown, markdown
    assert "not a verified grade" in comment, comment
    assert "Verified grade" not in markdown, markdown


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_a_verified_grade_is_reported_as_one_everywhere(name: str):
    report, gate, coverage, v = _run(*SCENARIOS[name])
    if not v.is_verified:
        return

    payload = renderers.to_json([], report, gate, coverage, v)
    markdown = renderers._summary_section(report, gate, coverage, v)
    comment = renderers._pr_comment([], report, gate, coverage, v)

    assert payload["score"]["verified_grade"] == report.letter
    assert "Verified grade" in markdown, markdown
    assert "not a verified grade" not in comment, comment


def test_the_markdown_report_states_why_a_grade_was_withheld():
    """A caveat without a reason is a shrug.

    An operator reading "not a verified grade" needs to know that the fix is to
    declare `gates.require_scanners`, not to go hunting.
    """
    report, gate, coverage, v = _run(*SCENARIOS["no require_scanners declared"])

    markdown = renderers._summary_section(report, gate, coverage, v)

    assert v.reasons
    for reason in v.reasons:
        assert reason in markdown


def test_every_scenario_agrees_across_all_three_outputs():
    """The invariant stated once, over every scenario at the same time."""
    for name in SCENARIOS:
        report, gate, coverage, v = _run(*SCENARIOS[name])
        payload = renderers.to_json([], report, gate, coverage, v)
        markdown = renderers._summary_section(report, gate, coverage, v)
        comment = renderers._pr_comment([], report, gate, coverage, v)

        json_claims_grade = payload["score"]["verified_grade"] is not None
        markdown_claims_grade = "Verified grade" in markdown
        comment_claims_grade = "not a verified grade" not in comment

        assert json_claims_grade == markdown_claims_grade == comment_claims_grade, (
            f"{name}: json={json_claims_grade} markdown={markdown_claims_grade} "
            f"comment={comment_claims_grade}"
        )
