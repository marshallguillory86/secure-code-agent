"""The line a person reads must carry the reason the record already holds.

`ScannerExecution` has carried a `reason` field all along, and
`evaluate_coverage` composed its failure strings from the *outcome* alone:

    required scanner 'trivy' did not complete: failed

That string is what reaches `coverage.failures`, which is what the
`require_scanners` gate reports and what the summary prints. So the operator
reading CI gets the word "failed" and no cause, while the cause sits one
field away in the same record.

This is the second half of a defect found by running this repository's own
audit. The first half was the trivy adapter dropping `r.stderr` when it
produced no SARIF; fixing it put a real diagnosis into
`ScannerExecution.reason` — a 429 from Maven Central with a `Retry-After`
and the remedy — and the printed line still said only "failed". A diagnosis
that reaches a JSON field nobody reads is not a diagnosis.

Both halves are the same mistake in the same direction: the tool had the
evidence and reported its absence. That is what this product exists to stop
other people's pipelines doing.
"""

from __future__ import annotations

from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)

_TRIVY_REASON = (
    "trivy emitted no SARIF output (exit 1): FATAL remote Maven repository "
    "returned 429 Too Many Requests. Retry-After: 1313."
)


def _failed(name: str, reason: str | None) -> ScannerExecution:
    return ScannerExecution(name=name, outcome=ScannerOutcome.FAILED, reason=reason)


def test_a_required_scanner_failure_names_the_reason():
    """The defect: the cause was in the record and not in the message."""
    report = evaluate_coverage([_failed("trivy", _TRIVY_REASON)], required=["trivy"])

    assert report.status is CoverageStatus.FAILED
    joined = " ".join(report.failures)
    assert "429" in joined, (
        f"the reason was recorded and the operator-facing failure dropped it: {joined!r}"
    )


def test_the_failure_still_names_the_scanner_and_the_outcome():
    """Adding the cause must not cost the two things the line already said."""
    report = evaluate_coverage([_failed("trivy", _TRIVY_REASON)], required=["trivy"])

    joined = " ".join(report.failures)
    assert "trivy" in joined, joined
    assert "failed" in joined, joined


def test_a_failure_with_no_recorded_reason_reads_as_it_always_did():
    """The falsifier. A scanner that explained nothing must not gain an empty
    colon, and the old message is still the right one when there is no more
    to say."""
    report = evaluate_coverage([_failed("trivy", None)], required=["trivy"])

    assert report.failures == ("required scanner 'trivy' did not complete: failed",), (
        report.failures
    )


def test_an_unselected_required_scanner_is_unchanged():
    """A different failure mode with no execution to carry a reason."""
    report = evaluate_coverage([], required=["trivy"])

    assert report.failures == ("required scanner 'trivy' was not selected",), report.failures


def test_a_completed_required_scanner_still_passes():
    """The ordinary case, pinned because the branch is being edited."""
    report = evaluate_coverage(
        [ScannerExecution(name="trivy", outcome=ScannerOutcome.COMPLETED)], required=["trivy"]
    )

    assert report.status is CoverageStatus.COMPLETE
    assert report.failures == ()
