"""The language nobody read must appear in what a person actually reads.

Coverage degrading to PARTIAL is only half an answer. "scanner coverage is
partial" tells an operator that something is missing, not *what* — and this
repository made exactly that mistake earlier the same day with trivy, where
the 429 from Maven Central sat in `ScannerExecution.reason` while the
operator-facing line said `did not complete: failed`. A diagnosis that
reaches only a JSON field nobody reads is not a diagnosis.

So the language and the scanner that would read it have to survive into the
JSON report and into the summary a person sees in CI.
"""

from __future__ import annotations

from secure_code_audit.renderers import _coverage_to_dict, _summary_section
from secure_code_audit.scanner_status import (
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)
from secure_code_audit.scoring import GateResult, score


def _gate() -> GateResult:
    return GateResult(passed=True, reasons=(), tripped=(), configured=())


def _coverage():
    ran = ScannerExecution(name="bandit", outcome=ScannerOutcome.COMPLETED)
    return evaluate_coverage([ran], required=[], languages=["go"])


def test_the_premise_holds():
    """Without an unread language recorded, the checks below prove nothing."""
    cov = _coverage()

    assert cov.unread_languages, cov
    assert "gosec" in " ".join(cov.unread_languages)


def test_the_json_report_carries_the_unread_language():
    """Machine consumers — MA's security pillar among them — need the field."""
    cov = _coverage()

    payload = _coverage_to_dict(cov)

    unread = (payload or {}).get("unread_languages")
    assert unread, f"the JSON dropped it: {payload}"
    assert any("gosec" in entry for entry in unread), unread


def test_the_markdown_report_names_the_language_and_the_scanner():
    """The report a person opens."""
    cov = _coverage()

    text = _summary_section(score([], loc_scanned=1000), _gate(), cov)

    assert "go" in text.lower()
    assert "gosec" in text, "the remedy was not named"


def test_a_fully_covered_run_says_nothing_about_languages():
    """The falsifier: no noise when there is nothing to report.

    A warning that is always on is not a warning, which is the reasoning the
    applicability check in `_repository_inventory` already records.
    """
    ran = ScannerExecution(name="bandit", outcome=ScannerOutcome.COMPLETED)
    cov = evaluate_coverage([ran], required=[], languages=["python"])

    text = _summary_section(score([], loc_scanned=1000), _gate(), cov)
    payload = _coverage_to_dict(cov) or {}

    assert "gosec" not in text
    assert not payload.get("unread_languages")
