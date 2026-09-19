"""The work order is available as facts, not only as prose (D27).

`generate` writes Markdown, which is right for the operator and for the
agent that reads the prompt. It is the wrong thing to hand a *tool*.

`maintainability-agent` embeds this work order in an HTML report. It had
only prose, so it wrapped the text in `<pre>` — and a reader who chose an
HTML presentation got raw Markdown inside it: `##` headings, asterisks
for bold, backticks around code, in a page where everything else was
rendered. Prose is the one thing a consumer cannot re-present.

`as_data` is the same triage, the same order and the same caps, as data.
The tiers come from `triage.partition` exactly as the Markdown's do, so
the two can never describe different work — which is the property that
matters, because this project's own rule is that a consumer reproduces
its work order rather than re-ranking it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import remediation, triage
from secure_code_audit.findings import Category, Confidence, Finding, Severity


def _finding(
    rule_id: str = "B608",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    path: str = "src/app.py",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=f"fp:{rule_id}:{path}",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=confidence,
        file_path=Path(path),
        line_start=12,
        line_end=14,
        code_snippet="query = 'SELECT ' + name",
        message="Possible SQL injection",
        short_desc="SQL injection",
        fix_hint="Use a parameterised query.",
    )


# --- the data is the same work as the prose -------------------------------


def test_the_tiers_come_from_the_same_triage() -> None:
    """Not a second opinion about what matters.

    If these could disagree, a consumer would render different work than
    the prompt the operator is reading.
    """
    findings = [_finding(), _finding("B105", Severity.LOW, Confidence.LOW)]

    data = remediation.as_data(findings)
    tiers = triage.partition(findings)

    assert data["counts"]["fix"] == len(tiers[triage.Tier.FIX])
    assert data["counts"]["review"] == len(tiers[triage.Tier.REVIEW])
    assert data["counts"]["accept"] == len(tiers[triage.Tier.ACCEPT])


def test_a_finding_carries_what_a_renderer_needs() -> None:
    """What it is, where it is, what to do, and the citation."""
    entry = remediation.as_data([_finding()])["fix"]["shown"][0]

    assert entry["rule_id"] == "B608"
    assert entry["title"] == "SQL injection"
    assert entry["fix_hint"] == "Use a parameterised query."
    assert entry["path"] == "src/app.py"
    assert entry["line_start"] == 12
    assert entry["code_snippet"] == "query = 'SELECT ' + name"
    assert entry["standards"]["cwe"] == "CWE-89"
    assert entry["standards"]["owasp_top10"] == "A03"


def test_bookkeeping_is_not_published() -> None:
    """The fingerprint and baseline flag are this tool's, not a renderer's.

    Emitting the whole `Finding` would make every internal field a
    published contract that a consumer could start depending on.
    """
    entry = remediation.as_data([_finding()])["fix"]["shown"][0]

    for internal in ("fingerprint", "is_new", "suppressed", "suppression_note"):
        assert internal not in entry


def test_the_caps_match_the_prose() -> None:
    """A consumer must not show more than the artifact the operator reads.

    `omitted` is the same number `_overflow` prints in the Markdown.
    """
    many = [_finding(path=f"src/app{n}.py") for n in range(remediation._MAX_BLOCKS + 5)]

    data = remediation.as_data(many)

    assert len(data["fix"]["shown"]) == remediation._MAX_BLOCKS
    assert data["fix"]["omitted"] == 5
    assert data["counts"]["fix"] == remediation._MAX_BLOCKS + 5


def test_a_review_finding_carries_the_reason_it_was_demoted() -> None:
    """§REVIEW is judgement, and the reason is what the reader checks."""
    data = remediation.as_data([_finding("B105", Severity.LOW, Confidence.LOW)])

    review = data["review"]["shown"]
    if not review:
        pytest.skip("this rule no longer lands in the review tier")
    assert review[0]["review_note"], "a demoted finding without its reason is a bare claim"


def test_a_fix_finding_carries_no_review_note() -> None:
    """The key is present and null rather than absent, so a consumer never
    has to tell a missing field from an empty one."""
    entry = remediation.as_data([_finding()])["fix"]["shown"][0]

    assert entry["review_note"] is None


def test_nothing_to_do_is_an_empty_work_order_not_an_error() -> None:
    data = remediation.as_data([])

    assert data["counts"] == {"fix": 0, "review": 0, "accept": 0}
    assert data["fix"]["shown"] == []


def test_the_schema_version_is_published() -> None:
    """A consumer reads it to know whether it can still parse this."""
    assert remediation.as_data([])["schema_version"] == (remediation.WORK_ORDER_SCHEMA_VERSION)
