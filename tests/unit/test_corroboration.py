"""One weakness at one line is one finding, however many checks saw it.

Bandit ships `mark_safe` (B308) as a generic blacklist call *and*
`django_mark_safe` (B703) as a Django-specific plugin. Both fire on the same
expression. Django's audit carried 56 B703 and 51 B308 findings sharing 50
lines — a third of its reported code findings were one issue counted twice.

This changed no grade. Django was already clamped at 0 and no other corpus
repository has the pair, so the corpus median is identical before and after.
It is fixed anyway, because a report that lists a line twice is wrong about
the code, and a remediation prompt built from it asks for the same fix twice.

The risk in the other direction is worse than the bug: collapsing two
*different* weaknesses at one line would hide a finding. So the merge is
deliberately narrow — a hand-checked alias table, plus the CWE where one is
mapped — and these tests pin both halves.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
    merge_corroborating,
)


def _f(
    rule_id: str,
    *,
    scanner: str = "bandit",
    line: int = 10,
    path: str = "app.py",
    cwe: str | None = None,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner=scanner,
        fingerprint=f"{scanner}{rule_id}{path}{line}",
        canonical_cwe=cwe,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=confidence,
        file_path=Path(path),
        line_start=line,
        line_end=line,
        code_snippet="mark_safe(value)",
        message="m",
    )


# ---------------------------------------------------------------------------
# What merges
# ---------------------------------------------------------------------------


def test_the_same_check_under_two_ids_becomes_one_finding():
    """The measured case, exactly."""
    merged = merge_corroborating([_f("B703"), _f("B308")])

    assert len(merged) == 1
    assert merged[0].rule_id == "B703"
    assert merged[0].corroborated_by == ("bandit:B308",)


def test_the_witness_is_recorded_rather_than_discarded():
    """Two checks agreeing is stronger evidence, and the report says so."""
    merged = merge_corroborating([_f("B308"), _f("B703")])

    assert merged[0].corroborated_by == ("bandit:B703",)


def test_an_alias_pair_merges_even_when_upstream_gives_them_different_cwes():
    """The regression the corpus caught and the unit tests did not.

    Bandit files `mark_safe` as CWE-79 under B308 and CWE-80 under B703 —
    cross-site scripting and "improper neutralization of script-related
    tags", two names for one check firing on one expression.

    While Bandit's CWEs were being discarded both were None, the key fell
    back to the alias table, and the pair merged. The moment the adapter
    started reading them, each acquired a different CWE, the CWE outranked
    the alias, and Django went back to counting `mark_safe` twice. Every
    test here passed throughout, because they all used rules with no CWE.
    """
    merged = merge_corroborating(
        [_f("B703", cwe="CWE-80"), _f("B308", cwe="CWE-79")],
    )

    assert len(merged) == 1
    assert merged[0].corroborated_by == ("bandit:B308",)


def test_two_checks_sharing_a_cwe_at_one_line_are_one_weakness():
    """Where a CWE is mapped it is the discriminator, across scanners too."""
    merged = merge_corroborating(
        [
            _f("B602", cwe="CWE-78"),
            _f("sca.python.subprocess.shell_true", scanner="builtin_rules", cwe="CWE-78"),
        ]
    )

    assert len(merged) == 1
    assert merged[0].corroborated_by == ("builtin_rules:sca.python.subprocess.shell_true",)


def test_the_strongest_report_of_a_weakness_is_the_one_kept():
    """Merging must not quietly downgrade.

    If one scanner calls it HIGH and another LOW, the finding is HIGH with a
    LOW witness — never the reverse, which would let adding a scanner improve
    the grade.
    """
    merged = merge_corroborating(
        [
            _f("B703", severity=Severity.LOW, confidence=Confidence.LOW),
            _f("B308", severity=Severity.HIGH, confidence=Confidence.HIGH),
        ]
    )

    assert len(merged) == 1
    assert merged[0].severity is Severity.HIGH
    assert merged[0].confidence is Confidence.HIGH


def test_confidence_breaks_a_severity_tie():
    merged = merge_corroborating(
        [
            _f("B703", confidence=Confidence.LOW),
            _f("B308", confidence=Confidence.HIGH),
        ]
    )

    assert merged[0].confidence is Confidence.HIGH


# ---------------------------------------------------------------------------
# What must not merge
# ---------------------------------------------------------------------------


def test_two_different_weaknesses_at_one_line_stay_two_findings():
    """The failure mode that would be worse than the bug.

    `B603` (subprocess without shell=True) and `B607` (partial executable
    path) co-occur four times in Django on the same lines and are genuinely
    two different problems with two different fixes.
    """
    merged = merge_corroborating([_f("B603"), _f("B607")])

    assert len(merged) == 2


def test_different_cwes_at_one_line_stay_separate():
    merged = merge_corroborating([_f("X", cwe="CWE-78"), _f("Y", cwe="CWE-89")])

    assert len(merged) == 2


def test_the_same_rule_at_different_lines_stays_separate():
    """Volume is not duplication. Ten real instances are ten findings."""
    merged = merge_corroborating([_f("B101", line=n) for n in range(10)])

    assert len(merged) == 10


def test_the_same_rule_in_different_files_stays_separate():
    merged = merge_corroborating([_f("B101", path="a.py"), _f("B101", path="b.py")])

    assert len(merged) == 2


def test_an_unmapped_rule_from_two_scanners_is_not_assumed_identical():
    """No CWE and no alias entry means we do not know they are the same.

    Guessing here would hide findings, so the default is to keep both.
    """
    merged = merge_corroborating([_f("R1", scanner="bandit"), _f("R1", scanner="semgrep")])

    assert len(merged) == 2


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_order_is_preserved():
    """Reports are read by humans; stable order keeps diffs reviewable."""
    findings = [_f("B101", line=3), _f("B608", line=1), _f("B105", line=2)]

    assert [f.rule_id for f in merge_corroborating(findings)] == ["B101", "B608", "B105"]


def test_a_finding_with_no_duplicate_is_returned_untouched():
    original = _f("B101")
    (merged,) = merge_corroborating([original])

    assert merged is original
    assert merged.corroborated_by == ()


def test_an_empty_scan_merges_to_nothing():
    assert merge_corroborating([]) == []


# ---------------------------------------------------------------------------
# A shared CWE is not a shared weakness
# ---------------------------------------------------------------------------


def test_two_rules_from_one_scanner_sharing_a_cwe_stay_separate():
    """The defect this rule exists for, found by auditing a single file.

    Bandit files B602 (`shell=True`), B603 (subprocess call) and B607
    (partial executable path) all under CWE-78. They are not one finding:
    one is fixed with an argument list, one with an absolute path. Keying
    the merge on the CWE collapsed them, so
    `subprocess.call('ls', shell=True)` reported B607 alone with the
    `shell=True` buried inside it as a footnote — a work order missing the
    more serious of the two.

    `test_two_different_weaknesses_at_one_line_stay_two_findings` above
    asserted this and passed anyway, because its fixtures carried no CWE.
    Reading Bandit's CWEs gave them one and turned it into a false
    assurance.
    """
    merged = merge_corroborating(
        [_f("B602", cwe="CWE-78"), _f("B607", cwe="CWE-78")],
    )

    assert len(merged) == 2
    assert {f.rule_id for f in merged} == {"B602", "B607"}


def test_two_scanners_sharing_a_cwe_still_corroborate():
    """The other half, and the reason the function exists: bandit and our
    own rule catching one `shell=True` is one finding with two witnesses."""
    merged = merge_corroborating(
        [
            _f("B602", scanner="bandit", cwe="CWE-78"),
            _f("sca.python.subprocess.shell_true", scanner="builtin_rules", cwe="CWE-78"),
        ]
    )

    assert len(merged) == 1
    assert merged[0].corroborated_by == ("builtin_rules:sca.python.subprocess.shell_true",)


def test_an_alias_pair_merges_regardless_of_cwe():
    """The hand-checked table still outranks everything for one scanner."""
    merged = merge_corroborating([_f("B703", cwe="CWE-80"), _f("B308", cwe="CWE-79")])

    assert len(merged) == 1


def test_different_scanners_with_no_cwe_do_not_merge():
    """Without a CWE there is no evidence they are the same weakness, and
    guessing would hide a finding."""
    merged = merge_corroborating(
        [_f("R1", scanner="bandit"), _f("R1", scanner="semgrep")],
    )

    assert len(merged) == 2
