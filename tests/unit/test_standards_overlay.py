"""An operator may extend the standards mapping, and may not move the grade.

§8 question 3 asked who owns the mapping table. The answer accepted on
2026-10-02 was: ship it as data with an operator overlay. The table is 34
curated rules and Semgrep alone publishes thousands, so an operator who maps
their own rules currently waits for a package release.

The overlay carries the *standards* fields only — CWE, OWASP, ASVS, SSDF,
short description, fix hint. It may not carry `severity`, `confidence` or
`category`, and a row that does is refused rather than ignored.

That constraint is not tidiness. Those three are the scoring inputs, and
D32 is what happens when something outside the curated table can set them:
an in-tree `severity_overrides` moved a repository's own grade from 0.00/F
to 5.00/A+ by re-labelling one finding, because `INFORMATIONAL` is weight
0.0. An overlay that set severity would reopen that hole through a second
door, and an overlay is exactly the kind of file an audited tree would ship.

So the overlay can say *what weakness a rule describes* and cannot say *how
much it counts*. The first is the operator's knowledge; the second is the
instrument's.
"""

from __future__ import annotations

import pytest

from secure_code_audit.findings import Category, Confidence, Severity
from secure_code_audit.scanners._finding_builder import _resolve_standards
from secure_code_audit.standards import (
    clear_overlay,
    install_overlay,
    load_overlay,
    lookup,
    overlay_for,
)

_OVERLAY_DOC = """version: 1
entries:
  - scanner: semgrep
    rule_id: python.lang.security.audit.my-rule
    canonical_cwe: CWE-22
    owasp_top10: A01
    asvs_section: V12.3.1
    nist_ssdf: PW.5.1
    short_desc: Operator-mapped path traversal.
    fix_hint: Resolve and contain the path.
"""


@pytest.fixture(autouse=True)
def _no_overlay_leaks():
    """Module state must not leak between tests.

    `install_overlay` sets process-wide state, because `_resolve_standards`
    is reached from fifteen adapters and threading a config object through
    all of them to deliver one optional table would be the larger change. A
    leaked overlay would make a later test pass for a reason it does not
    state.
    """
    clear_overlay()
    yield
    clear_overlay()


def _install(tmp_path, text: str):
    path = tmp_path / "overlay.yaml"
    path.write_text(text, encoding="utf-8")
    entries, errors = load_overlay(path)
    assert errors == [], errors
    install_overlay(entries)
    return entries


def test_an_overlay_maps_a_rule_the_shipped_table_does_not_cover(tmp_path):
    """The whole point: an operator maps their own rule without a release."""
    _install(tmp_path, _OVERLAY_DOC)
    rule = "python.lang.security.audit.my-rule"

    assert lookup("semgrep", rule) is None or lookup("semgrep", rule).canonical_cwe != "CWE-22"

    std = _resolve_standards(
        "semgrep",
        rule,
        cwe_override=None,
        scanner_cwe=None,
        category=None,
        severity=None,
        confidence=None,
        default_category=Category.CODE_VULNERABILITIES,
    )

    assert std.canonical_cwe == "CWE-22"
    assert std.owasp_top10 == "A01"
    assert std.asvs_section == "V12.3.1"
    assert std.nist_ssdf == "PW.5.1"
    assert std.fix_hint == "Resolve and contain the path."


def test_an_overlay_cannot_change_severity_confidence_or_category(tmp_path):
    """The P3 property, and the reason the constraint exists at all.

    The overlay above maps a rule to CWE-22. Severity, confidence and
    category must still come from the scanner, the curated table, or the
    defaults — never from the overlay — so no overlay can move a grade.
    """
    _install(tmp_path, _OVERLAY_DOC)

    std = _resolve_standards(
        "semgrep",
        "python.lang.security.audit.my-rule",
        cwe_override=None,
        scanner_cwe=None,
        category=None,
        severity=None,
        confidence=None,
        default_category=Category.POLICY_DOCS,
    )

    assert std.canonical_cwe == "CWE-22", "the mapping did apply"
    assert std.severity is Severity.MEDIUM, "severity must be the default, not the overlay's"
    assert std.confidence is Confidence.MEDIUM
    assert std.category is Category.POLICY_DOCS, "category must stay the scanner's default"


@pytest.mark.parametrize("field", ["severity", "confidence", "category"])
def test_an_overlay_row_naming_a_scoring_field_is_refused(tmp_path, field):
    """Refused, not ignored.

    Ignoring it would let an operator believe they had set a severity while
    the number came from elsewhere — the inert-setting defect this
    repository keeps finding. Refusing says which field and why.
    """
    value = {"severity": "informational", "confidence": "low", "category": "policy_docs"}[field]
    text = _OVERLAY_DOC.rstrip("\n") + f"\n    {field}: {value}\n"
    path = tmp_path / "overlay.yaml"
    path.write_text(text, encoding="utf-8")

    entries, errors = load_overlay(path)

    assert entries == {}
    assert len(errors) == 1
    assert field in errors[0]
    assert "D32" in errors[0], f"the refusal must say why: {errors[0]}"


def test_an_overlay_wins_over_the_curated_table_for_a_mapping_field(tmp_path):
    """An operator correcting a curated mapping is the second use case.

    Extension was the stated need; correction is the same mechanism, and
    refusing it would mean a wrong CWE in the shipped table could only be
    fixed by a release — the complaint question 3 opens with.
    """
    curated = lookup("bandit", "B102")
    assert curated.canonical_cwe == "CWE-95", "premise: the shipped value"

    _install(
        tmp_path,
        "version: 1\nentries:\n  - scanner: bandit\n    rule_id: B102\n"
        "    canonical_cwe: CWE-94\n    short_desc: Operator says the parent.\n",
    )

    std = _resolve_standards(
        "bandit",
        "B102",
        cwe_override=None,
        scanner_cwe=None,
        category=None,
        severity=None,
        confidence=None,
        default_category=Category.CODE_VULNERABILITIES,
    )

    assert std.canonical_cwe == "CWE-94"
    assert std.severity is Severity.HIGH, "the curated severity must survive the overlay"
    assert std.category is Category.CODE_VULNERABILITIES


def test_an_adapters_cwe_override_still_beats_the_overlay(tmp_path):
    """Precedence has four sources now, and the adapter is still first.

    A Semgrep rule's own metadata is more specific than anything an operator
    curates for it in bulk, which is why `cwe_override` exists (D31).
    """
    _install(
        tmp_path,
        "version: 1\nentries:\n  - scanner: bandit\n    rule_id: B102\n"
        "    canonical_cwe: CWE-94\n    short_desc: Operator mapping.\n",
    )

    std = _resolve_standards(
        "bandit",
        "B102",
        cwe_override="CWE-78",
        scanner_cwe=None,
        category=None,
        severity=None,
        confidence=None,
        default_category=Category.CODE_VULNERABILITIES,
    )

    assert std.canonical_cwe == "CWE-78"


def test_with_no_overlay_installed_nothing_changes(tmp_path):
    """The falsifier.

    Every test above installs an overlay. If `overlay_for` returned
    something for an empty overlay, or `_resolve_standards` consulted it
    unconditionally, the curated path would be broken and these tests would
    not show it.
    """
    assert overlay_for("bandit", "B102") is None

    std = _resolve_standards(
        "bandit",
        "B102",
        cwe_override=None,
        scanner_cwe=None,
        category=None,
        severity=None,
        confidence=None,
        default_category=Category.CODE_VULNERABILITIES,
    )

    assert std.canonical_cwe == "CWE-95"
    assert std.owasp_top10 == "A03"
    assert std.severity is Severity.HIGH


def test_a_missing_overlay_file_is_an_error_not_an_empty_table(tmp_path):
    """A named-but-absent overlay is a typo in a path, and silence would
    mean the operator's whole mapping file quietly did nothing — the same
    fail-closed reasoning as a named config that does not exist."""
    entries, errors = load_overlay(tmp_path / "does-not-exist.yaml")

    assert entries == {}
    assert len(errors) == 1
    assert "does-not-exist.yaml" in errors[0]
