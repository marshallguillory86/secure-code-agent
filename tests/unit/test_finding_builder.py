"""`_resolve_standards` — which of three sources to believe about a finding.

Precedence for the CWE: adapter `cwe_override`, then the curated map via
`lookup`, then the tool's own `scanner_cwe`. The real curated map is used
throughout, so a change to the map that breaks an assumption here fails
loudly rather than being papered over by a stub.

Real entries relied on (all in `standards._MAP`):
  bandit/B608     CWE-89,  A03, Top 25, HIGH severity, MEDIUM confidence
  bandit/B102     CWE-95,  A03, Top 25 only via its parent CWE-94
  gitleaks/*      CWE-798, wildcard entry, CRITICAL severity
  scorecard/*     no CWE, but OWASP A08 -- a map entry with a gap
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners._finding_builder import (
    FindingConstruction,
    _resolve_standards,
    _Standards,
)
from secure_code_audit.standards import is_top25, lookup, owasp_for_cwe


def _resolve(scanner="bandit", rule_id="B608", **overrides):
    kwargs = {
        "cwe_override": None,
        "scanner_cwe": None,
        "category": None,
        "severity": None,
        "confidence": None,
        "default_category": Category.CODE_VULNERABILITIES,
    }
    kwargs.update(overrides)
    return _resolve_standards(scanner, rule_id, **kwargs)


# --- CWE precedence -----------------------------------------------------


def test_cwe_override_beats_curated_map_and_scanner_cwe():
    """An adapter's override must outrank both other sources.

    Prevents Semgrep's rule-specific CWE being replaced by the coarser curated
    one. The map's own CWE-89 and the tool's CWE-703 are both present and
    different, so only a correct ordering yields CWE-79.
    """
    assert lookup("bandit", "B608").canonical_cwe == "CWE-89"  # premise

    std = _resolve(cwe_override="CWE-79", scanner_cwe="CWE-703")

    assert std.canonical_cwe == "CWE-79"


def test_curated_map_beats_scanner_cwe():
    """The map outranks what the tool says about its own rule.

    Prevents the tool's "defensible" CWE overwriting a reviewed, more specific
    one: B608 is curated as CWE-89 while Bandit may publish something else.
    """
    std = _resolve(scanner_cwe="CWE-703")

    assert std.canonical_cwe == "CWE-89"


def test_scanner_cwe_is_used_when_no_map_entry_exists():
    """With no curated entry, the tool's own CWE beats having none at all.

    Prevents the regression where 86% of corpus findings carried no CWE
    because Bandit's and gosec's published CWEs were discarded.
    """
    assert lookup("nosuchscanner", "X1") is None  # premise

    std = _resolve("nosuchscanner", "X1", scanner_cwe="CWE-89")

    assert std.canonical_cwe == "CWE-89"


def test_no_source_at_all_leaves_the_cwe_unset_rather_than_invented():
    """No override, no map entry, no scanner CWE means None, never a default."""
    std = _resolve("nosuchscanner", "X1")

    assert std.canonical_cwe is None
    assert std.owasp_top10 is None
    assert not is_top25(std.canonical_cwe)


def test_scanner_cwe_fills_a_map_entry_that_has_no_cwe_of_its_own():
    """A curated entry whose CWE is None must not shadow the tool's CWE.

    Prevents `entry.canonical_cwe` being treated as authoritative when empty:
    scorecard/* is curated with no CWE, so the tool's value must come through.
    """
    entry = lookup("scorecard", "Anything")
    assert entry is not None and entry.canonical_cwe is None  # premise

    std = _resolve("scorecard", "Anything", scanner_cwe="CWE-89")

    assert std.canonical_cwe == "CWE-89"


def test_wildcard_map_entry_applies_to_an_unlisted_rule():
    """`lookup`'s (scanner, '*') fallback must reach the resolver.

    Prevents wildcard-only scanners (gitleaks) losing their curated CWE and
    severity on any rule id not individually listed.
    """
    std = _resolve("gitleaks", "some-rule-nobody-listed")

    assert std.canonical_cwe == "CWE-798"
    assert std.severity is Severity.CRITICAL


def test_scanner_label_lookup_is_case_insensitive():
    """The label is lowercased by `lookup`; 'Bandit' must resolve like 'bandit'."""
    assert _resolve("Bandit", "B608") == _resolve("bandit", "B608")


# --- OWASP interplay ----------------------------------------------------


def test_owasp_is_derived_from_the_cwe_when_the_map_has_none():
    """No map entry: OWASP comes from the winning CWE via `owasp_for_cwe`.

    Prevents a tool-supplied CWE-89 being filed with no OWASP bucket.
    """
    std = _resolve("nosuchscanner", "X1", scanner_cwe="CWE-89")

    assert std.owasp_top10 == owasp_for_cwe("CWE-89") == "A03"


def test_cwe_override_derives_owasp_from_the_override_not_from_the_map():
    """The derived OWASP follows the CWE that won, not the entry's CWE.

    Only a scanner with no curated OWASP exercises the derivation, so use a
    scanner with no map entry: override CWE-22 -> A01 while scanner_cwe
    (CWE-89 -> A03) must be ignored.
    """
    std = _resolve("nosuchscanner", "X1", cwe_override="CWE-22", scanner_cwe="CWE-89")

    assert std.canonical_cwe == "CWE-22"
    assert std.owasp_top10 == "A01"


def test_curated_owasp_wins_over_the_one_derived_from_an_overriding_cwe():
    """When the map carries an OWASP id it is kept even if the CWE is overridden.

    Documents the actual rule (`entry.owasp_top10 or owasp_for_cwe(...)`):
    B608 is A03 in the map; overriding to CWE-22 (A01 by derivation) keeps A03.
    The assertion that A01 differs guards against the test passing vacuously.
    """
    assert owasp_for_cwe("CWE-22") == "A01"  # the competing answer

    std = _resolve(cwe_override="CWE-22")

    assert std.canonical_cwe == "CWE-22"
    assert std.owasp_top10 == "A03"


def test_cwe_with_no_owasp_bucket_yields_none_not_a_guess():
    """CWE-703 belongs to no Top 10 category and must stay unmapped.

    Prevents a standard's name being put behind a claim it does not make
    (Bandit files assert_used under CWE-703).
    """
    assert owasp_for_cwe("CWE-703") is None  # premise

    std = _resolve("nosuchscanner", "X1", scanner_cwe="CWE-703")

    assert std.canonical_cwe == "CWE-703"
    assert std.owasp_top10 is None


def test_map_owasp_survives_when_the_map_has_no_cwe():
    """scorecard/* has OWASP A08 and no CWE: A08 must not be dropped.

    Prevents the OWASP being derived (and lost) only from the CWE when the map
    already stated one.
    """
    std = _resolve("scorecard", "Anything")

    assert std.canonical_cwe is None
    assert std.owasp_top10 == "A08"


# --- the rest of the entry ----------------------------------------------


def test_map_entry_supplies_asvs_ssdf_description_and_fix_hint():
    """Only the curated map carries ASVS, SSDF, short_desc and fix_hint."""
    entry = lookup("bandit", "B608")

    std = _resolve()

    assert std.asvs_section == entry.asvs_section == "V5.3.5"
    assert std.nist_ssdf == entry.nist_ssdf == "PW.5.1"
    assert std.short_desc == entry.short_desc and std.short_desc
    assert std.fix_hint == entry.fix_hint and std.fix_hint


def test_overrides_do_not_unlock_asvs_ssdf_or_hints_without_a_map_entry():
    """A CWE override cannot conjure ASVS/SSDF/hints that only the map holds."""
    std = _resolve("nosuchscanner", "X1", cwe_override="CWE-89")

    assert std.asvs_section is None
    assert std.nist_ssdf is None
    assert std.short_desc is None
    assert std.fix_hint is None


def test_scanner_severity_beats_the_map_default():
    """Scanner-emitted severity wins over the entry's default (HIGH here)."""
    assert lookup("bandit", "B608").severity is Severity.HIGH  # premise

    std = _resolve(severity=Severity.LOW)

    assert std.severity is Severity.LOW


def test_map_severity_and_confidence_apply_when_scanner_gives_none():
    std = _resolve()

    assert std.severity is Severity.HIGH
    assert std.confidence is Confidence.MEDIUM


def test_scanner_confidence_beats_the_map_default():
    """Confidence is overridable too; the map entry says MEDIUM, so HIGH proves it."""
    std = _resolve(confidence=Confidence.HIGH)

    assert std.confidence is Confidence.HIGH


def test_unmapped_finding_falls_back_to_medium_severity_and_confidence():
    """No entry and no scanner values: MEDIUM/MEDIUM, and the adapter's category."""
    std = _resolve("nosuchscanner", "X1", default_category=Category.SECRETS)

    assert std.severity is Severity.MEDIUM
    assert std.confidence is Confidence.MEDIUM
    assert std.category is Category.SECRETS


def test_category_precedence_explicit_then_map_then_adapter_default():
    """Explicit category > map category > adapter default.

    Gitleaks/* is SECRETS in the map; the adapter default is deliberately
    different so the map-over-default step is observable.
    """
    default = Category.CONFIG_IAC
    assert lookup("gitleaks", "r").category is Category.SECRETS  # premise

    from_map = _resolve("gitleaks", "r", default_category=default)
    explicit = _resolve("gitleaks", "r", category=Category.DEPENDENCIES, default_category=default)
    fallback = _resolve("nosuchscanner", "X1", default_category=default)

    assert from_map.category is Category.SECRETS
    assert explicit.category is Category.DEPENDENCIES
    assert fallback.category is default


def test_result_is_a_frozen_value():
    """_Standards is immutable so a resolved mapping cannot drift mid-build."""
    std = _resolve()

    assert isinstance(std, _Standards)
    with pytest.raises(AttributeError):
        std.canonical_cwe = "CWE-1"  # type: ignore[misc]


# --- Top 25 via the winning CWE (through _make_finding) -----------------


class _Builder(FindingConstruction):
    name = "bandit"
    binary = "bandit"


def _finding(builder=None, **extra) -> Finding:
    kwargs = {
        "rule_id": "B608",
        "message": "m",
        "file_path": Path("a.py"),
        "line_start": 3,
        "line_end": None,
        "code_snippet": "x",
    }
    kwargs.update(extra)
    return (builder or _Builder())._make_finding(**kwargs)


def test_top25_flag_follows_the_winning_cwe_not_the_losing_one():
    """cwe_top25 is computed from the CWE that won the precedence.

    B608 is CWE-89 (Top 25); overriding to CWE-703 (not Top 25) must clear it.
    Prevents the flag being computed from the map entry after an override.
    """
    assert _finding().cwe_top25 is True
    overridden = _finding(cwe_override="CWE-703")

    assert overridden.canonical_cwe == "CWE-703"
    assert overridden.cwe_top25 is False


def test_top25_flag_counts_a_child_cwe_via_its_parent():
    """CWE-95 is not listed but is a child of listed CWE-94 (bandit B102)."""
    finding = _finding(rule_id="B102")

    assert finding.canonical_cwe == "CWE-95"
    assert finding.cwe_top25 is True


# --- FindingConstruction ------------------------------------------------


def test_make_finding_uses_scanner_name_override_as_label_and_for_lookup():
    """`scanner_name` replaces `self.name` for the label AND the map lookup.

    Prevents a multi-source adapter (one class, several tools) attributing
    findings, or looking up standards, under the wrong scanner.
    """
    finding = _finding(rule_id="anything", scanner_name="gitleaks")

    assert finding.scanner == "gitleaks"
    assert finding.canonical_cwe == "CWE-798"


def test_make_finding_keeps_the_path_as_reported():
    """The path is not made relative here; `findings.anchor` owns that."""
    absolute = Path("/abs/elsewhere/a.py")

    assert _finding(file_path=absolute).file_path == absolute


def test_fingerprint_depends_on_the_resolved_cwe():
    """Fingerprints are built from the *resolved* CWE, so overrides re-key them.

    Prevents a finding's identity ignoring the standards mapping decided here.
    """
    assert _finding().fingerprint != _finding(cwe_override="CWE-79").fingerprint
    assert _finding().fingerprint == _finding().fingerprint


class _Hinted(FindingConstruction):
    name = "tool"
    binary = "tool-bin"
    install_hint = "pipx install tool"


def test_unavailable_finding_is_informational_and_carries_the_hint():
    """A missing tool is reported as informational with an actionable fix.

    Prevents an unresolvable scanner being scored as a vulnerability.
    """
    target = Path("/repo")

    finding = _Hinted()._unavailable_finding(target)

    assert finding.rule_id == "tool.tool_unavailable"
    assert finding.severity is Severity.INFORMATIONAL
    assert finding.category is Category.POLICY_DOCS
    assert finding.file_path == target
    assert finding.fingerprint == "unavailable.tool"
    assert finding.fix_hint is not None and "pipx install tool" in finding.fix_hint


def test_unavailable_fix_hint_defaults_to_installing_the_binary():
    """With no install_hint it names the binary and both escape hatches."""
    builder = _Builder()

    hint = builder.unavailable_fix_hint()

    assert hint.startswith("Install bandit")
    assert "scanners.bandit.command" in hint
    assert "--sarif-import" in hint
