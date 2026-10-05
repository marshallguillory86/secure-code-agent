"""Turning scanner-emitted bits into a canonical `Finding`.

Split out of `Scanner`, the third of its four jobs. `_make_finding` was also
a hotspot in its own right — 85 lines against an 80 limit, complexity 17
against 15 — and almost all of that was one decision repeated nine times:
which of three sources to believe about a finding's standards mapping. That
decision now lives in `_resolve_standards`, which makes it reviewable on its
own, and leaves `_make_finding` as what it says it is: a constructor.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.standards import (
    StandardsEntry,
    is_top25,
    lookup,
    overlay_for,
    owasp_for_cwe,
)


@dataclass(frozen=True, slots=True)
class _Standards:
    """The standards mapping for one finding, after all three sources are weighed."""

    canonical_cwe: str | None
    owasp_top10: str | None
    asvs_section: str | None
    nist_ssdf: str | None
    category: Category
    severity: Severity
    confidence: Confidence
    short_desc: str | None
    fix_hint: str | None


def _resolve_standards(
    scanner_label: str,
    rule_id: str,
    *,
    cwe_override: str | None,
    scanner_cwe: str | None,
    category: Category | None,
    severity: Severity | None,
    confidence: Confidence | None,
    default_category: Category,
) -> _Standards:
    """Weigh the curated map, the adapter and the tool against each other.

    Scanner-emitted severity wins over the map's default; confidence falls
    back to the map; category is set per the map unless explicitly
    overridden.

    Three sources of a CWE, in descending authority:

    `cwe_override` is the adapter asserting it knows better than both the
    map and the tool — Semgrep uses it, because a Semgrep rule's own
    metadata is more specific than anything we could curate for it.

    The curated `_MAP` comes next. It is reviewed, and it is the only
    source that also carries OWASP, ASVS, SSDF and a fix hint.

    `scanner_cwe` is the last resort: what the tool said about its own
    rule. Bandit publishes a CWE for every plugin and gosec for every
    rule, and we were discarding both — 86% of real corpus findings
    carried no CWE at all while the README led with "Anchored to NIST
    SSDF · OWASP ASVS · OWASP Top 10 · MITRE CWE Top 25". It ranks below
    the curated map because upstream picks a defensible CWE rather than
    the most specific one (Bandit files `assert_used` under CWE-703,
    "improper check for unusual conditions"), but a defensible CWE beats
    none.
    """
    entry: StandardsEntry | None = lookup(scanner_label, rule_id)
    # The operator's overlay sits between the adapter and the curated table,
    # and only for the standards fields. It cannot reach severity, confidence
    # or category — those are the scoring inputs, and an overlay that set them
    # could move the grade the way an in-tree `severity_overrides` did before
    # D32. §8 question 3 is why it exists at all.
    extra = overlay_for(scanner_label, rule_id)

    def mapped(field: str) -> str | None:
        """The operator's value for a standards field, then the curated one.

        One helper rather than `(extra.x if extra else None) or (entry.x if
        entry else None)` written six times: that spelling put this function
        at cognitive complexity 17, and six copies of a precedence rule is
        six places for it to drift.
        """
        return getattr(extra, field, None) or getattr(entry, field, None)

    # Mapping fallback to wildcard (handled inside lookup and overlay_for).
    canonical_cwe = cwe_override or mapped("canonical_cwe") or scanner_cwe
    # An override decides the OWASP category too, because a CWE and an OWASP
    # id that disagree describe two different defects. This was
    # `entry.owasp_top10 or owasp_for_cwe(...)` unconditionally, so a Semgrep
    # rule asserting CWE-22 against B608 produced CWE-22 with A03 — path
    # traversal filed under Injection. An adapter overriding the CWE is
    # asserting the weakness, not just its number.
    #
    # No fallback to the curated id when the override maps to no bucket: that
    # id describes the CWE the override just replaced, so it would reinstate
    # the same incoherence. None means "no Top 10 category", which is the
    # honest answer. D31, and docs/product-intent.md §8 question 9.
    derived = owasp_for_cwe(canonical_cwe)
    owasp_top10 = derived if cwe_override else mapped("owasp_top10") or derived
    return _Standards(
        canonical_cwe=canonical_cwe,
        owasp_top10=owasp_top10,
        asvs_section=mapped("asvs_section"),
        nist_ssdf=mapped("nist_ssdf"),
        # Scoring inputs. The overlay is deliberately absent from these three
        # lines, and that absence is the whole of D32's scope note.
        category=category or (entry.category if entry else default_category),
        severity=severity or (entry.severity if entry else Severity.MEDIUM),
        confidence=confidence or (entry.confidence if entry else Confidence.MEDIUM),
        short_desc=mapped("short_desc"),
        fix_hint=mapped("fix_hint"),
    )


class FindingConstruction:
    """Building findings — the scanner's own, and the ones about the scanner.

    A mixin of `Scanner`; `name` comes from there.
    """

    name: str  # supplied by Scanner
    binary: str  # name of the executable on PATH
    default_category: Category = Category.CODE_VULNERABILITIES
    # How an operator obtains this scanner. Surfaced in the unavailable
    # finding and in --preflight. The agent never installs anything itself.
    install_hint: str = ""

    def _make_finding(
        self,
        *,
        rule_id: str,
        message: str,
        file_path: Path,
        line_start: int,
        line_end: int | None,
        code_snippet: str | None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        category: Category | None = None,
        cwe_override: str | None = None,
        scanner_cwe: str | None = None,
        scanner_name: str | None = None,
    ) -> Finding:
        """Construct a canonical Finding, layering in the standards mapping.

        `_resolve_standards` decides which source to believe for the CWE and
        the severity; see it for the precedence and why it is that way.
        """
        scanner_label = scanner_name or self.name
        std = _resolve_standards(
            scanner_label,
            rule_id,
            cwe_override=cwe_override,
            scanner_cwe=scanner_cwe,
            category=category,
            severity=severity,
            confidence=confidence,
            default_category=self.default_category,
        )

        # The path is kept as the tool reported it. `findings.anchor` makes it
        # repository-relative for every adapter and every SARIF import at once;
        # doing it here as well was how two conventions came to coexist.
        fingerprint = Finding.make_fingerprint(
            canonical_cwe=std.canonical_cwe,
            rule_id=rule_id,
            file_path=file_path,
            code_snippet=code_snippet,
        )

        return Finding(
            rule_id=rule_id,
            scanner=scanner_label,
            fingerprint=fingerprint,
            canonical_cwe=std.canonical_cwe,
            owasp_top10=std.owasp_top10,
            asvs_section=std.asvs_section,
            nist_ssdf=std.nist_ssdf,
            category=std.category,
            severity=std.severity,
            confidence=std.confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            message=message,
            short_desc=std.short_desc,
            fix_hint=std.fix_hint,
            cwe_top25=is_top25(std.canonical_cwe),
        )

    def _dependency_finding(
        self, rule_id: str, message: str, manifest: Path, severity: Severity
    ) -> Finding:
        """A dependency advisory, reported against the manifest that pins it.

        Four sites across `npm_audit`, `osv_scanner` and `pip_audit` built
        this with the same seven fixed arguments — a 27-line duplicate block
        that MA named, and the kind where fixing one and missing another is
        the whole risk. The category especially: `DEPENDENCIES` is what takes
        these off the code-condition score and onto their own axis (a CVE in
        a pinned dependency is fixed with a version bump; an injection flaw
        is fixed with a rewrite), so a site that drifted out of it would be
        silently scored as shipped code.

        Line 0 and no snippet are deliberate, not placeholders: the defect is
        the *pinned version* in the manifest, not a line of our source, and a
        snippet would quote a lockfile entry rather than anything an operator
        edits. HIGH confidence because the scanner matched a package version
        against an advisory database — there is no heuristic in it.
        """
        return self._make_finding(
            rule_id=rule_id,
            message=message,
            file_path=manifest,
            line_start=0,
            line_end=None,
            code_snippet=None,
            severity=severity,
            confidence=Confidence.HIGH,
            category=Category.DEPENDENCIES,
        )

    def _unavailable_finding(self, target: Path) -> Finding:
        """Informational finding emitted when no safe command can be resolved."""
        return Finding(
            rule_id=f"{self.name}.tool_unavailable",
            scanner=self.name,
            fingerprint=f"unavailable.{self.name}",
            canonical_cwe=None,
            owasp_top10=None,
            asvs_section=None,
            nist_ssdf=None,
            category=Category.POLICY_DOCS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            message=(
                f"Could not resolve {self.name} from its configured command, PATH, "
                "or supported Python module fallback; scan skipped."
            ),
            short_desc=None,
            fix_hint=self.unavailable_fix_hint(),
        )

    def unavailable_fix_hint(self) -> str:
        """Operator-actionable text for a scanner that could not be resolved."""
        install = self.install_hint or f"Install {self.binary}"
        return (
            f"{install}, or set scanners.{self.name}.command to an explicit path, "
            "or supply its SARIF via --sarif-import."
        )
