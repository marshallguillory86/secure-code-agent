"""Canonical Finding type — the lingua franca between scanners, scoring, and renderers.

Every scanner returns a list[Finding]. Stable fingerprints support baseline
matching. `merge_corroborating` collapses repeat reports of one weakness at
one line — two checks agreeing is one finding with two witnesses, not two
findings — and records the witnesses rather than dropping them.
Renderers consume the same dataclass — markdown, JSON, SARIF,
PR-comment, remediation prompt all read these fields directly.

See docs/design.md §4.3 for the rationale + field semantics.
"""

from __future__ import annotations

import enum
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse permissively — scanners use 'info', 'INFO', 'note', 'warning', etc."""
        normalized = value.strip().lower()
        return _SEVERITY_ALIASES.get(normalized, cls.INFORMATIONAL)

    @property
    def rank(self) -> int:
        """Higher = worse. For sorting."""
        return _SEVERITY_RANK[self]


_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "error": Severity.HIGH,
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_string(cls, value: str) -> Confidence:
        normalized = (value or "").strip().lower()
        if normalized in ("high", "h"):
            return cls.HIGH
        if normalized in ("medium", "med", "m"):
            return cls.MEDIUM
        if normalized in ("low", "l"):
            return cls.LOW
        return cls.MEDIUM  # default when scanner doesn't emit confidence

    @property
    def rank(self) -> int:
        """Higher = more certain. For choosing between duplicate reports."""
        return CONFIDENCE_RANK[self]


CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


class Category(str, enum.Enum):
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    CODE_VULNERABILITIES = "code_vulnerabilities"
    AUTH_AUTHZ = "auth_authz"
    CRYPTO = "crypto"
    SUPPLY_CHAIN = "supply_chain"
    CONFIG_IAC = "config_iac"
    LOGGING_OBSERVABILITY = "logging_observability"
    POLICY_DOCS = "policy_docs"


@dataclass(frozen=True)
class Finding:
    """A normalized security finding."""

    # --- identity ----------------------------------------------------------
    rule_id: str  # scanner-local id (e.g. "B608", "generic.sql.tainted")
    scanner: str  # which scanner emitted it
    fingerprint: str  # stable id for baseline identity

    # --- standards taxonomy (any/all may be None when unmapped) ------------
    canonical_cwe: str | None  # e.g. "CWE-89" — stable fingerprint input
    owasp_top10: str | None  # e.g. "A03:2021-Injection"
    asvs_section: str | None  # e.g. "V5.3"
    nist_ssdf: str | None  # e.g. "PW.5.1"
    category: Category

    # --- severity ----------------------------------------------------------
    severity: Severity
    confidence: Confidence

    # --- locus -------------------------------------------------------------
    file_path: Path
    line_start: int
    line_end: int | None
    code_snippet: str | None

    # --- human-readable ----------------------------------------------------
    message: str
    short_desc: str | None = None
    full_desc: str | None = None
    fix_hint: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    # --- lifecycle ---------------------------------------------------------
    suppressed: bool = False
    suppression_note: str | None = None
    is_new: bool = False  # not in baseline

    # --- flags -------------------------------------------------------------
    cwe_top25: bool = False  # set by scoring layer

    #: Other `scanner:rule_id` pairs that reported this same weakness at this
    #: same line, folded in by `merge_corroborating`. Empty for the common
    #: case of one check firing once. Non-empty is *stronger* evidence, not
    #: weaker — two independent checks agreeing is worth saying out loud —
    #: which is why they are recorded here rather than discarded.
    corroborated_by: tuple[str, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------------ ctor
    @staticmethod
    def make_fingerprint(
        *,
        canonical_cwe: str | None,
        rule_id: str,
        file_path: Path,
        code_snippet: str | None,
    ) -> str:
        """Stable 16-hex-char fingerprint for baseline identity.

        Inputs:
          - canonical_cwe falls back to rule_id when no CWE is mapped (so
            unmapped findings still remain distinct per rule).
          - file_path is POSIX-normalized for cross-platform stability.
          - code_snippet is normalized (whitespace collapsed, max 512 chars)
            so a reformat-only edit doesn't break the fingerprint.
        """
        key = canonical_cwe or rule_id
        path = file_path.as_posix()
        snippet_norm = " ".join((code_snippet or "").split())[:512]
        material = f"{key}|{path}|{snippet_norm}".encode()
        return hashlib.sha256(material).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def severity_at_or_above(target: Severity) -> set[Severity]:
    """Return the set of severities >= target. Useful for gate filters."""
    return {s for s in Severity if s.rank >= target.rank}


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------

#: Scanner rules that are the same check under two ids. Bandit ships
#: `mark_safe` (B308) as a generic blacklist call *and* `django_mark_safe`
#: (B703) as a Django-specific plugin; both fire on the same expression. Across
#: the calibration corpus Django carried 56 B703 and 51 B308 findings that
#: shared 50 lines — a third of its reported code findings were one issue
#: counted twice.
#:
#: Keyed by `scanner`, mapping the alias to the id kept. Deliberately a short
#: hand-checked table rather than a heuristic: two rules firing on one line
#: usually means two different weaknesses, and collapsing those would hide
#: findings rather than tidy them.
RULE_ALIASES: dict[str, dict[str, str]] = {
    "bandit": {"B703": "B308"},
}


def _canonical_rule(finding: Finding) -> str:
    """A rule id with aliases resolved, scoped to its scanner."""
    alias = RULE_ALIASES.get(finding.scanner, {})
    return f"{finding.scanner}:{alias.get(finding.rule_id, finding.rule_id)}"


def _same_weakness(a: Finding, b: Finding) -> bool:
    """Are these two reports of one weakness, or two weaknesses at one line?

    Two conditions, and a CWE match alone is not enough.

    **Two different rules from the same scanner are two different checks.**
    Bandit files `B602` (shell=True), `B603` (subprocess call) and `B607`
    (partial executable path) all under CWE-78, and they are not the same
    finding: one is fixed with an argument list, one with an absolute path.
    Keying on the CWE merged them and the work order lost a finding: a
    one-line shell-enabled subprocess call reported `B607` alone, with the
    more serious `B602` hidden inside it as a footnote.

    (The example is described rather than quoted. Writing the offending
    call out verbatim put a real `B602` on the primary axis of this file
    and failed the repository's own gate — the second time in two days that
    documenting a vulnerable pattern created one. Prose is scanned too.)

    An earlier test asserted exactly this must not happen and passed anyway,
    because its fixtures carried no CWE. Reading Bandit's CWEs gave them one
    and turned a passing test into a false assurance.

    So: the same scanner merges only through the hand-checked alias table.
    Different scanners merge on a shared CWE, which is the corroboration
    this function exists for — bandit and our own rule catching one
    `shell=True` is one finding with two witnesses.
    """
    if a.file_path != b.file_path or a.line_start != b.line_start:
        return False
    if a.scanner == b.scanner:
        return _canonical_rule(a) == _canonical_rule(b)
    return bool(a.canonical_cwe) and a.canonical_cwe == b.canonical_cwe


def _merge_key(finding: Finding) -> tuple:
    """What makes two reports the same report.

    **The alias table outranks the CWE.** Two rules declared aliases of each
    other are the same check, whatever CWEs upstream files them under, and
    upstream does not always agree with itself: Bandit files `mark_safe` as
    CWE-79 under B308 and CWE-80 under B703 — cross-site scripting and
    "improper neutralization of script-related tags", two names for one
    check firing on one expression.

    That ordering was the other way round and it silently undid this whole
    function. The alias table worked only while Bandit's CWEs were being
    discarded; the moment they were read, every aliased pair acquired two
    different CWEs and stopped merging. Django went back to counting
    `mark_safe` twice — 56 B703 and 51 B308 over 50 shared lines — and the
    corpus caught it, not the unit tests, which pin behaviour for rules that
    have no CWE.

    Otherwise the CWE is the discriminator: two checks at one line with
    different CWEs are two weaknesses and both are kept. With no CWE and no
    alias entry we do not know they are the same, so nothing merges.
    """
    alias = RULE_ALIASES.get(finding.scanner, {})
    if finding.rule_id in alias or finding.rule_id in set(alias.values()):
        discriminator = f"{finding.scanner}:{alias.get(finding.rule_id, finding.rule_id)}"
    else:
        discriminator = finding.canonical_cwe or f"{finding.scanner}:{finding.rule_id}"
    return (finding.file_path.as_posix(), finding.line_start, discriminator)


def merge_corroborating(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse repeat reports of one weakness, keeping the strongest.

    Order is preserved and the first report of each weakness is the one kept,
    raised to the highest severity and confidence anything reported for it,
    with every other `scanner:rule_id` recorded in `corroborated_by`.

    This is a reporting-correctness fix, not a scoring one. Measured across
    the corpus it moved no repository's grade: Django, the only one with a
    meaningful number of duplicates, was already clamped at 0. It matters
    because a report that lists one line twice is wrong about the code, and
    a work order derived from it would ask for the same fix twice.
    """
    # Keyed by line so the pairwise test only runs against plausible
    # neighbours; `_same_weakness` decides the rest.
    by_line: dict[tuple, list[int]] = {}
    kept: list[Finding] = []
    witnesses: list[list[str]] = []

    for finding in findings:
        locus = (finding.file_path.as_posix(), finding.line_start)
        slot = None
        for index in by_line.get(locus, []):
            if _same_weakness(kept[index], finding):
                slot = index
                break
        if slot is None:
            by_line.setdefault(locus, []).append(len(kept))
            kept.append(finding)
            witnesses.append([])
            continue
        label = f"{finding.scanner}:{finding.rule_id}"
        existing = kept[slot]
        if label not in witnesses[slot] and label != f"{existing.scanner}:{existing.rule_id}":
            witnesses[slot].append(label)
        if finding.severity.rank > existing.severity.rank or (
            finding.severity.rank == existing.severity.rank
            and CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[existing.confidence]
        ):
            kept[slot] = finding

    return [
        replace(f, corroborated_by=tuple(seen)) if seen else f
        for f, seen in zip(kept, witnesses, strict=True)
    ]
