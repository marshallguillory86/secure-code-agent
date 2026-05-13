"""Canonical Finding type — the lingua franca between scanners, scoring, and renderers.

Every scanner returns a list[Finding]. The scoring layer dedupes by `canonical_cwe`
+ `fingerprint`. Renderers consume the same dataclass — markdown, JSON, SARIF,
PR-comment, remediation prompt all read these fields directly.

See docs/design.md §4.3 for the rationale + field semantics.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


class Severity(str, enum.Enum):
    CRITICAL      = "critical"
    HIGH          = "high"
    MEDIUM        = "medium"
    LOW           = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse permissively — scanners use 'info', 'INFO', 'note', 'warning', etc."""
        normalized = value.strip().lower()
        return _SEVERITY_ALIASES.get(normalized, cls.INFORMATIONAL)

    @property
    def rank(self) -> int:
        """Higher = worse. For sorting."""
        return _SEVERITY_RANK[self]


_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical":      Severity.CRITICAL,
    "crit":          Severity.CRITICAL,
    "error":         Severity.HIGH,
    "high":          Severity.HIGH,
    "warning":       Severity.MEDIUM,
    "moderate":      Severity.MEDIUM,
    "medium":        Severity.MEDIUM,
    "med":           Severity.MEDIUM,
    "low":           Severity.LOW,
    "note":          Severity.LOW,
    "info":          Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "none":          Severity.INFORMATIONAL,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL:      5,
    Severity.HIGH:          4,
    Severity.MEDIUM:        3,
    Severity.LOW:           2,
    Severity.INFORMATIONAL: 1,
}


class Confidence(str, enum.Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"

    @classmethod
    def from_string(cls, value: str) -> "Confidence":
        normalized = (value or "").strip().lower()
        if normalized in ("high", "h"):
            return cls.HIGH
        if normalized in ("medium", "med", "m"):
            return cls.MEDIUM
        if normalized in ("low", "l"):
            return cls.LOW
        return cls.MEDIUM   # default when scanner doesn't emit confidence


class Category(str, enum.Enum):
    SECRETS               = "secrets"
    DEPENDENCIES          = "dependencies"
    CODE_VULNERABILITIES  = "code_vulnerabilities"
    AUTH_AUTHZ            = "auth_authz"
    CRYPTO                = "crypto"
    SUPPLY_CHAIN          = "supply_chain"
    CONFIG_IAC            = "config_iac"
    LOGGING_OBSERVABILITY = "logging_observability"
    POLICY_DOCS           = "policy_docs"


@dataclass(frozen=True)
class Finding:
    """A normalized security finding."""

    # --- identity ----------------------------------------------------------
    rule_id:       str          # scanner-local id (e.g. "B608", "generic.sql.tainted")
    scanner:       str          # which scanner emitted it
    fingerprint:   str          # stable id for baseline + dedupe

    # --- standards taxonomy (any/all may be None when unmapped) ------------
    canonical_cwe: Optional[str]  # e.g. "CWE-89" — primary dedupe key
    owasp_top10:   Optional[str]  # e.g. "A03:2021-Injection"
    asvs_section:  Optional[str]  # e.g. "V5.3"
    nist_ssdf:     Optional[str]  # e.g. "PW.5.1"
    category:      Category

    # --- severity ----------------------------------------------------------
    severity:   Severity
    confidence: Confidence

    # --- locus -------------------------------------------------------------
    file_path:    Path
    line_start:   int
    line_end:     Optional[int]
    code_snippet: Optional[str]

    # --- human-readable ----------------------------------------------------
    message:    str
    short_desc: Optional[str]   = None
    full_desc:  Optional[str]   = None
    fix_hint:   Optional[str]   = None
    references: tuple[str, ...] = field(default_factory=tuple)

    # --- lifecycle ---------------------------------------------------------
    suppressed:       bool          = False
    suppression_note: Optional[str] = None
    is_new:           bool          = False   # not in baseline

    # --- flags -------------------------------------------------------------
    cwe_top25: bool = False         # set by scoring layer

    # ------------------------------------------------------------------ ctor
    @staticmethod
    def make_fingerprint(
        *,
        canonical_cwe: Optional[str],
        rule_id:       str,
        file_path:     Path,
        code_snippet:  Optional[str],
    ) -> str:
        """Stable 16-hex-char fingerprint for dedupe + baseline.

        Inputs:
          - canonical_cwe falls back to rule_id when no CWE is mapped (so
            unmapped findings still dedupe per-rule).
          - file_path is POSIX-normalized for cross-platform stability.
          - code_snippet is normalized (whitespace collapsed, max 512 chars)
            so a reformat-only edit doesn't break the fingerprint.
        """
        key = canonical_cwe or rule_id
        path = file_path.as_posix()
        snippet_norm = (
            " ".join((code_snippet or "").split())[:512]
        )
        material = f"{key}|{path}|{snippet_norm}".encode()
        return hashlib.sha256(material).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def severity_at_or_above(target: Severity) -> set[Severity]:
    """Return the set of severities >= target. Useful for gate filters."""
    return {s for s in Severity if s.rank >= target.rank}
