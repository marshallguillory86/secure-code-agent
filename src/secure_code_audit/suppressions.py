"""Suppressions loader — `.scignore.yaml`.

Schema:
  - file:     <single file path>     (optional)
    paths:    [<glob>, <glob>]       (optional — alternative to `file`)
    rule_id:  <rule id>              (required; "*" allowed only with file/paths)
    reason:   <non-empty string>     (required)
    expires:  <ISO date YYYY-MM-DD>  (required; max 365 days from today)

Wildcard rule (rule_id: "*") requires `file` or `paths` so an operator can't
disable a rule globally. Past-expiry entries become CRITICAL findings.
"""
from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Finding, Severity

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_TTL_DAYS = 365


@dataclass(frozen=True)
class SuppressionRule:
    rule_id:     str
    reason:      str
    expires:     datetime.date
    file:        str | None         = None
    paths:       tuple[str, ...]    = field(default_factory=tuple)

    def matches(self, finding: Finding) -> bool:
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        rel = finding.file_path.as_posix()
        if self.file is not None and self.file != rel and not rel.endswith(self.file):
            return False
        if self.paths:
            if not any(fnmatch.fnmatch(rel, p) for p in self.paths):
                return False
        return True

    @property
    def expired(self) -> bool:
        return datetime.date.today() > self.expires


def load(path: Path) -> tuple[list[SuppressionRule], list[str]]:
    """Returns (rules, validation_errors). On a missing file, both are empty."""
    if not path.exists():
        return [], []
    try:
        import yaml   # pyyaml — only imported when a suppressions file is present
    except ImportError:
        return [], [f"{path}: pyyaml not installed — `pip install pyyaml` to use .scignore.yaml"]

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except yaml.YAMLError as e:
        return [], [f"{path}: YAML parse error: {e}"]

    if not isinstance(raw, list):
        return [], [f"{path}: top-level must be a list of suppression entries."]

    rules: list[SuppressionRule] = []
    errors: list[str] = []
    today = datetime.date.today()

    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"{path}: entry #{i}: must be a mapping.")
            continue
        rule_id = str(entry.get("rule_id", "")).strip()
        if not rule_id:
            errors.append(f"{path}: entry #{i}: 'rule_id' is required.")
            continue
        reason = str(entry.get("reason", "")).strip()
        if not reason:
            errors.append(f"{path}: entry #{i}: 'reason' is required (non-empty).")
            continue
        expires_raw = str(entry.get("expires", "")).strip()
        if not _DATE_RE.match(expires_raw):
            errors.append(f"{path}: entry #{i}: 'expires' is required as YYYY-MM-DD.")
            continue
        try:
            expires = datetime.date.fromisoformat(expires_raw)
        except ValueError:
            errors.append(f"{path}: entry #{i}: 'expires' not parseable.")
            continue
        if (expires - today).days > _MAX_TTL_DAYS:
            errors.append(
                f"{path}: entry #{i}: 'expires' must be within {_MAX_TTL_DAYS} days "
                f"(got {(expires - today).days} days out)."
            )
            continue

        file_v = entry.get("file")
        paths_v = entry.get("paths") or []
        if rule_id == "*" and not file_v and not paths_v:
            errors.append(
                f"{path}: entry #{i}: rule_id='*' requires `file` or `paths`."
            )
            continue

        rules.append(SuppressionRule(
            rule_id=rule_id,
            reason=reason,
            expires=expires,
            file=str(file_v) if file_v else None,
            paths=tuple(str(p) for p in paths_v) if paths_v else (),
        ))

    return rules, errors


def apply(findings: list[Finding], rules: list[SuppressionRule]) -> list[Finding]:
    """Mark matching findings as suppressed (set suppressed=True + note).
    Expired rules do NOT suppress — but generate their own findings via
    `expired_findings()`. Returns a new list (frozen dataclass replace)."""
    from dataclasses import replace
    out: list[Finding] = []
    for f in findings:
        active = next((r for r in rules if not r.expired and r.matches(f)), None)
        if active is not None:
            out.append(replace(
                f,
                suppressed=True,
                suppression_note=f"{active.reason} (expires {active.expires.isoformat()})",
            ))
        else:
            out.append(f)
    return out


def expired_findings(rules: list[SuppressionRule], path: Path) -> list[Finding]:
    """One CRITICAL finding per expired suppression — you can't ship
    `reason: 'we'll fix it later'` forever."""
    out: list[Finding] = []
    for r in rules:
        if not r.expired:
            continue
        rid = f"suppressions.expired.{r.rule_id}"
        snippet = f"rule_id: {r.rule_id}; expired {r.expires.isoformat()}; reason: {r.reason}"
        out.append(Finding(
            rule_id=rid,
            scanner="suppressions",
            fingerprint=Finding.make_fingerprint(
                canonical_cwe=None,
                rule_id=rid,
                file_path=path,
                code_snippet=snippet,
            ),
            canonical_cwe=None,
            owasp_top10=None,
            asvs_section=None,
            nist_ssdf="PO.4.1",
            category=Category.POLICY_DOCS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=path,
            line_start=0,
            line_end=None,
            code_snippet=snippet,
            message=(
                f"Suppression for rule `{r.rule_id}` expired on "
                f"{r.expires.isoformat()}: \"{r.reason}\". Either fix the "
                "underlying issue or extend `expires` with a fresh reason."
            ),
            short_desc="Expired suppression entry.",
            fix_hint="Address the original finding, or extend the suppression with operator approval.",
        ))
    return out
