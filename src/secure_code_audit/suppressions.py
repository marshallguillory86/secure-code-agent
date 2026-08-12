"""Suppressions loader — `.scignore.yaml`.

Schema:
  - file:     <single file path>     (optional)
    paths:    [<glob>, <glob>]       (optional — alternative to `file`)
    rule_id:  <rule id>              (required; "*" allowed only with file/paths)
    reason:   <non-empty string>     (required)
    expires:  <ISO date YYYY-MM-DD>  (required; max 365 days from today)

Wildcard rule (rule_id: "*") requires `file` or `paths` so an operator can't
disable a rule globally. Past-expiry entries become CRITICAL findings.

Entry schema (.scignore.yaml)::

    - rule_id: gitleaks.generic-api-key   # or "*" (then file/paths is required)
      reason: >-                           # required; why this is not a real finding
        ...
      expires: 2027-08-01                  # required; max 365 days out
      file: api/tests/x.py                 # optional path (suffix match)
      paths: ["api/**"]                    # optional fnmatch patterns
      fingerprint: 0aaa689f8a967d8c        # optional; 16 hex chars, from the report
      line: 18                             # optional; positive integer

`fingerprint` + `line` together pin an entry to ONE finding. Neither is sufficient alone for
secret findings: the fingerprint excludes the line (so reformatting does not break baseline
identity) and gitleaks reports REDACTED evidence, so two different secrets in one file share a
fingerprint. Unknown fields and malformed values are rejected rather than ignored — a typo must
not silently widen a suppression back to file+rule.
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

# Exactly the keys an entry may carry. Anything else is a typo or a misunderstanding, and both
# must fail loudly rather than degrade the entry to a broader match.
_ALLOWED_KEYS = frozenset({"rule_id", "reason", "expires", "file", "paths", "fingerprint", "line"})
_VALID_FINGERPRINT = re.compile(r"[0-9a-f]{16}")


@dataclass(frozen=True)
class SuppressionRule:
    rule_id: str
    reason: str
    expires: datetime.date
    file: str | None = None
    paths: tuple[str, ...] = field(default_factory=tuple)
    # Narrowing keys. A suppression keyed only to (file, rule) covers every present and future
    # finding of that rule in that file — a different secret, on a different line, hidden by a
    # reason that was never about it.
    #
    # `fingerprint` alone is NOT sufficient for secret findings and must not be sold as such:
    # Finding.make_fingerprint deliberately excludes the line number (so a reformat does not
    # break baseline identity) and gitleaks reports REDACTED evidence, so two different secrets
    # on different lines of the same file produce the SAME fingerprint. `line` is what separates
    # them. An audit demonstrated exactly that collision.
    fingerprint: str | None = None
    line: int | None = None

    def matches(self, finding: Finding) -> bool:
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        rel = finding.file_path.as_posix()
        if self.file is not None and self.file != rel and not rel.endswith(self.file):
            return False
        if self.fingerprint is not None and self.fingerprint != finding.fingerprint:
            return False
        if self.line is not None and self.line != finding.line_start:
            return False
        return not self.paths or any(fnmatch.fnmatch(rel, p) for p in self.paths)

    @property
    def expired(self) -> bool:
        return datetime.date.today() > self.expires


def load(path: Path) -> tuple[list[SuppressionRule], list[str]]:
    """Returns (rules, validation_errors). On a missing file, both are empty."""
    if not path.exists():
        return [], []
    try:
        import yaml  # pyyaml — only imported when a suppressions file is present
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

        # FAIL CLOSED on anything unrecognised or malformed. Silently ignoring a key means a
        # typo (`fingerpint:`) or an empty value quietly downgrades a narrow suppression back to
        # the broad file+rule form — restoring the blind spot the narrow keys exist to remove,
        # with the config still reading as if it were narrow.
        unknown = sorted(set(entry) - _ALLOWED_KEYS)
        if unknown:
            errors.append(
                f"{path}: entry #{i}: unknown field(s) {', '.join(unknown)}. "
                f"Allowed: {', '.join(sorted(_ALLOWED_KEYS))}."
            )
            continue

        file_v = entry.get("file")
        paths_v = entry.get("paths") or []
        if rule_id == "*" and not file_v and not paths_v:
            errors.append(f"{path}: entry #{i}: rule_id='*' requires `file` or `paths`.")
            continue

        fingerprint_v = entry.get("fingerprint")
        if "fingerprint" in entry and not _VALID_FINGERPRINT.fullmatch(str(fingerprint_v or "")):
            errors.append(
                f"{path}: entry #{i}: 'fingerprint' must be 16 hexadecimal characters "
                f"(got {fingerprint_v!r})."
            )
            continue

        line_v = entry.get("line")
        if "line" in entry and not (
            isinstance(line_v, int) and not isinstance(line_v, bool) and line_v > 0
        ):
            errors.append(
                f"{path}: entry #{i}: 'line' must be a positive integer (got {line_v!r})."
            )
            continue

        rules.append(
            SuppressionRule(
                rule_id=rule_id,
                reason=reason,
                expires=expires,
                file=str(file_v) if file_v else None,
                paths=tuple(str(p) for p in paths_v) if paths_v else (),
                fingerprint=str(fingerprint_v) if fingerprint_v else None,
                line=line_v if isinstance(line_v, int) else None,
            )
        )

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
            out.append(
                replace(
                    f,
                    suppressed=True,
                    suppression_note=f"{active.reason} (expires {active.expires.isoformat()})",
                )
            )
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
        out.append(
            Finding(
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
                    f'{r.expires.isoformat()}: "{r.reason}". Either fix the '
                    "underlying issue or extend `expires` with a fresh reason."
                ),
                short_desc="Expired suppression entry.",
                fix_hint="Address the original finding, or extend the suppression with operator approval.",
            )
        )
    return out
