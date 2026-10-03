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
      paths: ["api/"]                      # optional; exclude_patterns syntax, repository-relative
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
from secure_code_audit.git_tools import matches_pattern

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

    def matches(self, finding: Finding, root: Path | None = None) -> bool:
        """Does this entry cover `finding`?

        `finding.file_path` is repository-relative (`findings.anchor`), which is
        what an entry names. Through 0.12.1 it was absolute for most scanners, so
        a `paths:` glob written relative never matched and entries grew a `*/`
        prefix to swallow the checkout directory. Those entries keep working
        without depending on where the checkout lives: a glob is also tried
        against the path with a leading `/`, and `*/src/app.py` matches
        `/src/app.py`. `root` lets an absolute `file:` and a fingerprint
        recorded by an earlier release keep matching the finding they named.

        **A `paths:` glob is an exclude pattern (D21).** It is matched by
        `git_tools.matches_pattern`, the matcher `exclude_patterns` uses, so a
        trailing slash means "this directory, at any depth" and a bare name
        matches at any depth. Through 0.12.2 it was bare `fnmatch`, under which
        `paths: ["tests/"]` — the example README, `design.md` and the skill all
        show — matched nothing.
        """
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        rel = finding.file_path.as_posix()
        if self.file is not None and not self._names_file(rel, finding, root):
            return False
        if self.fingerprint is not None and self.fingerprint not in _identities(finding, root):
            return False
        if self.line is not None and self.line != finding.line_start:
            return False
        return not self.paths or any(
            matches_pattern(rel, p) or fnmatch.fnmatch(f"/{rel}", p) for p in self.paths
        )

    def _names_file(self, rel: str, finding: Finding, root: Path | None) -> bool:
        if self.file == rel or rel.endswith(self.file):
            return True
        named = Path(self.file)
        return root is not None and named.is_absolute() and named == root / finding.file_path

    @property
    def expired(self) -> bool:
        return datetime.date.today() > self.expires


@dataclass(frozen=True, slots=True)
class _Required:
    """The three fields every entry must carry, validated."""

    rule_id: str
    reason: str
    expires: datetime.date


@dataclass(frozen=True, slots=True)
class _Narrow:
    """The optional keys that narrow a suppression, validated."""

    file: str | None
    paths: tuple[str, ...]
    fingerprint: str | None
    line: int | None


def _parse_document(path: Path) -> tuple[list, str | None]:
    """The file as a list of entries, or the one error that stopped it.

    An absent file is not an error — it yields no entries and no error, so
    the caller's loop runs zero times rather than branching on it.
    """
    if not path.exists():
        return [], None
    try:
        import yaml  # pyyaml — only imported when a suppressions file is present
    except ImportError:
        return [], f"{path}: pyyaml not installed — `pip install pyyaml` to use .scignore.yaml"

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except (yaml.YAMLError, ValueError) as e:
        # `ValueError` alongside `YAMLError`, because PyYAML lets one out.
        #
        # An unquoted `expires: 2027-02-30` is a YAML *timestamp*, and
        # `construct_yaml_timestamp` raises a plain `ValueError` ("day is out
        # of range for month") rather than a `YAMLError`. It therefore escaped
        # this handler entirely, left `load`, and surfaced through the CLI's
        # blanket `except ValueError` as a bare "ERROR: day is out of range
        # for month" — no file, no entry number, none of the fail-closed
        # wording every other malformed entry gets.
        #
        # Quote the same typo and it was reported properly, so whether an
        # operator could diagnose their own file depended on whether they
        # happened to use quotes. This contract says `load` returns
        # `(rules, errors)`; it does not say it raises.
        return [], f"{path}: YAML parse error: {e}"

    if not isinstance(raw, list):
        return [], f"{path}: top-level must be a list of suppression entries."
    return raw, None


def _required_fields(
    prefix: str, entry: dict, today: datetime.date
) -> tuple[_Required | None, str | None]:
    """`rule_id`, `reason` and a bounded `expires`, or the first failure."""
    rule_id = str(entry.get("rule_id", "")).strip()
    if not rule_id:
        return None, f"{prefix}: 'rule_id' is required."
    reason = str(entry.get("reason", "")).strip()
    if not reason:
        return None, f"{prefix}: 'reason' is required (non-empty)."
    expires_raw = str(entry.get("expires", "")).strip()
    if not _DATE_RE.match(expires_raw):
        return None, f"{prefix}: 'expires' is required as YYYY-MM-DD."
    try:
        expires = datetime.date.fromisoformat(expires_raw)
    except ValueError:
        return None, f"{prefix}: 'expires' not parseable."
    if (expires - today).days > _MAX_TTL_DAYS:
        return None, (
            f"{prefix}: 'expires' must be within {_MAX_TTL_DAYS} days "
            f"(got {(expires - today).days} days out)."
        )
    return _Required(rule_id=rule_id, reason=reason, expires=expires), None


def _narrow_keys(prefix: str, entry: dict, rule_id: str) -> tuple[_Narrow | None, str | None]:
    """The narrowing keys, or the first failure.

    FAIL CLOSED on anything unrecognised or malformed. Silently ignoring a key means a
    typo (`fingerpint:`) or an empty value quietly downgrades a narrow suppression back to
    the broad file+rule form — restoring the blind spot the narrow keys exist to remove,
    with the config still reading as if it were narrow.
    """
    unknown = sorted(set(entry) - _ALLOWED_KEYS)
    if unknown:
        return None, (
            f"{prefix}: unknown field(s) {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(_ALLOWED_KEYS))}."
        )

    file_v = entry.get("file")
    paths_v = entry.get("paths") or []
    if rule_id == "*" and not file_v and not paths_v:
        return None, f"{prefix}: rule_id='*' requires `file` or `paths`."

    fingerprint_v = entry.get("fingerprint")
    if "fingerprint" in entry and not _VALID_FINGERPRINT.fullmatch(str(fingerprint_v or "")):
        return None, (
            f"{prefix}: 'fingerprint' must be 16 hexadecimal characters (got {fingerprint_v!r})."
        )

    line_v = entry.get("line")
    if "line" in entry and not (
        isinstance(line_v, int) and not isinstance(line_v, bool) and line_v > 0
    ):
        return None, f"{prefix}: 'line' must be a positive integer (got {line_v!r})."

    return (
        _Narrow(
            file=str(file_v) if file_v else None,
            paths=tuple(str(p) for p in paths_v) if paths_v else (),
            fingerprint=str(fingerprint_v) if fingerprint_v else None,
            line=line_v if isinstance(line_v, int) else None,
        ),
        None,
    )


def _rule_from_entry(
    prefix: str, entry: dict, today: datetime.date
) -> tuple[SuppressionRule | None, str | None]:
    """One validated rule, or the first reason this entry is refused."""
    required, error = _required_fields(prefix, entry, today)
    if required is None:
        return None, error
    narrow, error = _narrow_keys(prefix, entry, required.rule_id)
    if narrow is None:
        return None, error
    return (
        SuppressionRule(
            rule_id=required.rule_id,
            reason=required.reason,
            expires=required.expires,
            file=narrow.file,
            paths=narrow.paths,
            fingerprint=narrow.fingerprint,
            line=narrow.line,
        ),
        None,
    )


def load(path: Path) -> tuple[list[SuppressionRule], list[str]]:
    """Returns (rules, validation_errors). On a missing file, both are empty."""
    entries, error = _parse_document(path)
    if error is not None:
        return [], [error]

    rules: list[SuppressionRule] = []
    errors: list[str] = []
    today = datetime.date.today()

    for i, entry in enumerate(entries):
        prefix = f"{path}: entry #{i}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: must be a mapping.")
            continue
        rule, error = _rule_from_entry(prefix, entry, today)
        if rule is None:
            errors.append(error)
        else:
            rules.append(rule)

    return rules, errors


def _identities(finding: Finding, root: Path | None) -> set[str]:
    """The fingerprint, plus the one 0.12.1 and earlier recorded for it."""
    if root is None:
        return {finding.fingerprint}
    return {finding.fingerprint, finding.legacy_fingerprint(root)}


def apply(
    findings: list[Finding], rules: list[SuppressionRule], root: Path | None = None
) -> list[Finding]:
    """Mark matching findings as suppressed (set suppressed=True + note).
    Expired rules do NOT suppress — but generate their own findings via
    `expired_findings()`. Returns a new list (frozen dataclass replace).

    `root` is the repository root the finding paths are relative to."""
    from dataclasses import replace

    out: list[Finding] = []
    for f in findings:
        active = next((r for r in rules if not r.expired and r.matches(f, root)), None)
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


def unused_findings(
    findings_rules: list[SuppressionRule],
    findings: list[Finding],
    path: Path,
    root: Path | None = None,
) -> list[Finding]:
    """One informational finding per suppression that matched nothing.

    A suppression is a reviewed decision with a reason and an expiry. One
    that matches no current finding is none of those things any more: it
    reads as active protection and protects nothing. Two ways to get there,
    and only one of them is good news —

    - the underlying finding was fixed, and the entry should be deleted;
    - the code moved, and the entry silently stopped covering it.

    The second is what happened when `Scanner` was split: the `B404` and
    `B603` entries named `scanners/base.py`, the subprocess code moved out
    to `_execution.py` and `_resolution.py`, and four reviewed findings
    came back as new work while the entries meant to cover them sat there
    naming a file that still existed and no longer contained any of it.

    `tests/unit/test_no_suppression_path_matches_nothing.py` catches the
    weaker version of this — a glob whose file is gone — and passed against
    that incident for exactly the reason above. Only a run holding the
    findings can answer the real question, so this is computed here rather
    than linted over the file.

    **Expired rules are excluded.** They do not suppress, so they match
    nothing by construction, and `expired_findings` already reports them as
    CRITICAL. One entry must not produce two findings about itself, and
    expiry is the more specific statement.

    **INFORMATIONAL, so the score cannot move.** `SEVERITY_WEIGHT` prices it
    at 0.0. A repository is not more vulnerable for holding stale
    suppressions, and a tidiness finding that changed a grade would be the
    next thing an operator suppresses.
    """
    out: list[Finding] = []
    for r in findings_rules:
        if r.expired:
            continue
        if any(r.matches(f, root) for f in findings):
            continue
        rid = f"suppressions.unused.{r.rule_id}"
        snippet = f"rule_id: {r.rule_id}; expires {r.expires.isoformat()}; reason: {r.reason}"
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
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                file_path=path,
                line_start=0,
                line_end=None,
                code_snippet=snippet,
                message=(
                    f"Suppression for rule `{r.rule_id}` matched no finding in this "
                    f'run: "{r.reason}". Either the finding was fixed and this entry '
                    "should be deleted, or the code it covered moved and the entry no "
                    "longer protects it."
                ),
                short_desc="Suppression with no subject.",
                fix_hint=(
                    "Delete the entry if the finding is fixed, or point it at where the "
                    "code moved. An entry that matches nothing reads as protection and "
                    "provides none."
                ),
            )
        )
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
