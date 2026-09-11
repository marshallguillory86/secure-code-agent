"""Did the work order actually improve security, or just change the code?

A work order that nobody checks is a suggestion. This is the other half:
re-audit after the agent has worked, compare against the run that produced
the order, and state per finding whether it is **fixed**, **still present**,
or **suppressed rather than repaired**.

Three failure modes this exists to catch, all of them things an agent under
time pressure genuinely does:

  * **Silenced, not fixed.** The finding is gone because a `# nosec` was
    added, or because the file stopped being scanned. `_HARD_CONSTRAINTS`
    forbids both; forbidding is not the same as detecting.
  * **Traded.** Five findings resolved and three new ones introduced. The
    count fell, the code did not improve.
  * **Regression elsewhere.** The patch was correct and broke something in
    a file the work order never mentioned.

Identity is the finding fingerprint, which is stable across reformatting
because it is derived from the CWE (or rule), the path, and a
whitespace-normalised snippet. A fix that edits the offending line changes
the fingerprint and the finding reads as resolved — which is the intended
meaning, since the code that triggered it is gone.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from secure_code_audit.findings import Finding, Severity


class Outcome(enum.Enum):
    FIXED = "fixed"
    #: Reported before and after, unchanged.
    UNRESOLVED = "unresolved"
    #: Gone from the findings, but only because a suppression now covers it.
    SUPPRESSED = "suppressed"
    #: Not in the before set at all.
    INTRODUCED = "introduced"


@dataclass(frozen=True)
class Verification:
    """What changed between two audits of the same repository."""

    fixed: tuple[Finding, ...] = ()
    unresolved: tuple[Finding, ...] = ()
    suppressed: tuple[Finding, ...] = ()
    introduced: tuple[Finding, ...] = ()
    #: Severity totals before and after, for the headline.
    before_count: int = 0
    after_count: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def improved(self) -> bool:
        """Did security actually improve?

        Something was fixed, nothing was introduced, and nothing was merely
        silenced. Deliberately strict: a run that resolves five findings and
        introduces one has not improved the code, it has traded. The
        operator can read the detail and decide otherwise, but the headline
        does not get to round in the flattering direction.
        """
        return bool(self.fixed) and not self.introduced and not self.suppressed

    def headline(self) -> str:
        if not any((self.fixed, self.unresolved, self.suppressed, self.introduced)):
            return "no findings before or after — nothing to verify"
        parts = [f"{len(self.fixed)} fixed"]
        if self.introduced:
            parts.append(f"{len(self.introduced)} introduced")
        if self.suppressed:
            parts.append(f"{len(self.suppressed)} silenced rather than fixed")
        if self.unresolved:
            parts.append(f"{len(self.unresolved)} still open")
        verdict = "improved" if self.improved else "not proven"
        return f"{verdict}: " + ", ".join(parts)


def _actionable(findings: Iterable[Finding]) -> dict[str, Finding]:
    """Fingerprint → finding, for everything a work order could have asked
    about. Control findings are excluded: a scanner that was unavailable
    before and available after did not "fix" anything."""
    return {
        f.fingerprint: f
        for f in findings
        if f.severity is not Severity.INFORMATIONAL and not f.suppressed
    }


#: Inline comments that stop a scanner reporting a line. `_HARD_CONSTRAINTS`
#: item 6 forbids adding these; forbidding is not detecting.
_SILENCERS = (
    "nosec",
    "noqa",
    "type: ignore",
    "eslint-disable",
    "rubocop:disable",
    "nolint",
    "sonar-disable",
    "semgrep-disable",
    "nosemgrep",
)


def _is_silenced(finding: Finding, root: Path | None) -> bool:
    """Is the reported line now carrying a suppression comment?

    This closes the hole that made the whole module optimistic. The first
    working version detected only *our* `.scignore.yaml` suppressions, and
    those leave the finding in the report with `suppressed=True` where it is
    easy to spot. A `# nosec` is different in kind: Bandit honours it
    itself, so the finding never reaches us at all and simply reads as
    fixed. Measured on a fixture — two real findings, both silenced with
    `# nosec`, reported "improved: 2 fixed" and exited 0.

    So the source is read back. A window rather than the exact line because
    a patch above shifts what follows, and erring toward "not proven" is the
    safe direction: the operator sees the detail and can still decide the
    suppression was legitimate.
    """
    if root is None:
        return False
    path = finding.file_path
    if not path.is_absolute():
        path = root / path
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    lo = max(0, finding.line_start - 3)
    hi = min(len(lines), (finding.line_end or finding.line_start) + 2)
    window = "\n".join(lines[lo:hi]).lower()
    return any(marker in window for marker in _SILENCERS)


def compare(
    before: Iterable[Finding], after: Iterable[Finding], root: Path | None = None
) -> Verification:
    """Verify one work order's outcome.

    `before` is the audit that produced the order; `after` is a fresh audit
    of the same tree once the work is done. `root` lets the check read the
    source back to tell a repair from a silencing.
    """
    before = list(before)
    after = list(after)
    old = _actionable(before)
    new = _actionable(after)

    # A finding that vanished because a suppression now matches it is not
    # fixed. Two ways that happens: our own `.scignore.yaml`, which leaves
    # the finding in the report flagged; and an inline `# nosec`, which the
    # scanner honours so the finding never arrives.
    suppressed_now = {f.fingerprint for f in after if f.suppressed and f.fingerprint in old}
    gone = [fp for fp in old if fp not in new and fp not in suppressed_now]
    silenced_inline = {fp for fp in gone if _is_silenced(old[fp], root)}
    suppressed_now |= silenced_inline

    fixed = [f for fp, f in old.items() if fp not in new and fp not in suppressed_now]
    unresolved = [f for fp, f in old.items() if fp in new]
    introduced = [f for fp, f in new.items() if fp not in old]
    suppressed = [old[fp] for fp in suppressed_now]

    notes: list[str] = []
    if suppressed:
        notes.append(
            f"{len(suppressed)} finding(s) disappeared without the code being "
            f"repaired — a suppression entry now covers them, or the reported "
            f"line gained an inline marker such as `# nosec`. That is a "
            f"decision to record with a reason and an expiry, not a fix."
        )
    if introduced:
        worst = max(introduced, key=lambda f: f.severity.rank)
        notes.append(
            f"{len(introduced)} finding(s) did not exist before this work, the "
            f"worst at {worst.severity.value}. A patch that resolves one weakness "
            f"and opens another has not improved the code."
        )
    if not fixed and unresolved:
        notes.append(
            "Nothing was resolved. If the work order was applied, either the "
            "patches missed the reported lines or the findings are false "
            "positives that should be suppressed with a reason instead."
        )

    return Verification(
        fixed=tuple(fixed),
        unresolved=tuple(unresolved),
        suppressed=tuple(suppressed),
        introduced=tuple(introduced),
        before_count=len(old),
        after_count=len(new),
        notes=tuple(notes),
    )


def to_dict(result: Verification) -> dict:
    """The machine-readable form, for CI and for maintainability-agent."""

    def _rows(findings: Iterable[Finding]) -> list[dict]:
        return [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "scanner": f.scanner,
                "severity": f.severity.value,
                "category": f.category.value,
                "file_path": f.file_path.as_posix(),
                "line_start": f.line_start,
            }
            for f in findings
        ]

    return {
        "improved": result.improved,
        "headline": result.headline(),
        "before_count": result.before_count,
        "after_count": result.after_count,
        "fixed": _rows(result.fixed),
        "unresolved": _rows(result.unresolved),
        "suppressed": _rows(result.suppressed),
        "introduced": _rows(result.introduced),
        "notes": list(result.notes),
    }
