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

from secure_code_audit import triage
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
class Scope:
    """Did the work stay inside the order?

    The product's claim is that a bounded work order keeps an agent from
    doing crypto roulette, auth rewrites and 600-line "while I was in there"
    patches. Until now only *silencing* and *regressions* were mechanical —
    a reviewer put it exactly: "ten hard constraints are a leash I can still
    ignore ... not for 'did you rewrite the session model'."

    This makes that question mechanical. The work order cites files and
    lines; the repository knows what actually changed. Everything changed
    outside the cited files is collateral, and collateral is the measurable
    shadow of the constraint the prompt cannot enforce.

    **`known` is False when the answer is unavailable** — no commit in the
    before-report, or not a git repository. An unknown scope is reported as
    unknown and never as conformant: a measurement that failed must not read
    as a clean result, which is the same rule the coverage axis applies to
    scanners.
    """

    known: bool = False
    reason: str | None = None
    #: Files the work order named.
    cited: tuple[str, ...] = ()
    #: Files that actually changed, including untracked additions.
    changed: tuple[str, ...] = ()
    #: Changed, and never cited. The blast radius.
    collateral: tuple[str, ...] = ()

    @property
    def conformant(self) -> bool:
        """Only ever True when the question was actually answered."""
        return self.known and not self.collateral

    def headline(self) -> str:
        if not self.known:
            return f"scope: unknown ({self.reason or 'no baseline commit recorded'})"
        if not self.changed:
            return "scope: nothing changed"
        if not self.collateral:
            return f"scope: conformant — {len(self.changed)} file(s), all cited in the order"
        return (
            f"scope: EXCEEDED — {len(self.collateral)} of {len(self.changed)} changed "
            f"file(s) were never cited: {', '.join(sorted(self.collateral)[:5])}"
            + (" …" if len(self.collateral) > 5 else "")
        )


def measure_scope(
    before: Iterable[Finding],
    root: Path | None,
    since: str | None,
    ours: Iterable[Path] = (),
) -> Scope:
    """Compare what the order cited against what the repository changed."""
    if root is None:
        return Scope(reason="no repository root")
    if not since:
        return Scope(reason="the before-report records no commit")

    from secure_code_audit.git_tools import changed_files

    paths, reason = changed_files(root, since)
    if paths is None:
        return Scope(reason=reason)

    cited: set[str] = set()
    for finding in before:
        try:
            cited.add(finding.file_path.resolve().relative_to(root.resolve()).as_posix())
        except (ValueError, OSError):
            cited.add(finding.file_path.as_posix())

    # This tool's own artifacts are written *by* the run doing the verifying.
    # An agent that fixed something did not "also change
    # secure-code-report.md"; we did, a second ago. Counting them as
    # collateral would make every verification exceed its scope.
    #
    # The set comes from the caller — `cli._own_artifacts`, the same function
    # that keeps a run from scanning its own report — rather than a list of
    # default basenames here. A report written to `--json-output
    # before.json` is ours too, and a hard-coded list of defaults said it was
    # the agent's.
    ignored: set[str] = set()
    for artifact in ours:
        try:
            ignored.add(artifact.resolve().relative_to(root.resolve()).as_posix())
        except (ValueError, OSError):
            continue
    changed = {
        path for path in paths if path not in ignored and not path.startswith(".secure-code/")
    }
    return Scope(
        known=True,
        cited=tuple(sorted(cited)),
        changed=tuple(sorted(changed)),
        collateral=tuple(sorted(changed - cited)),
    )


@dataclass(frozen=True)
class Verification:
    """What changed between two audits of the same repository."""

    fixed: tuple[Finding, ...] = ()
    unresolved: tuple[Finding, ...] = ()
    suppressed: tuple[Finding, ...] = ()
    introduced: tuple[Finding, ...] = ()
    #: Still present, and the work order never asked for them — the test
    #: tree and documentation, which §ACCEPT explicitly says not to patch.
    #: Reported, never required.
    deferred: tuple[Finding, ...] = ()
    #: Severity totals before and after, for the headline.
    before_count: int = 0
    after_count: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)
    #: Blast radius, when it could be measured.
    scope: Scope = field(default_factory=Scope)

    @property
    def regressed(self) -> bool:
        """Did this work make things worse, or only appear to make them better?"""
        return bool(self.introduced) or bool(self.suppressed)

    @property
    def improved(self) -> bool:
        """Did security actually improve?

        Something was fixed, nothing was introduced, and nothing was merely
        silenced. Deliberately strict: a run that resolves five findings and
        introduces one has not improved the code, it has traded. The
        operator can read the detail and decide otherwise, but the headline
        does not get to round in the flattering direction.

        This answers "did it get better", which is not the same question as
        "should CI go red" — see `passed`.
        """
        return bool(self.fixed) and not self.regressed

    @property
    def passed(self) -> bool:
        """Should this run be allowed through?

        Separate from `improved`, because conflating them made a clean
        repository impossible to verify: with nothing to fix, nothing was
        fixed, so `improved` was False and the exit code was 1 — forever.
        A team that resolved everything would have had a CI step that could
        never go green again, which is a good way to teach people to delete
        the CI step.

        So the gate asks the answerable question: nothing regressed, and
        either work was done or there was none to do. An outstanding work
        order that went unactioned still fails — `unresolved` with nothing
        fixed is not "nothing to do".
        """
        if self.regressed:
            return False
        nothing_to_do = not self.fixed and not self.unresolved
        return bool(self.fixed) or nothing_to_do

    def headline(self) -> str:
        if not any((self.fixed, self.unresolved, self.suppressed, self.introduced)):
            if self.deferred:
                # Saying "clean" over 899 deferred findings would be the
                # flattering read of a tree full of fixtures. Nothing was
                # *required*, which is not the same as nothing being there.
                return (
                    f"nothing required and nothing broken — "
                    f"{len(self.deferred)} reported in the test tree and documentation"
                )
            return "clean before and after — nothing to fix, nothing broken"
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
    before: Iterable[Finding],
    after: Iterable[Finding],
    root: Path | None = None,
    axis_of=lambda _f: "primary",
) -> Verification:
    """Verify one work order's outcome.

    `before` is the audit that produced the order; `after` is a fresh audit
    of the same tree once the work is done. `root` lets the check read the
    source back to tell a repair from a silencing. `axis_of` says where each
    finding lives.

    **The axis matters, because the work order does not ask for all of
    them.** §ACCEPT says in as many words not to patch the test tree or the
    documentation. Counting those as outstanding work made verification
    unpassable on any repository with fixtures: auditing this one produced
    899 actionable findings, every single one in its own test tree, so
    `passed` was False no matter how much real work had been done. They are
    now `deferred` — reported, never required — while a *new* one still
    counts as introduced, because a fresh secret in a fixture is worth
    knowing about wherever it appears.
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

    def _asked_about(finding: Finding) -> bool:
        return triage.tier_of(finding, axis_of(finding)) is not triage.Tier.ACCEPT

    fixed = [f for fp, f in old.items() if fp not in new and fp not in suppressed_now]
    still_open = [f for fp, f in old.items() if fp in new]
    unresolved = [f for f in still_open if _asked_about(f)]
    deferred = [f for f in still_open if not _asked_about(f)]
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
        deferred=tuple(deferred),
        suppressed=tuple(suppressed),
        introduced=tuple(introduced),
        before_count=len(old),
        after_count=len(new),
        notes=tuple(notes),
    )


def _scope_to_dict(scope: Scope) -> dict:
    return {
        "known": scope.known,
        "reason": scope.reason,
        "conformant": scope.conformant,
        "cited": list(scope.cited),
        "changed": list(scope.changed),
        "collateral": list(scope.collateral),
    }


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
        "passed": result.passed,
        "regressed": result.regressed,
        "headline": result.headline(),
        "before_count": result.before_count,
        "after_count": result.after_count,
        "fixed": _rows(result.fixed),
        "unresolved": _rows(result.unresolved),
        "deferred": _rows(result.deferred),
        "suppressed": _rows(result.suppressed),
        "introduced": _rows(result.introduced),
        "scope": _scope_to_dict(result.scope),
        "notes": list(result.notes),
    }
