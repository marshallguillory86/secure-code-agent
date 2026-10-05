"""Scanner execution and coverage status.

Findings describe security defects in the target.  Scanner status describes
whether the tools needed to produce those findings actually ran.  Keeping the
two concepts separate prevents a clean finding set from implying complete
coverage.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from secure_code_audit.findings import Finding


class ScannerOutcome(str, Enum):
    COMPLETED = "completed"
    # Someone else ran the scanner and handed us the output. We never observed
    # the process, so we cannot assert it succeeded — only that the operator
    # vouched for the file. Distinct from COMPLETED on purpose.
    UNVERIFIED = "unverified"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


#: Outcomes that mean the scanner's ground was covered, verified or not.
COVERING_OUTCOMES = (ScannerOutcome.COMPLETED, ScannerOutcome.UNVERIFIED)


class CoverageStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class ScannerExecution:
    name: str
    outcome: ScannerOutcome
    command: tuple[str, ...] = ()
    version: str | None = None
    finding_count: int = 0
    reason: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """What an adapter reports: what happened to it, and what it found.

    Adapters used to signal outcome by *naming a finding* — `bandit.tool_error`
    meant FAILED, anything starting `bandit.no_` meant NOT_APPLICABLE — and
    `classify_execution` reverse-engineered the intent by prefix matching.
    Nothing enforced that protocol: no type, no test, no lint. An adapter that
    named a control finding wrongly silently produced a *security* finding, and
    a real finding whose id happened to start with the scanner's name plus
    `no_` became a false NOT_APPLICABLE, which a required-scanner gate then
    escalated into a hard failure.

    The outcome is now stated rather than inferred, and the control finding is
    derived from it (see `Scanner._control_result`), so the two cannot
    disagree. See `docs/architecture.md` §2.
    """

    outcome: ScannerOutcome
    findings: tuple[Finding, ...] = ()
    #: Why, for any outcome that is not COMPLETED. Carried into the report so
    #: an operator reads a reason rather than an absence.
    reason: str | None = None
    #: What this run actually covered — pip-audit's mode and inputs, the
    #: offline rule profile semgrep used. Declared by the adapter, because the
    #: orchestrator used to special-case scanners by name to supply it.
    scope: str | None = None

    def __post_init__(self) -> None:
        if self.outcome is not ScannerOutcome.COMPLETED and not self.reason:
            raise ValueError(f"{self.outcome.value} requires a reason")


@dataclass(frozen=True)
class CoverageReport:
    status: CoverageStatus
    required: tuple[str, ...]
    executions: tuple[ScannerExecution, ...]
    failures: tuple[str, ...]
    #: Scanners whose coverage rests on an operator-supplied artifact rather
    #: than a process we watched. Reported everywhere so COMPLETE is never
    #: read as "we verified all of this ourselves".
    unverified: tuple[str, ...] = ()
    #: Languages present in the tree that nothing in this run reads for code
    #: vulnerabilities. Separate from `failures` on purpose: a required
    #: scanner that did not run broke a promise the operator made and fails
    #: the gate, while an unread language is a limit of the floor and
    #: withholds the verified grade instead.
    unread_languages: tuple[str, ...] = ()


def execution_from_result(
    name: str,
    result: ScanResult,
    *,
    command: tuple[str, ...] = (),
    version: str | None = None,
) -> ScannerExecution:
    """Record what an adapter reported. No inference, no string parsing.

    This is what `classify_execution` becomes once the adapter states its own
    outcome: a copy, not a decoding. `finding_count` counts only a run that
    completed — a scanner that failed after emitting partial output has not
    covered its ground, and a count taken from that would read as progress.
    """
    return ScannerExecution(
        name=name,
        outcome=result.outcome,
        command=command,
        version=version,
        finding_count=len(result.findings) if result.outcome is ScannerOutcome.COMPLETED else 0,
        reason=result.reason,
        scope=result.scope,
    )


# Worst-first. A scanner can be reported twice — once from a local run and
# once from an imported SARIF — and the degraded result must win so a clean
# import cannot mask a failed local execution.
#
# COMPLETED outranks UNVERIFIED deliberately: if we ran the scanner ourselves
# *and* an import reports it, our own observation is the stronger evidence and
# should not be downgraded by someone else's file.
_OUTCOME_PRECEDENCE: dict[ScannerOutcome, int] = {
    ScannerOutcome.FAILED: 0,
    ScannerOutcome.TIMED_OUT: 1,
    ScannerOutcome.UNAVAILABLE: 2,
    ScannerOutcome.NOT_APPLICABLE: 3,
    ScannerOutcome.COMPLETED: 4,
    ScannerOutcome.UNVERIFIED: 5,
}


def worst_by_name(
    executions: Iterable[ScannerExecution],
) -> dict[str, ScannerExecution]:
    """Collapse duplicate scanner names to their least successful execution."""
    by_name: dict[str, ScannerExecution] = {}
    for execution in executions:
        current = by_name.get(execution.name)
        if (
            current is None
            or _OUTCOME_PRECEDENCE[execution.outcome] < _OUTCOME_PRECEDENCE[current.outcome]
        ):
            by_name[execution.name] = execution
    return by_name


#: Which scanners in this floor actually read a language for *code* defects.
#:
#: **Verified by running them, not adopted from anywhere.** An earlier version
#: of this lifted `calibration/calibrate.py`'s `LANGUAGE_SCANNERS` wholesale
#: and was wrong, because that map answers a different question: the study
#: fixes its scanner set and uses "did the *dedicated* language scanner run"
#: as a proxy for coverage depth. Read as "what reads this language at all" it
#: asserts things that are false — that nothing reads Go without `gosec`
#: (semgrep's offline profile carries five Go rules, and they fire), and that
#: nothing reads Python without `bandit` (`builtin_rules` is Python-only and
#: found the findings in the very fixture that caught this).
#:
#: So this lists every scanner that genuinely reads the language, and a
#: language is flagged only when **nothing** read it. That is a weaker claim
#: than the study's and it is the one that is true.
#:
#: The depth question the study is really asking — "five generic rules is a
#: floor, not coverage" — is deliberately *not* answered here. `COMPLETE` and
#: `PARTIAL` cannot express it, and inventing a third state is a product
#: decision rather than a bug fix.
LANGUAGE_SCANNERS: dict[str, tuple[str, ...]] = {
    # `builtin_rules` is Python-only; semgrep's offline profile adds two more.
    "python": ("bandit", "semgrep", "builtin_rules"),
    "javascript": ("njsscan", "semgrep"),
    "typescript": ("njsscan", "semgrep"),
    "ruby": ("rubocop", "semgrep"),
    # No dedicated Go scanner in the floor, but the offline profile's five Go
    # rules do read it: command injection, weak hash, weak cipher, TLS
    # verification disabled, weak random. Verified firing on the shipped Go
    # fixture.
    "go": ("gosec", "semgrep"),
    # Likewise Java: five offline rules. D12 is about PMD and SpotBugs not
    # providing a *dedicated* scanner, which is a statement about depth.
    "java": ("semgrep",),
    # Nothing in the floor reads shell for code defects — no entry to name.
    "shell": (),
}


#: File extension -> the language `LANGUAGE_SCANNERS` keys on.
#:
#: Only extensions whose language this floor claims to scan for *code*
#: defects. `.yaml`, `.json`, `Dockerfile` and `.md` are deliberately absent:
#: they are covered on other axes by checkov and trivy, and mapping them to a
#: language would make PARTIAL the permanent state of every repository.
_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
}


def languages_for(extensions: Iterable[str]) -> tuple[str, ...]:
    """The code-vulnerability languages these extensions represent, sorted.

    Deduplicated: `.js` and `.mjs` are both JavaScript and the result names it
    once. An extension with no entry is dropped rather than guessed at.
    """
    return tuple(
        sorted({_EXTENSION_LANGUAGE[ext] for ext in extensions if ext in _EXTENSION_LANGUAGE})
    )


def _unread_languages(languages: Iterable[str], covered_by: set[str]) -> tuple[str, ...]:
    """Languages present in the tree that no scanner in this run reads.

    `gin` — 7,146 lines of Go — reported `coverage: complete` and
    `code_vulnerabilities: 5.0` while bandit, njsscan and rubocop found
    nothing in Go source and `gosec` was not in the run. That is P7's own
    falsification condition, and COMPLETE was a fact about the scanner list
    rather than about the tree.
    """
    out: list[str] = []
    for language in dict.fromkeys(languages):
        readers = LANGUAGE_SCANNERS.get(language)
        if readers is None:
            # Not a code-vulnerability language in this floor's terms.
            continue
        if any(name in covered_by for name in readers):
            continue
        if readers:
            out.append(f"{language}: no scanner that reads it ran ({', '.join(readers)})")
        else:
            # Nothing exists to suggest, so do not invent a name.
            out.append(f"{language}: no scanner in this floor reads it")
    return tuple(out)


def evaluate_coverage(
    executions: Iterable[ScannerExecution],
    required: Iterable[str],
    languages: Iterable[str] = (),
) -> CoverageReport:
    """What examined this tree, and whether that was enough to cover it.

    `languages` names the programming languages actually present in the
    scanned tree. Omitting it keeps the previous behaviour exactly, so every
    existing call site and every older report keeps its meaning.
    """
    executions = tuple(executions)
    required = tuple(dict.fromkeys(required))
    by_name = worst_by_name(executions)

    failures: list[str] = []
    for name in required:
        execution = by_name.get(name)
        if execution is None:
            failures.append(f"required scanner {name!r} was not selected")
        elif execution.outcome not in COVERING_OUTCOMES:
            # The reason, when the adapter recorded one. These strings reach
            # `coverage.failures`, which is what the `require_scanners` gate
            # reports and what the summary prints — so composing them from the
            # outcome alone told an operator "failed" while the cause sat one
            # field away in the same record. On this repository's own audit
            # that cause was a 429 from Maven Central with a `Retry-After`
            # and a remedy, and sixty committed trend rows carried the word
            # "failed" and nothing else.
            detail = (execution.reason or "").strip()
            failures.append(
                f"required scanner {name!r} did not complete: {execution.outcome.value}"
                + (f" — {detail}" if detail else "")
            )

    # An unverified import covers the ground, so it does not degrade status to
    # PARTIAL — PARTIAL still means "something did not run". It is named
    # separately instead, so COMPLETE never silently implies we watched every
    # scanner ourselves.
    unverified = tuple(
        execution.name
        for execution in by_name.values()
        if execution.outcome is ScannerOutcome.UNVERIFIED
    )

    covered_by = {
        execution.name for execution in by_name.values() if execution.outcome in COVERING_OUTCOMES
    }
    unread = _unread_languages(languages, covered_by)

    if failures:
        status = CoverageStatus.FAILED
    elif unread:
        # PARTIAL, not FAILED. PARTIAL withholds the *verified* grade and
        # leaves `require_scanners` alone, which is how a partially covered
        # repository already behaves. FAILED would refuse to audit anything
        # containing a shell script. An operator who wants the stricter
        # reading of P7 has `require_scanners` for it.
        status = CoverageStatus.PARTIAL
    elif any(
        execution.outcome not in (*COVERING_OUTCOMES, ScannerOutcome.NOT_APPLICABLE)
        for execution in executions
    ):
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.COMPLETE

    return CoverageReport(
        status=status,
        required=required,
        unverified=unverified,
        executions=executions,
        failures=tuple(failures),
        unread_languages=unread,
    )
