"""Security practice level: is anything *preventing* the next vulnerability?

The rubric, the level definitions and the cap are `maintainability-agent`'s —
[ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
§2 and its `_practice.py`. This is the security reading of the same scale, not
a second scale that happens to have five numbers. Two tools reporting "level 3"
about the same repository must mean the same thing by it, or the pillar view
that joins them is worse than either tool alone.

Read from **configuration and CI, never from source**. That separation is the
whole point, and it is the half this tool was missing. A scan says the code is
clean today; it cannot say whether anything stops tomorrow's merge from
committing a private key. MA found its version of this with a hello-world that
scored A+ on genuinely clean source with no linter, no CI and no gates — the
second fact invisible because nothing looked for it. The security equivalent is
a repository with no findings because nobody has ever scanned it.

The levels:

1. **Nothing detectable.** No scanner configuration, no security job in CI.
2. **Intent.** Security configuration exists on disk, so someone chose to care
   — but nothing runs it, so nothing is binding.
3. **Enforcement.** CI runs a security scanner. A bad change can fail a build.
4. **Gates.** CI holds a security line: a required scanner set, a severity
   ceiling, a finding cap — something with a number in it that can be crossed.
5. **Discipline.** Gates plus the practices that keep them honest — a
   disclosure policy, suppressions that expire, scanner versions pinned,
   findings published where they can be tracked.

**Configuration without CI is capped at 2.** A repository can hold every
scanner config ever written and still merge anything; a scanner nobody runs is
a preference, not an enforcement.

Every signal names the file that proves it. A maturity level a reader cannot
check is a grade with no marking scheme — and this one is a judgment about
someone's engineering practice made from the outside, so it had better be
checkable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

#: A repository holding configuration but running none of it. MA's
#: `MAX_WITHOUT_CI`, same value and same reasoning: intent is not enforcement,
#: and the gap between them is the most useful thing this measurement reports.
MAX_WITHOUT_CI = 2

#: Where continuous integration lives, across the hosts people actually use.
#: Taken from MA rather than re-derived: recognising only GitHub Actions would
#: score every GitLab shop at level 2 for choosing a different host, which is a
#: statement about this tool rather than about them.
CI_LOCATIONS: tuple[str, ...] = (
    ".github/workflows",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    ".travis.yml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    "buildkite.yml",
    ".woodpecker.yml",
)

#: Configuration that declares a security standard. Presence is level-2
#: evidence; being invoked from CI is what lifts it to 3.
SCANNER_CONFIGS: tuple[str, ...] = (
    "secure-code-agent.json",
    ".bandit",
    "bandit.yaml",
    ".semgrep.yml",
    ".semgrepignore",
    "semgrep.yml",
    ".gitleaks.toml",
    "gitleaks.toml",
    ".trivyignore",
    "trivy.yaml",
    ".checkov.yaml",
    ".checkov.yml",
    ".snyk",
    ".njsscan",
    "sonar-project.properties",
    ".gosec.json",
    "brakeman.yml",
    ".zap/rules.tsv",
)

#: Names that mean a CI job is doing security work. Matched against workflow
#: text, so a job that runs any of these counts even when the file is not ours.
SCANNER_INVOCATIONS: tuple[str, ...] = (
    "secure-code-agent",
    "secure-code-audit",
    "bandit",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "trivy",
    "checkov",
    "osv-scanner",
    "pip-audit",
    "npm audit",
    "njsscan",
    "gosec",
    "brakeman",
    "snyk",
    "codeql",
    "dependency-review",
    "scorecard",
)

#: A gate is a line that can be crossed — something with a threshold in it.
#: Presence of a scanner in CI is level 3; one of these is level 4.
GATE_MARKERS: tuple[str, ...] = (
    "--fail-on-gate",
    "--fail-on-new",
    "fail_on_severity",
    "fail_on_category",
    "require_scanners",
    "max_unsuppressed",
    "min_score",
    "--severity-threshold",
    "--exit-code",
    "severity-cutoff",
    "fail-on",
    "--fail",
)

#: Level-5 practices: the ones that keep a gate honest over time.
DISCIPLINE_FILES: tuple[str, ...] = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
    ".pre-commit-config.yaml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    ".renovaterc.json",
)

#: A suppression that never expires is a permanent exception wearing a
#: temporary name. An expiry date is the discipline signal.
SUPPRESSION_FILES: tuple[str, ...] = (".scignore.yaml", ".scignore.yml")


@dataclass(frozen=True)
class Signal:
    """One piece of evidence, and the file that proves it."""

    signal: str
    path: str

    def as_dict(self) -> dict[str, str]:
        return {"signal": self.signal, "path": self.path}


@dataclass(frozen=True)
class PracticeLevel:
    """Where this repository sits on the maturity rubric, and why."""

    level: int
    summary: str
    signals: tuple[Signal, ...]
    #: Set when a rule held the level down, so a reader sees the reason rather
    #: than only the number. MA reports the same field for the same purpose.
    caps: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "summary": self.summary,
            "signals": [s.as_dict() for s in self.signals],
            "caps": list(self.caps),
        }


_SUMMARIES = {
    1: "nothing detectable — no security configuration and no security job in CI",
    2: "intent — security configuration exists, but nothing runs it",
    3: "enforcement — CI runs a security scanner, so a bad change can fail a build",
    4: "gates — CI holds a security line that can be crossed",
    5: "discipline — gates, plus the practices that keep them honest",
}


def _read(path: Path, limit: int = 200_000) -> str:
    """Best-effort text read. A file we cannot read is not evidence."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _ci_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for location in CI_LOCATIONS:
        candidate = root / location
        if candidate.is_dir():
            found.extend(p for p in sorted(candidate.rglob("*")) if p.is_file())
        elif candidate.is_file():
            found.append(candidate)
    return found


def _ci_evidence(
    root: Path, ci_files: list[Path], configs: list[str]
) -> tuple[list[Signal], list[Signal]]:
    """What CI actually runs, and what declares a threshold.

    Two lists rather than one because the difference between them is the
    whole point of the level: a scanner in CI is enforcement, a threshold in
    a config is intent, and `_apply_caps` needs to tell them apart.

    A gate can also be declared in configuration that CI then runs, so the
    config sweep appends after the CI sweep — that order reaches the report
    and is preserved from when this was one function.
    """
    scanner_in_ci: list[Signal] = []
    gates_in_ci: list[Signal] = []
    for path in ci_files:
        text = _read(path).lower()
        if not text:
            continue
        relative = str(path.relative_to(root))
        for name in SCANNER_INVOCATIONS:
            if name in text:
                scanner_in_ci.append(Signal(f"CI runs {name}", relative))
                break
        for marker in GATE_MARKERS:
            if marker.lower() in text:
                gates_in_ci.append(Signal(f"CI enforces {marker}", relative))
                break

    for name in configs:
        text = _read(root / name)
        for marker in GATE_MARKERS:
            if marker in text:
                gates_in_ci.append(Signal(f"gate declared: {marker}", name))
                break
    return scanner_in_ci, gates_in_ci


def _discipline_evidence(root: Path) -> list[Signal]:
    """Practice files, and suppressions that carry an expiry."""
    discipline: list[Signal] = [
        Signal("security practice file", name)
        for name in DISCIPLINE_FILES
        if (root / name).is_file()
    ]
    for name in SUPPRESSION_FILES:
        path = root / name
        if path.is_file() and re.search(r"^\s*expires\s*:", _read(path), re.MULTILINE):
            discipline.append(Signal("suppressions carry an expiry", name))
    return discipline


def _intended_level(
    configs: list[str],
    scanner_in_ci: list[Signal],
    gates_in_ci: list[Signal],
    discipline: list[Signal],
) -> int:
    """The level the evidence *claims*, before any cap.

    Computed separately from the cap so that a config declaring a strict gate
    nothing executes can be capped **and told why** — the number alone would
    read as though the gate were real.
    """
    intended = 1
    if configs:
        intended = 2
    if scanner_in_ci:
        intended = 3
    if gates_in_ci:
        intended = 4
    if intended == 4 and discipline:
        intended = 5
    return intended


def _apply_caps(
    intended: int, ci_files: list[Path], scanner_in_ci: list[Signal]
) -> tuple[int, list[str]]:
    """Intent is not enforcement.

    A repository can hold every scanner config ever written, declare every
    threshold in it, and still merge anything. Each cap carries its reason,
    because a level with no explanation reads as a measurement of the code
    rather than of what runs against it.
    """
    if ci_files and scanner_in_ci:
        return intended, []
    reason = (
        f"no continuous integration found, so the level is capped at "
        f"{MAX_WITHOUT_CI}: configuration that nothing runs is a "
        f"preference, not an enforcement"
        if not ci_files
        else f"CI exists but runs no recognised security scanner, so the "
        f"level is capped at {MAX_WITHOUT_CI}: a threshold nothing "
        f"evaluates is not a gate"
    )
    caps = [reason] if intended > MAX_WITHOUT_CI else []
    return min(intended, MAX_WITHOUT_CI), caps


def assess(root: Path) -> PracticeLevel:
    """Score the repository's security practice from its configuration and CI.

    Never reads source. A source finding is code condition, which is the other
    axis and is measured by the scanners.

    The signal order is load-bearing: it reaches the report, so configs come
    before CI presence, then what CI runs, then what declares a gate, then
    discipline. That order is why this reads as a sequence of appends rather
    than one comprehension.
    """
    configs = [name for name in SCANNER_CONFIGS if (root / name).is_file()]
    ci_files = _ci_files(root)
    scanner_in_ci, gates_in_ci = _ci_evidence(root, ci_files, configs)
    discipline = _discipline_evidence(root)

    signals: list[Signal] = [Signal("security configuration present", name) for name in configs]
    if ci_files:
        signals.append(Signal("continuous integration present", str(ci_files[0].relative_to(root))))
    signals.extend(scanner_in_ci)
    signals.extend(gates_in_ci)
    signals.extend(discipline)

    intended = _intended_level(configs, scanner_in_ci, gates_in_ci, discipline)
    level, caps = _apply_caps(intended, ci_files, scanner_in_ci)

    return PracticeLevel(
        level=level,
        summary=_SUMMARIES[level],
        signals=tuple(signals),
        caps=tuple(caps),
    )
