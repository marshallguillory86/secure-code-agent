"""The declared minimum tool set, and why each tool is in it.

A security gate that ships with everything optional has no opinion, and an
operator who has to choose ten scanners before the first run will choose none.
This module is the opinion: the set this project asserts is the floor for
calling a repository scanned, plus the tools deliberately left out of it and
the reason for each.

Two rules keep the floor honest.

**A floor tool that does not apply is not a gap.** Running an npm auditor
against a repository with no JavaScript proves nothing, so applicability is
declared per tool and a tool outside its ecosystem reports `not_applicable`
with a reason rather than counting against coverage. Silence would read as a
pass; a named reason does not.

**Overlap must earn its place.** Where two tools answer the same question, the
better one is in the floor and the other is optional with the reason it
survived at all. Four tools reporting the same CVE is not four times the
assurance — it is one finding, counted four times, in a score that normalizes
over findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolPolicy:
    """Why a scanner is in the floor, or why it is not."""

    name: str
    licence: str
    domain: str
    rationale: str
    #: File extensions that make this tool applicable. Empty means it applies
    #: to every repository — secrets and CI-workflow analysis are not tied to
    #: a language.
    applies_to: tuple[str, ...] = ()
    #: Set only for tools outside the floor: why they are opt-in.
    optional_because: str | None = None
    #: Filenames whose presence makes the tool applicable regardless of
    #: extensions, e.g. a Dockerfile or a lockfile.
    applies_to_files: tuple[str, ...] = field(default_factory=tuple)


#: The floor. Enabled unless an operator turns one off, and the set that
#: `gates.require_scanners: ["floor"]` expands to.
FLOOR: tuple[ToolPolicy, ...] = (
    ToolPolicy(
        name="builtin_rules",
        licence="MIT (this project)",
        domain="multiple",
        rationale=(
            "a small, high-precision floor that needs nothing installed, so a "
            "repository is never scanned by nothing at all"
        ),
    ),
    ToolPolicy(
        name="bandit",
        licence="Apache-2.0",
        domain="code_vulnerabilities",
        rationale="PyCQA-official Python SAST; rules the multi-language engines do not carry",
        applies_to=(".py",),
    ),
    ToolPolicy(
        name="semgrep",
        licence="LGPL-2.1 (engine); registry rules are separately licensed",
        domain="code_vulnerabilities",
        rationale="the broadest FOSS multi-language SAST; the only cross-language dataflow we get",
        applies_to=(".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".rs"),
    ),
    ToolPolicy(
        name="pip_audit",
        licence="Apache-2.0",
        domain="dependencies",
        rationale=(
            "PyPA-official, and the only SCA here that reads requirements, "
            "pyproject and lock files without needing a resolved lockfile"
        ),
        applies_to=(".py",),
        applies_to_files=("requirements.txt", "pyproject.toml", "setup.py"),
    ),
    ToolPolicy(
        name="osv_scanner",
        licence="Apache-2.0",
        domain="dependencies",
        rationale=(
            "cross-ecosystem SCA against OSV.dev, matched per ecosystem rather "
            "than by CPE, which is why it carries far fewer false positives "
            "than advisory-database scanners"
        ),
    ),
    ToolPolicy(
        name="gitleaks",
        licence="MIT",
        domain="secrets",
        rationale="fast, offline, history-aware secret detection; permissively licensed",
    ),
    ToolPolicy(
        name="checkov",
        licence="Apache-2.0",
        domain="config_iac",
        rationale="the deepest FOSS IaC coverage — Terraform, CloudFormation, Helm, Kubernetes",
        applies_to=(".tf", ".yaml", ".yml", ".json"),
        applies_to_files=("Dockerfile",),
    ),
    ToolPolicy(
        name="trivy",
        licence="Apache-2.0",
        domain="config_iac",
        rationale=(
            "container and image posture, which nothing else here covers; its "
            "SCA overlaps osv_scanner and is not why it is in the floor"
        ),
        applies_to=(".yaml", ".yml", ".tf"),
        applies_to_files=("Dockerfile",),
    ),
    ToolPolicy(
        name="scorecard",
        licence="Apache-2.0",
        domain="supply_chain",
        rationale="repository and supply-chain hygiene; no other tool here asks these questions",
    ),
)

#: Deliberately outside the floor. Each carries the reason it is opt-in rather
#: than absent, because "we left it out" and "we never considered it" are
#: different statements and only one of them is useful.
OPTIONAL: tuple[ToolPolicy, ...] = (
    ToolPolicy(
        name="trufflehog",
        licence="AGPL-3.0",
        domain="secrets",
        rationale="verifies candidate secrets against the live service, a real precision gain",
        optional_because=(
            "duplicates gitleaks for detection, needs network to verify, and "
            "AGPL would hand a source-offer obligation to anyone running this "
            "as a hosted service — their decision to make, not ours"
        ),
    ),
    ToolPolicy(
        name="hadolint",
        licence="GPL-3.0",
        domain="config_iac",
        rationale="the best dedicated Dockerfile linter, and better at Dockerfiles than the generalists",
        applies_to_files=("Dockerfile",),
        optional_because=(
            "overlaps checkov and trivy on Dockerfiles; GPL is fine for a tool "
            "we invoke and never distribute, but some adopters' policies "
            "exclude it outright"
        ),
    ),
    ToolPolicy(
        name="npm_audit",
        licence="Artistic-2.0 (ships with npm)",
        domain="dependencies",
        rationale="ecosystem-native, no extra install where Node is already present",
        applies_to_files=("package-lock.json", "npm-shrinkwrap.json"),
        optional_because=(
            "osv_scanner covers the same advisories with fewer false positives "
            "and without requiring Node or a resolved lockfile"
        ),
    ),
)

FLOOR_NAMES: tuple[str, ...] = tuple(policy.name for policy in FLOOR)
OPTIONAL_NAMES: tuple[str, ...] = tuple(policy.name for policy in OPTIONAL)

#: The token an operator writes in `gates.require_scanners` to require the
#: floor without enumerating it, so the set stays maintained here rather than
#: copied into every repository's config and left to rot.
FLOOR_TOKEN = "floor"

_BY_NAME: dict[str, ToolPolicy] = {p.name: p for p in (*FLOOR, *OPTIONAL)}


def policy(name: str) -> ToolPolicy | None:
    return _BY_NAME.get(name)


def default_enabled(name: str) -> bool:
    """Whether a scanner runs when the configuration does not say."""
    return name in FLOOR_NAMES


def applies_to_repository(name: str, extensions: set[str], filenames: set[str]) -> bool:
    """Whether a floor tool has anything to look at in this repository.

    A tool outside its ecosystem is `not_applicable`, never a coverage
    failure. Counting an absent ecosystem as a gap would make every
    single-language repository permanently incomplete, and an alarm that is
    always on is not an alarm.
    """
    p = policy(name)
    if p is None:
        return True
    if not p.applies_to and not p.applies_to_files:
        return True  # secrets, supply chain: not tied to a language
    return bool(extensions & set(p.applies_to)) or bool(filenames & set(p.applies_to_files))


def expand_required(names: list[str]) -> list[str]:
    """Replace the `floor` token with the floor's members, order preserved."""
    out: list[str] = []
    for name in names:
        if name == FLOOR_TOKEN:
            out.extend(n for n in FLOOR_NAMES if n not in out)
        elif name not in out:
            out.append(name)
    return out
