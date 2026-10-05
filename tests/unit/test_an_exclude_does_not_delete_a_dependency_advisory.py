"""A path exclusion must not delete a finding about a package.

`_classify` already settled this one layer up, and said why:

    A dependency advisory is about the dependency, not about the file that
    happened to declare it. Classified by category before path, because the
    path routing gets it wrong: `requirements.txt` matches the documentation
    pattern `**/*.txt`, so every CVE in a pip manifest was filed under
    **documentation** — eighteen of them on a six-file demo tree.

The same argument applies to exclusion, and nothing applied it. A
dependency finding is reported against the manifest or lockfile that pins
the version, because that is the only file there is to point at — so any
pattern matching that path deletes the advisory.

**Found on this repository.** `paths.exclude_patterns` contains
`**/*.lock`, which is an ordinary thing to write: a lockfile is generated,
enormous, and full of hashes that read like secrets. The effect was that
trivy's 19 dependency advisories against `uv.lock` — one CRITICAL, nine
HIGH — never reached the report, and the `dependencies` category graded
**5.0**: a perfect score for a category whose only evidence source was
excluded. That is the same "absence read as a value" this release closes
elsewhere, arriving through a path pattern.

The exclusion is still obeyed for everything else in the same file. A
secret or a code finding inside an excluded lockfile stays excluded, which
is what the operator asked for; it is only the advisory about the *package*
that survives, because the path was never what it was about.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from secure_code_audit.cli import _drop_excluded
from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity


def _finding(*, category: Category, file_path: str) -> Finding:
    return Finding(
        rule_id="CVE-2026-102268" if category is Category.DEPENDENCIES else "B602",
        scanner="trivy",
        fingerprint="a" * 16,
        canonical_cwe="CWE-1104",
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path=Path(file_path),
        line_start=0,
        line_end=None,
        code_snippet=None,
        message="m",
    )


@pytest.fixture
def tree(tmp_path):
    """A repository whose lockfile is excluded, as this one's is."""
    (tmp_path / "uv.lock").write_text("locked\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def _kept(tree: Path, findings: list[Finding], patterns: list[str]) -> list[Finding]:
    cfg = replace(Config(), exclude_patterns=patterns)
    return _drop_excluded(findings, tree, cfg, frozenset(), repository=tree)


def test_a_dependency_advisory_survives_an_excluded_lockfile(tree):
    """The defect: the advisory was deleted with the file it was filed against."""
    advisory = _finding(category=Category.DEPENDENCIES, file_path="uv.lock")

    kept = _kept(tree, [advisory], ["**/*.lock"])

    assert kept == [advisory], (
        "an exclusion deleted a dependency advisory. The finding is about the "
        "pinned package; the lockfile is only the one file there is to point at."
    )


def test_a_code_finding_in_the_same_excluded_file_is_still_excluded(tree):
    """The falsifier, and the limit of the rule.

    Without this, "dependency findings survive" could be implemented as
    "exclusions stopped working", which would be far worse than the defect.
    The operator excluded the lockfile; everything about the *file* goes.
    """
    code = _finding(category=Category.CODE_VULNERABILITIES, file_path="uv.lock")

    assert _kept(tree, [code], ["**/*.lock"]) == []


def test_a_secret_in_an_excluded_file_is_still_excluded(tree):
    """The reason `**/*.lock` gets written in the first place.

    Lockfiles are full of hashes that read like credentials. Exempting
    dependency advisories must not drag secrets back in, or the exclusion
    stops being worth writing.
    """
    secret = _finding(category=Category.SECRETS, file_path="uv.lock")

    assert _kept(tree, [secret], ["**/*.lock"]) == []


def test_a_dependency_advisory_elsewhere_is_unaffected(tree):
    """A manifest nobody excluded keeps behaving as it always did."""
    advisory = _finding(category=Category.DEPENDENCIES, file_path="uv.lock")

    assert _kept(tree, [advisory], []) == [advisory]


def test_an_excluded_directory_still_drops_its_code_findings(tree):
    """The ordinary case this release exists to make work: a vendored tree."""
    vendored = _finding(category=Category.CODE_VULNERABILITIES, file_path="vendor/app.py")

    assert _kept(tree, [vendored], ["vendor/"]) == []


def test_a_dependency_advisory_inside_an_excluded_vendored_tree_survives(tree):
    """Deliberate, and worth stating because it is the arguable case.

    A vendored third-party tree is excluded precisely because it is not our
    code — but a CVE in a package it pins is still a CVE we ship. The same
    reasoning `_classify` used: the path is incidental to the advisory.
    Excluding it would be the lockfile case again, one directory up.
    """
    advisory = _finding(category=Category.DEPENDENCIES, file_path="vendor/requirements.txt")

    kept = _kept(tree, [advisory], ["vendor/"])

    assert kept == [advisory], kept
