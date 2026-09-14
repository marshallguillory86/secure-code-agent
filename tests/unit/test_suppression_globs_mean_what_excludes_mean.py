"""A `paths:` suppression glob means what an exclude pattern means.

README, `docs/design.md` and the shipped skill all show the same suppression:

    - rule_id: "B101"
      paths:   ["tests/"]

It has never suppressed anything. `SuppressionRule.matches` used bare
`fnmatch`, which gives a trailing slash no meaning, so `tests/` matched only a
file literally named `tests/`. `exclude_patterns` did not have that problem:
`git_tools` reads a trailing slash as "this directory, at any depth", matches
`**/` at depth zero, globs directory components and runs of them — each of
those fixed after it was found inert (`test_exclude_patterns_are_live.py`).

Two pattern languages in one configuration, differing silently, is the D5 and
D20 defect again: a suppression that reads as intent and hides nothing.

So the population is every case the exclude matcher is held to, plus every
`paths:` pattern the documentation shows, and the check is that a suppression
and an exclusion agree on all of them.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path

import pytest

from secure_code_audit.config import DEFAULT_EXCLUDES
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.git_tools import is_excluded
from secure_code_audit.suppressions import SuppressionRule

REPO = Path(__file__).resolve().parents[2]
ROOT = Path("/repo")

#: Every file that documents a suppression for a reader to copy.
DOCUMENTED = (
    REPO / "README.md",
    REPO / "docs" / "design.md",
    REPO / "skills" / "secure-code-agent" / "references" / "finding-taxonomy.md",
)

#: Cases `test_exclude_patterns_are_live.py` pins for the exclude matcher, with
#: the answer it gives. Lifted rather than imported so a reader sees the
#: population here.
_PINNED: list[tuple[str, str]] = [
    ("*.egg-info/", "src/pkg.egg-info/PKG-INFO"),
    ("*.egg-info/", "pkg.egg-info/PKG-INFO"),
    ("**/*.egg-info/", "src/pkg.egg-info/PKG-INFO"),
    ("build-*/", "build-x86/out.js"),
    ("test_*/", "a/b/test_data/x.py"),
    ("*.egg-info/", "src/app.py"),
    ("build-*/", "src/builder/x.js"),
    ("build-*/", "src/nested/out.js"),
    ("calibration/.corpus/", "calibration/.corpus/django/a.py"),
    ("a/b/", "a/b/c.py"),
    ("a/b/", "a/x/c.py"),
    ("a/b/", "z/a/b/c.py"),
    ("src/*/generated/", "src/pkg/generated/x.py"),
    ("src/*/generated/", "src/pkg/other/x.py"),
    ("**/__pycache__/", "__pycache__extra/x.py"),
    ("**/__pycache__/", "my__pycache__/x.py"),
    ("**/__pycache__/", "src/__pycache__"),
    ("*.egg-info/", "src/notes.egg-info"),
    ("**/", "src/app.py"),
    ("**/*.min.js", "a/b/c/vendor.min.js"),
    ("**/*.lock", "src/app.py"),
    ("**/*_test.go", "context_test.go"),
    ("conftest.py", "a/b/conftest.py"),
    ("src/*.py", "lib/src/app.py"),
]


def _sample(pattern: str) -> str:
    """A path the pattern is written to match."""
    bare = pattern[3:] if pattern.startswith("**/") else pattern
    if bare.endswith("/"):
        return f"{bare.replace('*', 'sample')}file.py"
    return bare.replace("*", "sample")


def _documented_patterns() -> list[str]:
    found: list[str] = []
    for path in DOCUMENTED:
        for block in re.findall(r"paths:\s*\[([^\]]*)\]", path.read_text(encoding="utf-8")):
            found.extend(re.findall(r"[\"']([^\"']+)[\"']", block))
    return found


def _population() -> list[tuple[str, str]]:
    cases = list(_PINNED)
    for pattern in sorted({*DEFAULT_EXCLUDES, *_documented_patterns()}):
        for depth in (0, 1, 3):
            cases.append((pattern, "/".join(["pkg"] * depth + [_sample(pattern)])))
        cases.append((pattern, "src/app.py"))
    return cases


def _finding(rel: str) -> Finding:
    return Finding(
        rule_id="B101",
        scanner="bandit",
        fingerprint="0" * 16,
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path=Path(rel),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="m",
    )


def _suppresses(pattern: str, rel: str) -> bool:
    rule = SuppressionRule(
        rule_id="B101",
        reason="reviewed",
        expires=datetime.date.today() + datetime.timedelta(days=30),
        paths=(pattern,),
    )
    return rule.matches(_finding(rel), ROOT)


def test_the_population_is_not_empty():
    assert len(_PINNED) >= 20
    assert _documented_patterns(), "the documentation shows no paths: example to hold"


@pytest.mark.parametrize(("pattern", "rel"), _population())
def test_a_suppression_glob_agrees_with_an_exclude_pattern(pattern: str, rel: str):
    excluded = is_excluded(ROOT / rel, ROOT, (pattern,))

    assert _suppresses(pattern, rel) is excluded, (
        f"paths: [{pattern!r}] {'suppresses' if not excluded else 'misses'} {rel}, "
        f"while exclude_patterns {'excludes' if excluded else 'keeps'} it"
    )


@pytest.mark.parametrize("pattern", _documented_patterns())
def test_every_documented_suppression_suppresses_what_it_names(pattern: str):
    """The example a reader copies has to work, at the root and below it."""
    assert _suppresses(pattern, _sample(pattern)), f"documented paths: [{pattern!r}] is inert"
    assert _suppresses(pattern, f"pkg/{_sample(pattern)}")


def test_the_star_slash_compatibility_is_still_a_suppression_only_extra():
    """D20's leading-slash rule keeps `*/src/app.py` entries written for
    absolute paths matching. It is the one place the two languages may differ,
    and only in the direction of the entry the operator already wrote."""
    assert _suppresses("*/src/app.py", "src/app.py")
    assert not _suppresses("*/src/app.py", "lib/app.py")


def test_a_leading_slash_anchors_an_entry_to_the_root():
    """The answer the changelog gives to "I meant only the root one"."""
    assert _suppresses("conftest.py", "pkg/conftest.py")
    assert _suppresses("/conftest.py", "conftest.py")
    assert not _suppresses("/conftest.py", "pkg/conftest.py")
