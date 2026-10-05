"""`exclude_patterns` must stop the scan, not just hide the findings.

The decision register states the contract plainly — *"`exclude_patterns`
stops the scan and leaves no trace in the report"* (D26's context). Only the
second half was ever true. Patterns filtered findings and LOC *after* the
scanners ran, and every adapter was handed the bare target root, so excluded
directories were scanned in full and then discarded.

**What that cost, measured on this repository.** `calibration/.corpus/` holds
342 MB of cloned third-party repositories — webgoat, gson, commons-lang —
with ten `pom.xml` files between them. It is the first entry an operator
would think to exclude, and it is in `paths.exclude_patterns`. Trivy was
still handed the root, walked into it, found Java projects, and resolved
their dependencies against Maven Central:

    FATAL  remote Maven repository returned 429 Too Many Requests
           Retry-After: 1313.

That rate limit is why `trivy` — a *required* scanner — failed, and why all
sixty committed rows in `.secure-code/history.jsonl` read
`coverage_complete: false`. It also hid 26 real dependency findings in
`uv.lock`, because trivy is the only scanner in the floor that reads it.
Skipping the excluded directory: **exit 0 in 51s** instead of failing after
minutes of backoff.

**The design invariant, which is what makes this safe.** The existing
finding-level filter stays authoritative. Passing exclusions to a tool is an
*optimisation* — it saves work and network egress — and must never be the
only thing excluding a path. So a tool that ignores the flag, or a pattern
this translation declines to pass on, changes nothing about the report. That
is deliberate: over-excluding would silently stop scanning real code, which
is the same class of silence this project counts as a defect.

Only patterns that unambiguously name a directory subtree are passed down.
The pattern language is `git_tools.matches_pattern` (D21), where a trailing
`/` means "this directory at any depth" — that form translates cleanly into
every tool's own flag. Bare names and file globs do not, so they are left to
the post-filter rather than guessed at.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from secure_code_audit.config import Config
from secure_code_audit.scanners._exclusions import as_regex, directory_excludes
from secure_code_audit.scanners.bandit_scanner import BanditScanner
from secure_code_audit.scanners.checkov_scanner import CheckovScanner
from secure_code_audit.scanners.semgrep_scanner import SemgrepScanner
from secure_code_audit.scanners.trivy_scanner import TrivyScanner

#: The shape that actually bit: a vendored clone tree, plus the usual suspects.
_PATTERNS = [
    "calibration/.corpus/",
    ".venv/",
    "node_modules/",
    "**/__pycache__/",
    "**/*.min.js",
    "src/secure_code_audit/standards.py",
]


# --- the translation ------------------------------------------------------


def test_directory_patterns_are_offered_to_the_tools():
    """A trailing slash means "this directory", in every tool's language."""
    dirs = directory_excludes(_PATTERNS)

    assert "calibration/.corpus" in dirs
    assert ".venv" in dirs
    assert "node_modules" in dirs


def test_file_globs_and_bare_paths_are_left_to_the_post_filter():
    """The conservative half, and the reason this cannot hide real code.

    `**/*.min.js` and a bare file path have no unambiguous directory meaning
    to hand a tool. Guessing would risk over-excluding, so they are not
    passed down at all — the finding-level filter already removes them, and
    it remains the authority.
    """
    dirs = directory_excludes(_PATTERNS)

    assert not any(d.endswith(".min.js") for d in dirs), dirs
    assert not any("standards.py" in d for d in dirs), dirs


def test_a_recursive_directory_pattern_keeps_its_recursion():
    """`**/__pycache__/` means that directory at any depth, which every tool
    expresses the same way."""
    dirs = directory_excludes(["**/__pycache__/"])

    assert dirs == ("**/__pycache__",), dirs


def test_nothing_configured_offers_nothing():
    assert directory_excludes([]) == ()


# --- checkov's regex, the one translation that can over-match --------------


def test_a_directory_pattern_becomes_an_anchored_regex():
    """Checkov's `--skip-path` is a regex, not a glob.

    Handing it a path unescaped is the over-exclusion risk this design is
    built to avoid: `calibration/.corpus` as a regex has `.` matching any
    character, so it would also skip `calibration/Xcorpus`. Harmless here and
    not harmless in general — a dot in a directory name is ordinary.
    """
    assert as_regex("calibration/.corpus") == r"calibration/\.corpus"


def test_the_recursive_prefix_becomes_a_path_wildcard():
    """`**/x` means "x at any depth", including the root."""
    pattern = as_regex("**/__pycache__")

    assert re.search(pattern, "src/a/__pycache__/x.pyc")
    assert re.search(pattern, "__pycache__/x.pyc"), "the root case is the one `**/` includes"


def test_the_regex_does_not_match_a_merely_similar_name():
    """The falsifier for the escaping: a near-miss must not be skipped."""
    pattern = as_regex("calibration/.corpus")

    assert re.search(pattern, "calibration/.corpus/webgoat/pom.xml")
    assert not re.search(pattern, "calibration/Xcorpus/webgoat/pom.xml")


def test_regex_metacharacters_in_a_directory_name_are_literal():
    """A directory called `a+b` or `(old)` must not become a regex operator."""
    assert re.search(as_regex("a+b"), "a+b/f.tf")
    assert not re.search(as_regex("a+b"), "aab/f.tf")


def test_the_translation_never_yields_an_empty_or_root_pattern():
    """A pattern that normalised to "" or "/" would exclude everything.

    The one outcome that would be worse than the defect: a tool told to skip
    the whole tree would report nothing and — before D33 — that scanned
    nothing would have graded A+.
    """
    dirs = directory_excludes(["/", "./", "", "   ", "//"])

    assert all(d.strip(" ./") for d in dirs), dirs
    assert "" not in dirs
    assert "/" not in dirs


# --- the adapters ---------------------------------------------------------


def _argv_from(monkeypatch, scanner_cls, config: Config) -> list[str]:
    """Run an adapter far enough to capture the argv it would execute."""
    seen: list[list[str]] = []

    monkeypatch.setattr(scanner_cls, "is_available", lambda self, cfg=None: True)
    monkeypatch.setattr(scanner_cls, "command", (scanner_cls.binary,), raising=False)

    def fake_exec(self, args, **kwargs):
        seen.append(list(args))
        return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner_cls, "_exec", fake_exec)
    scanner_cls().scan(Path("/repo"), config)
    assert seen, "the adapter never executed anything"
    return seen[0]


@pytest.mark.parametrize(
    ("scanner_cls", "flag", "expected"),
    [
        (TrivyScanner, "--skip-dirs", "calibration/.corpus"),
        (SemgrepScanner, "--exclude", "calibration/.corpus"),
        # bandit already did this, with the long form of `-x`.
        (BanditScanner, "--exclude", "calibration/.corpus"),
        # checkov's flag takes a regex, so the directory arrives escaped —
        # that *is* the excluded path in checkov's own language.
        (CheckovScanner, "--skip-path", r"calibration/\.corpus"),
    ],
    ids=lambda v: getattr(v, "name", str(v)),
)
def test_each_capable_adapter_passes_the_excluded_directory(
    monkeypatch, scanner_cls, flag, expected
):
    """The defect: every adapter was handed the bare root.

    Each tool's own flag, verified against its `--help` rather than assumed:
    trivy `--skip-dirs`, semgrep `--exclude`, bandit `-x`, checkov
    `--skip-path`.
    """
    config = replace(Config(), exclude_patterns=list(_PATTERNS))

    argv = _argv_from(monkeypatch, scanner_cls, config)

    assert flag in argv, f"{scanner_cls.name} never passed {flag}: {argv}"
    joined = " ".join(argv)
    assert expected in joined, (
        f"{scanner_cls.name} was told to scan a directory the operator excluded: {argv}"
    )


@pytest.mark.parametrize(
    "scanner_cls",
    [TrivyScanner, SemgrepScanner, BanditScanner, CheckovScanner],
    ids=lambda v: v.name,
)
def test_no_exclusions_configured_adds_no_flag(monkeypatch, scanner_cls):
    """An empty list must not produce a bare flag with no value.

    `--skip-dirs` with nothing after it either consumes the target path as its
    value or errors, and both of those are worse than not passing it.
    """
    config = replace(Config(), exclude_patterns=[])

    argv = _argv_from(monkeypatch, scanner_cls, config)

    assert "--skip-dirs" not in argv
    assert "--skip-path" not in argv
    assert "--exclude" not in argv


@pytest.mark.parametrize(
    "scanner_cls",
    [TrivyScanner, SemgrepScanner, BanditScanner, CheckovScanner],
    ids=lambda v: v.name,
)
def test_the_target_is_still_scanned(monkeypatch, scanner_cls):
    """The falsifier. Excluding things must not stop the scan happening.

    Without this, "pass the excludes down" could be satisfied by an adapter
    that excluded the target itself, which is the over-exclusion this design
    is built to avoid.
    """
    config = replace(Config(), exclude_patterns=list(_PATTERNS))

    argv = _argv_from(monkeypatch, scanner_cls, config)

    assert any("/repo" in a for a in argv), argv
