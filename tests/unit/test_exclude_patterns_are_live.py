"""An exclude pattern that matches nothing is worse than no pattern.

`**/__pycache__/` matched **nothing**. The directory branch of `_matches`
searched for a literal `/**/__pycache__/` inside the path, and no real path
contains `/**/`. The `**/` strip existed only on the file branch, so
`**/*_test.go` worked and `**/__pycache__/` did not — two spellings of the
same intent, one live and one inert.

This repository's own config used the inert spelling, so **`.pyc` files were
scanned as source the whole time**. Nothing reported it, because an inert
exclude has no symptom of its own: it reads as intent, it never errors, and
the only sign is findings the operator believed they had excluded. It
surfaced by accident when a compiled test fixture tripped a secrets rule and
failed CI.

The tests below are the structural form: for every directory pattern, the
`**/`-prefixed spelling and the bare one must agree, and every directory
pattern shipped in `DEFAULT_EXCLUDES` must actually match something.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.config import DEFAULT_EXCLUDES
from secure_code_audit.git_tools import is_excluded

ROOT = Path("/repo")

#: Directory patterns shipped by default, in both spellings.
_DIRECTORY_DEFAULTS = sorted({p for p in DEFAULT_EXCLUDES if p.endswith("/")})

#: File patterns shipped by default. Covered for the same reason, on the
#: other branch of `_matches`.
#:
#: The `maintainability-agent` maintainer hit the identical inert-directory
#: defect and their first fix stripped `**/` from *every* pattern, anchoring
#: `**/generated/*.py` to the repository root. A file pattern already matches
#: through `fnmatch`, where `*` crosses separators, so it needs no help and
#: is harmed by the help. Their suite caught it; mine would not have, because
#: the structural check below only walked the directory half — half a
#: structural rule, which is the kind that reads as covered.
_FILE_DEFAULTS = sorted({p for p in DEFAULT_EXCLUDES if not p.endswith("/")})


def _sample_for(pattern: str) -> str:
    """A filename the pattern is meant to match."""
    bare = pattern[3:] if pattern.startswith("**/") else pattern
    return bare.replace("*", "sample")


def _excluded(rel: str, *patterns: str) -> bool:
    return is_excluded(ROOT / rel, ROOT, patterns)


# ---------------------------------------------------------------------------
# The two spellings must agree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("directory", ["__pycache__", ".secure-code", "node_modules", "dist"])
@pytest.mark.parametrize("depth", [0, 1, 3])
def test_the_starstar_spelling_matches_what_the_bare_one_matches(directory: str, depth: int):
    """`**/x/` and `x/` both mean "this directory, at any depth"."""
    rel = "/".join(["pkg"] * depth + [directory, "file.py"])

    assert _excluded(rel, f"{directory}/") is True, "the bare spelling regressed"
    assert _excluded(rel, f"**/{directory}/") is True, (
        f"**/{directory}/ is inert — it reads as intent and matches nothing"
    )


@pytest.mark.parametrize("pattern", _DIRECTORY_DEFAULTS)
def test_every_shipped_directory_pattern_matches_something(pattern: str):
    """A default nobody can trip is a default nobody has."""
    name = pattern[3:] if pattern.startswith("**/") else pattern
    rel = f"{name.rstrip('/')}/file.txt"

    assert _excluded(rel, pattern), f"{pattern} matches nothing"


@pytest.mark.parametrize("pattern", _DIRECTORY_DEFAULTS)
def test_every_shipped_directory_pattern_matches_at_depth(pattern: str):
    name = pattern[3:] if pattern.startswith("**/") else pattern
    rel = f"a/b/{name.rstrip('/')}/file.txt"

    assert _excluded(rel, pattern), f"{pattern} does not match below the root"


# ---------------------------------------------------------------------------
# The file branch, which a uniform `**/` strip would have killed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern", _FILE_DEFAULTS)
@pytest.mark.parametrize("depth", [0, 1, 3])
def test_every_shipped_file_pattern_matches_at_every_depth(pattern: str, depth: int):
    """`**/*.min.js` and `**/*.lock` must match at the root and below it.

    This is the assertion that fails if someone "simplifies" `_matches` by
    stripping `**/` from every pattern and anchoring the result — the fix
    that creates a new dead exclude while closing the old one.
    """
    rel = "/".join(["pkg"] * depth + [_sample_for(pattern)])

    assert _excluded(rel, pattern), f"{pattern} does not match {rel}"


def test_a_file_pattern_is_not_anchored_to_the_root():
    """The specific regression, named. `*` crosses separators in `fnmatch`,
    so the file branch never needed the `**/` strip that the directory branch
    did."""
    assert _excluded("a/b/c/vendor.min.js", "**/*.min.js") is True
    assert _excluded("deep/nested/path/poetry.lock", "**/*.lock") is True


def test_a_file_pattern_still_discriminates():
    """Matching everything would pass the tests above and exclude the repo."""
    assert _excluded("src/app.py", "**/*.min.js") is False
    assert _excluded("src/app.py", "**/*.lock") is False


# ---------------------------------------------------------------------------
# It must still be a directory match, not a substring one
# ---------------------------------------------------------------------------


def test_a_similarly_named_directory_is_not_matched():
    assert _excluded("__pycache__extra/x.py", "**/__pycache__/") is False
    assert _excluded("my__pycache__/x.py", "**/__pycache__/") is False


def test_the_directory_itself_is_matched_not_only_its_contents():
    """A path *equal* to the excluded directory is excluded.

    `_matches` compares against `f"/{rel}/"`, so a bare `src/__pycache__`
    matches too. That is deliberate — `is_excluded` is called on directories
    as well as files during the walk, and a rule that excluded a directory's
    contents but not the directory would be a strange thing to have to
    reason about.

    It does mean a *file* named exactly `__pycache__` would be excluded.
    Noted rather than fixed: it is vanishingly rare, excluding it is
    harmless, and narrowing this to satisfy a hypothetical would break the
    directory walk, which is not.
    """
    assert _excluded("src/__pycache__", "**/__pycache__/") is True


def test_an_unrelated_path_is_untouched():
    assert _excluded("src/app.py", "**/__pycache__/") is False


def test_a_lone_double_star_excludes_nothing():
    """`**/` strips to the empty string, and `startswith("")` is true for
    every path — it would have excluded the entire tree and reported a clean
    repository with nothing scanned."""
    assert _excluded("src/app.py", "**/") is False
    assert _excluded("anything/at/all.py", "**/") is False


# ---------------------------------------------------------------------------
# The case that actually broke
# ---------------------------------------------------------------------------


def test_compiled_python_under_a_nested_pycache_is_excluded():
    """The exact path that failed CI: a compiled test module, whose bytecode
    still carries the string constants of its source."""
    assert _excluded(
        "tests/unit/__pycache__/test_x.cpython-311-pytest-9.1.1.pyc", *DEFAULT_EXCLUDES
    )


def test_the_repositorys_own_config_excludes_compiled_python():
    """Read from disk rather than reconstructed — the defect was in the
    configured value, not in the default."""
    import json

    repo_root = Path(__file__).resolve().parents[2]
    patterns = json.loads((repo_root / "secure-code-agent.json").read_text(encoding="utf-8"))[
        "paths"
    ]["exclude_patterns"]

    assert is_excluded(repo_root / "tests/unit/__pycache__/test_x.pyc", repo_root, patterns), (
        "this repository is scanning its own bytecode again"
    )
