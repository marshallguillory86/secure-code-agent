"""Git helpers — repo root detection and LOC counting."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    """Walk up from `start` until a .git directory is found. Returns `start`
    if no git repo is present (a tarball / archive run is still supported)."""
    cur = start.resolve()
    for parent in (cur, *cur.parents):
        if (parent / ".git").exists():
            return parent
    return cur


def is_excluded(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    """Check if `path` matches any exclude glob. Patterns are tested against
    the POSIX-relative path from `root`."""
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return False
    for pat in patterns:
        if pat.endswith("/"):
            if rel.startswith(pat) or f"/{pat}" in f"/{rel}/":
                return True
        elif fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.name, pat):
            return True
    return False


def in_scope(path: Path, include_exts: Iterable[str]) -> bool:
    """Does this path match the configured include_extensions?
    Dockerfile is matched by basename."""
    name = path.name
    for ext in include_exts:
        if ext.startswith("."):
            if name.endswith(ext):
                return True
        elif name == ext or name.startswith(f"{ext}."):
            return True
    return False


def is_test_path(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    """Does this path belong to the repository's own test tree?

    Same matching as `is_excluded`, and deliberately so — an operator who can
    write an exclude pattern already knows how to write one of these.

    A path outside `root` is not a test path. An imported SARIF can name
    absolute paths from another machine, and guessing that someone else's
    `/build/tests/` is our test tree would move real findings out of the score.
    """
    return is_excluded(path, root, patterns)


def loc_under(
    root: Path,
    include_exts: Iterable[str],
    excludes: Iterable[str],
    test_patterns: Iterable[str] = (),
) -> tuple[int, int]:
    """Non-blank in-scope lines, split into (primary, test).

    The split exists because the score's denominator has to move with its
    numerator. Scoring primary-tree findings over a LOC count that included the
    test tree would understate every repository in proportion to how well it is
    tested — the same numerator/denominator mismatch that `exclude_patterns`
    already caused once, arriving by a different door.
    """
    test_patterns = tuple(test_patterns)
    primary = 0
    test = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if is_excluded(path, root, excludes):
            continue
        if not in_scope(path, include_exts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = sum(1 for line in text.splitlines() if line.strip())
        if test_patterns and is_test_path(path, root, test_patterns):
            test += lines
        else:
            primary += lines
    return primary, test
