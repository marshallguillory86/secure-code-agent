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


def loc_under(root: Path, include_exts: Iterable[str], excludes: Iterable[str]) -> int:
    """Best-effort LOC count for the scoring normalizer. Counts non-blank
    lines across in-scope files; skips binary content."""
    total = 0
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
        total += sum(1 for line in text.splitlines() if line.strip())
    return total
