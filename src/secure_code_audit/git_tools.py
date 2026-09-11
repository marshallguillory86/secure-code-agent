"""Git helpers — repo root detection and LOC counting."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    """Walk up from `start` until a .git directory is found.

    Returns the nearest directory when no git repo is present, so a tarball
    or archive run is still supported.

    **A root is always a directory.** Auditing a single file outside a git
    repository used to return the file itself, and every path built under it
    became nonsense — `secure-code-agent one.py` died writing its report to
    `one.py/secure-code-report.md`.
    """
    cur = start.resolve()
    if not cur.is_dir():
        cur = cur.parent
    for parent in (cur, *cur.parents):
        if (parent / ".git").exists():
            return parent
    return cur


def is_excluded(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    """Check if `path` matches any exclude glob. Patterns are tested against
    the POSIX-relative path from `root`.

    A relative path is taken as relative to `root`, not to the process working
    directory. `Path.resolve()` would otherwise anchor it wherever the CLI
    happened to be invoked from, `relative_to(root)` would raise, and the
    answer would come back "not excluded" — fail-open, and silently. The
    adapter boundary now roots every finding path, so this is the second line
    rather than the first, but a rule that reads paths must not depend on the
    caller's shell.
    """
    if not path.is_absolute():
        path = root / path
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return False
    return any(_matches(rel, path.name, pat) for pat in patterns)


def _matches(rel: str, name: str, pat: str) -> bool:
    """One glob against one path, already made relative to the root.

    A trailing slash means "this directory, at any depth". Everything else is
    `fnmatch`, with one correction: `**/` reads as "at any depth" and every
    operator who writes it means to include depth zero. `fnmatch` does not,
    because the pattern carries a literal `/` — so `**/*_test.go` matched
    `router/context_test.go` and never `context_test.go`. Gin keeps its tests
    beside the code they test, so three of its four "production" secrets were
    test fixtures at the repository root, and that alone held it at F.

    **The `**/` strip has to happen on the directory branch too.** It did not,
    and so `**/__pycache__/` matched *nothing*: the branch searched for a
    literal `/**/__pycache__/` inside the path, and no real path contains
    `/**/`. A bare `__pycache__/` already matches at any depth, so the two
    spellings differed by everything — one worked and the one this
    repository's own config used was inert. `.pyc` files were scanned as
    source the whole time, and CI caught it only because a compiled test
    fixture tripped a secrets rule.

    An inert exclude pattern is the worst kind of configuration defect: it
    reads as intent, it never errors, and the only symptom is findings the
    operator believed they had excluded.
    """
    if pat.endswith("/"):
        bare = pat[3:] if pat.startswith("**/") else pat
        if not bare:  # a lone `**/` would otherwise exclude the entire tree
            return False
        return rel.startswith(bare) or f"/{bare}" in f"/{rel}/"
    bare = pat[3:] if pat.startswith("**/") else pat
    return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, bare) or fnmatch.fnmatch(name, bare)


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
    skip: Iterable[Path] = (),
    docs_patterns: Iterable[str] = (),
) -> tuple[int, int, int]:
    """Non-blank in-scope lines, split into (primary, test, docs).

    The split exists because the score's denominator has to move with its
    numerator. Scoring primary-tree findings over a LOC count that included the
    test tree would understate every repository in proportion to how well it is
    tested — the same numerator/denominator mismatch that `exclude_patterns`
    already caused once, arriving by a different door.

    Documentation is split for the same reason, and was not: its *findings*
    move to their own axis and out of the score, while its *lines* stayed in
    the primary denominator. FastAPI carries 7,160 lines of `docs/en/data/`
    — translator and contributor lists — diluting the count its code is
    graded against. Third occurrence of one mismatch.

    `skip` names the run's own artifacts — the report, the baseline, the
    suppressions file. Dropping their *findings* without dropping their
    *lines* is that same mismatch a third time: an audit that wrote a
    12,000-line JSON report into the tree scored the next run over a
    denominator inflated by its own output, and two identical audits of an
    unchanged repository returned 0.00 and 4.25.
    """
    test_patterns = tuple(test_patterns)
    docs_patterns = tuple(docs_patterns)
    skip = {p.resolve() for p in skip}
    primary = 0
    test = 0
    docs = 0
    # `rglob` on a file yields nothing, so a single-file audit reported zero
    # lines — and a zero denominator is not normalised at all, so the grade
    # became the raw subtotal. Auditing one file is supported; it should be
    # measured against that file.
    candidates = root.rglob("*") if root.is_dir() else [root]
    for path in candidates:
        if not path.is_file():
            continue
        if path.resolve() in skip:
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
        elif docs_patterns and is_test_path(path, root, docs_patterns):
            docs += lines
        else:
            primary += lines
    return primary, test, docs
