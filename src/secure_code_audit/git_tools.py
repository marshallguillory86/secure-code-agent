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
        return _matches_directory(rel, bare.rstrip("/"))
    bare = pat[3:] if pat.startswith("**/") else pat
    return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, bare) or fnmatch.fnmatch(name, bare)


def _matches_directory(rel: str, name: str) -> bool:
    """Does any directory component of `rel` match the glob `name`?

    **The directory branch did no globbing at all.** It compared with
    `startswith` and a substring test, so a pattern holding a glob was
    *inert*: `*.egg-info/` matched nothing while `src/pkg.egg-info/` sat in
    the tree being scanned, and `build-*/` and `test_*/` were the same. The
    `**/` spelling was one instance of the class and fixing it left the rest
    — an instance mistaken for a class, twice over, since
    `maintainability-agent` found the same thing in its own matcher (its
    D156) and reported the generalisation back.

    **The final component is excluded from the comparison.** A trailing slash
    says *directory*, so `*.egg-info/` must not match a **file** named
    `notes.egg-info` — and it did, until this was narrowed. Every caller
    filters to `path.is_file()` before asking, or asks about a finding's file
    path, so nothing prunes directories and nothing needs the final component
    to match. An earlier test asserted that it did; that was documenting an
    accident as intent, and it is corrected alongside this.

    **A pattern may name more than one segment.** `calibration/.corpus/` and
    `src/generated/` are ordinary things to write, and the first version of
    this globbed one component at a time — so no single component ever equalled
    `calibration/.corpus` and the pattern went inert. That regression was
    introduced *by* the fix for inert patterns and was caught one task later,
    when the repository inventory started walking nineteen cloned corpus
    repositories it was supposed to be excluding. Segments are matched as a
    consecutive run.

    An inert exclude is the worst kind of configuration defect: it reads as
    intent, it never errors, and the only symptom is findings the operator
    believed they had excluded.
    """
    wanted = [segment for segment in name.split("/") if segment]
    if not wanted:
        return False
    # Directory components only: the last element of `rel` is the file.
    components = rel.split("/")[:-1]
    span = len(wanted)
    for start in range(len(components) - span + 1):
        if all(
            fnmatch.fnmatch(component, pattern)
            for component, pattern in zip(components[start : start + span], wanted, strict=True)
        ):
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


def _git() -> str | None:
    """Resolve `git` to an absolute path, once.

    Invoking a bare `git` leaves the choice of binary to `PATH`, which is the
    same class of exposure this project refuses for scanner commands — and
    Bandit says so (`B607`, partial executable path). Resolving it is cheaper
    than suppressing it, and consistent with how every scanner adapter here
    already resolves its tool.
    """
    import shutil  # noqa: PLC0415

    return shutil.which("git")


def head_commit(root: Path) -> str | None:
    """The commit an audit was taken at, or None outside a git repository.

    Recorded in the JSON report so a later `--verify-against` can ask *what
    actually changed* rather than inferring it from two finding sets. Two
    reports tell you which findings moved; they cannot tell you that an agent
    also rewrote three unrelated modules, and that is the question the work
    order's constraints exist to answer.
    """
    import subprocess  # noqa: PLC0415 — only needed on this path

    git = _git()
    if git is None:
        return None
    try:
        completed = subprocess.run(
            [git, "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    sha = completed.stdout.strip()
    return sha or None


def changed_files(root: Path, since: str) -> tuple[frozenset[str], str | None] | tuple[None, str]:
    """Repository-relative paths changed since `since`, or a reason it is unknown.

    Includes uncommitted work, because an agent handed a work order usually
    has not committed. `git diff --name-only <sha>` covers tracked
    modifications against the working tree; untracked files are asked for
    separately, since a newly added module is exactly the kind of collateral
    worth seeing.

    Returns `(paths, None)` on success and `(None, reason)` when the answer is
    unavailable — never an empty set standing in for "could not tell", which
    would read as "nothing changed" and turn a failed measurement into a
    clean bill of health.
    """
    import subprocess  # noqa: PLC0415

    git = _git()
    if git is None:
        return None, "git is not on PATH"

    def _run(args: list[str]) -> tuple[str, str | None]:
        try:
            completed = subprocess.run(
                [git, "-C", str(root), *args],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return "", f"git failed: {type(exc).__name__}"
        if completed.returncode != 0:
            return "", (completed.stderr.strip().splitlines() or ["git failed"])[0]
        return completed.stdout, None

    tracked, reason = _run(["diff", "--name-only", since])
    if reason is not None:
        return None, reason
    untracked, reason = _run(["ls-files", "--others", "--exclude-standard"])
    if reason is not None:
        return None, reason
    paths = {line.strip() for line in (tracked + untracked).splitlines() if line.strip()}
    return frozenset(paths), None
