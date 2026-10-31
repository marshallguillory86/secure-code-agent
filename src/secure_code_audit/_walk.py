"""The one walk of an audited tree.

`Path.rglob` descends into `.git`, and on Python 3.11 it raises
`FileNotFoundError` when a directory it listed is gone by the time it opens
it. Git adds and removes worktrees under `.git/worktrees` while it works, so an
audit running beside it could end on a directory that was never part of the
tree being audited. This walk never enters `.git`, never follows a symlinked
directory out of the tree, and treats a directory it cannot open as empty:
what vanished was not there to audit. Every walk of the audited tree uses it;
a structural test refuses `rglob` anywhere else in the package.

Nothing here needs `.git`: history scanners read it through `git` itself.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path


def walk(root: Path, pattern: str = "*") -> Iterator[Path]:
    """Every file and directory below `root` whose name matches `pattern`, as `rglob` gives them."""
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(name for name in subdirectories if name != ".git")
        base = Path(directory)
        for name in (*subdirectories, *sorted(names)):
            if fnmatch.fnmatchcase(name, pattern):
                yield base / name
