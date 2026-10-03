"""A `paths:` glob in `.scignore.yaml` must match something.

A suppression is a reviewed decision with a reason and an expiry. A glob
that matches no tracked file is none of those things any more: it is a
decision about code that has been renamed or deleted, and it reads as
active protection while protecting nothing. Deleting a module and leaving
its suppression behind is the ordinary way to get there, and nothing errors
when you do.

**What this does not catch**, stated because the near miss that prompted it
was exactly this gap. Splitting `Scanner` into its four jobs moved the
subprocess code out of `scanners/base.py` into `_execution.py` and
`_resolution.py`. The `B404` and `B603` entries still named `base.py`, so
four reviewed findings came back as new work -- but `base.py` still exists,
so every glob still matched a tracked file and a check at this strength
passes. The stronger property is "every entry still suppresses at least one
current finding", which needs a scan rather than a parse; it is recorded as
an open question in `docs/product-intent.md` rather than claimed here.

So this is the weaker half, and it is worth having on its own: the repo has
had this exact class three times over -- a branch-protection rule naming two
contexts that did not exist, a `> Status:` header pattern matching no
document, and a half-applied action pin. The shape is always a rule whose
subject is gone, with nothing asking whether it still has one.

It matches with the product's own matcher -- `SuppressionRule.matches` uses
exactly this pair of calls -- so the lint and the thing it checks cannot
disagree about what a glob means.
"""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

import pytest
import yaml

from secure_code_audit.git_tools import matches_pattern

REPO = Path(__file__).resolve().parents[2]
SCIGNORE = REPO / ".scignore.yaml"


def _tracked_paths() -> list[str]:
    """Repository-relative paths of tracked files, as findings carry them."""
    r = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in r.stdout.splitlines() if line]


def _glob_matches_any(glob: str, paths: list[str]) -> bool:
    """The product's own test, from `SuppressionRule.matches`."""
    return any(matches_pattern(p, glob) or fnmatch.fnmatch(f"/{p}", glob) for p in paths)


def _declared_globs(text: str) -> list[tuple[int, str, str]]:
    """Every `paths:` glob, as (entry number, rule_id, glob)."""
    entries = yaml.safe_load(text) or []
    return [
        (i, str(entry.get("rule_id", "?")), str(glob))
        for i, entry in enumerate(entries, start=1)
        if isinstance(entry, dict)
        for glob in (entry.get("paths") or [])
    ]


def test_there_are_globs_to_check():
    """A parse that yielded nothing would make the check below vacuous."""
    assert _declared_globs(SCIGNORE.read_text(encoding="utf-8")), (
        f"no paths: globs parsed out of {SCIGNORE}"
    )


def test_the_detector_bites_on_a_glob_that_matches_nothing():
    """Keeps the real check honest.

    `matches_pattern` treats a bare directory name as a prefix at any
    depth. An over-permissive reading would call every glob matched, and
    this lint would then pass against a suppression whose file is gone --
    a green check proving nothing, which is worse than no check.
    """
    paths = ["src/secure_code_audit/scanners/_execution.py", "tests/unit/test_x.py"]
    assert _glob_matches_any("*/src/secure_code_audit/scanners/_execution.py", paths)
    assert not _glob_matches_any("*/src/secure_code_audit/scanners/base.py", paths), (
        "the detector called a stale glob matched"
    )


@pytest.mark.parametrize(
    ("entry", "rule_id", "glob"),
    _declared_globs(SCIGNORE.read_text(encoding="utf-8")),
    ids=lambda v: str(v),
)
def test_every_suppression_path_matches_a_tracked_file(entry: int, rule_id: str, glob: str):
    """Prevents a suppression that silently stopped covering anything."""
    assert _glob_matches_any(glob, _tracked_paths()), (
        f".scignore.yaml entry #{entry} ({rule_id}) has paths glob {glob!r}, "
        "which matches no tracked file. Either the code moved and the glob "
        "must follow it, or the suppression has outlived its subject and "
        "should be deleted."
    )
