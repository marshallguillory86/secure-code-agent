"""One action, one pin — everywhere in `.github/`.

GitHub Actions here are pinned by commit SHA with a trailing version comment,
because a tag is mutable and a SHA is the only reference that says what
actually ran::

    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

A dependabot bump updated `actions/checkout` in two of the three jobs of
`.github/workflows/ci.yml` and missed the third, which still sits on the v6
SHA. Nothing failed. Nothing could: every pin is individually valid YAML, the
workflow runs, and the only symptom is that one job silently checks out with an
older action than its siblings — the half-applied pin that reads as intent and
never errors.

That is the third instance of this class in this repository. The others were a
`> Status:` header pattern that matched no document (`test_docs_are_current.py`)
and a branch-protection rule naming two contexts that did not exist. The shape
is always the same: a rule applied to some of its subjects, with no mechanism
asking whether it was applied to all of them.

So this asks that question. For every `uses:` reference under `.github/` — the
workflows and the composite actions both — the SHA and the version comment for
a given action must be the same in every place it appears.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GITHUB = REPO / ".github"

#: `uses:` as a workflow or composite action actually writes it, with the
#: optional trailing version comment captured separately. The comment is part
#: of the pin, not decoration: it is the only human-readable statement of which
#: release a SHA is, and a stale one misleads the next reader and the next bump.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)\s*(?:#\s*(?P<comment>.*?))?\s*$")

#: Actions deliberately held on a different pin from their other call sites.
#:
#: Maps `owner/repo` to the reason. An entry here is a documented decision that
#: a reviewer can argue with — not a silent skip, and not a place to park a
#: missed bump. `actions/checkout` is **not** in here: its disagreement is the
#: defect this module exists to catch, and adding it would delete the test.
_DELIBERATELY_DIVERGENT_PINS: dict[str, str] = {}


def _workflow_sources() -> list[Path]:
    """Every YAML file under `.github/`, in a stable order.

    Both suffixes, because this repository already uses both (`ci.yml`,
    `release.yaml`) and a sweep that knows only one of them is a sweep that
    misses a file. `rglob` rather than a fixed list, so a new workflow or a new
    composite action is covered the day it lands instead of the day someone
    remembers this test.
    """
    found = {p for suffix in ("*.yml", "*.yaml") for p in GITHUB.rglob(suffix)}
    return sorted(found)


class _Pin:
    """One `uses:` reference: where it is, what it pins, what it claims to be."""

    def __init__(self, path: Path, line: int, action: str, sha: str, comment: str | None):
        self.path = path
        self.line = line
        self.action = action
        self.sha = sha
        self.comment = comment

    @property
    def where(self) -> str:
        return f"{self.path.relative_to(REPO)}:{self.line}"

    def __str__(self) -> str:
        shown = (
            f"{self.sha} # {self.comment}" if self.comment else f"{self.sha} (no version comment)"
        )
        return f"{self.where}  {self.action}@{shown}"


def _collect_pins() -> list[_Pin]:
    """Every externally pinned `uses:` reference under `.github/`.

    Local references (`./.github/actions/install-floor`) carry no SHA — they
    are this repository's own tree and move with it — so they are not pins and
    are not compared. Docker and reusable-workflow references are likewise left
    alone; neither appears here today, and neither is a SHA pin.

    The key is `owner/repo`, not the full `uses:` path. `github/codeql-action`
    ships several entry points (`init`, `analyze`, `upload-sarif`) out of one
    repository at one SHA, so two subpaths of it disagreeing is the same defect
    as two copies of `actions/checkout` disagreeing.
    """
    pins: list[_Pin] = []
    for path in _workflow_sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            match = _USES.match(line)
            if match is None:
                continue
            ref = match.group("ref")
            if ref.startswith((".", "/")) or ref.startswith("docker://") or "@" not in ref:
                continue
            target, _, sha = ref.rpartition("@")
            owner_repo = "/".join(target.split("/")[:2])
            comment = match.group("comment")
            pins.append(_Pin(path, number, owner_repo, sha, comment.strip() if comment else None))
    return pins


_PINS = _collect_pins()

_BY_ACTION: dict[str, list[_Pin]] = defaultdict(list)
for _pin in _PINS:
    _BY_ACTION[_pin.action].append(_pin)

#: Actions referenced from more than one place, which are the only ones that
#: can disagree with themselves.
_REPEATED = sorted(action for action, pins in _BY_ACTION.items() if len(pins) > 1)


@pytest.mark.parametrize("action", _REPEATED, ids=lambda a: a)
def test_every_reference_to_an_action_resolves_to_one_pin(action: str):
    """A bump that updates some call sites and not others leaves the repository
    running two versions of one action with nothing to say so."""
    if action in _DELIBERATELY_DIVERGENT_PINS:
        pytest.skip(f"{action}: {_DELIBERATELY_DIVERGENT_PINS[action]}")

    pins = _BY_ACTION[action]
    resolved = {(pin.sha, pin.comment) for pin in pins}

    assert len(resolved) == 1, (
        f"{action} is pinned {len(resolved)} different ways across {len(pins)} "
        f"reference(s); a bump updated some and missed others:\n"
        + "\n".join(f"  {pin}" for pin in sorted(pins, key=lambda p: (str(p.path), p.line)))
    )


def test_the_sweep_finds_the_workflow_files():
    """Non-vacuity guard: a renamed directory or a suffix this sweep does not
    know makes it examine nothing and pass forever.

    This repository's own history supplies the precedent — a version check here
    passed for every document by matching none of them.
    """
    found = [str(p.relative_to(REPO)) for p in _workflow_sources()]

    assert len(found) >= 4, (
        f"only {len(found)} YAML file(s) found under .github/: {found}. "
        f"The repository has workflows and at least one composite action; "
        f"finding almost none means the sweep is looking in the wrong place."
    )


def test_the_sweep_examines_the_pins_the_repository_actually_has():
    """Non-vacuity guard: a `uses:` pattern that stops matching turns the check
    above green without anything being fixed."""
    assert len(_PINS) >= 15, (
        f"only {len(_PINS)} pinned `uses:` reference(s) parsed out of "
        f"{len(_workflow_sources())} file(s). The workflows pin far more than "
        f"that, so the pattern has drifted from what they write."
    )

    assert len(_REPEATED) >= 4, (
        f"only {len(_REPEATED)} action(s) are referenced more than once: "
        f"{_REPEATED}. With fewer, nothing can disagree and the check means "
        f"nothing."
    )


def test_the_divergence_allowlist_names_actions_that_exist():
    """An exemption for an action nobody calls exempts nothing and rots in
    place, which is how an allowlist becomes a list of old opinions."""
    for action, reason in _DELIBERATELY_DIVERGENT_PINS.items():
        assert action in _BY_ACTION, (
            f"{action} is allowed to diverge but is not referenced anywhere under .github/"
        )
        assert reason.strip(), f"{action} is exempted with no stated reason"
