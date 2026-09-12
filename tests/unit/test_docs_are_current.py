"""Documentation that names a version must name the current one.

This drifted three separate times and a person had to notice each one, which
is the wrong mechanism. At v0.10.0 the repository still contained:

- `README.md` telling adopters `uses: ...@v0.3.0` — seven releases stale, and
  a working copy-paste that pins something ancient;
- `docs/product-intent.md` and `docs/architecture.md` headed **v0.3.0**;
- `docs/design.md` headed **v0.1 — MVP in flight**;
- `README.md` describing the v0.3.0 release blockers as open when all eight
  had closed a month earlier;
- `docs/ma-integration.md` documenting `schema_version: 1` and stating "a
  field may be added without a bump" — which contradicted the shipped
  contract *and* the rule agreed with the consumer, in the direction that
  fails silently.

**Not every version string is stale.** The register, the changelog and the
prose recounting the 0.4.0/0.3.0 stamping incident are history and must keep
their numbers. So this checks the two places that make a *claim about now*: a
document's `> Status:` header, and an Action reference someone will copy.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from secure_code_audit import __version__

REPO = Path(__file__).resolve().parents[2]
DOCS = sorted((REPO / "docs").glob("*.md"))

#: A version named anywhere in a `> Status:` line.
#:
#: The first version of this anchored the number as the *entire* bolded text,
#: so a real header — `**v0.10.0 — 2026-09-11.**` — never matched it and every
#: document fell through the "names no version" branch. The check passed for
#: every doc by examining none of them. Mutation-testing it found that; the
#: passing run did not.
_STATUS_VERSION = re.compile(r"\bv(?P<version>\d+\.\d+\.\d+)")

#: `uses: owner/secure-code-agent@v0.10.0` — a copy-pasteable pin.
_ACTION_REF = re.compile(r"secure-code-agent@v(?P<version>\d+\.\d+\.\d+)")

#: Headers that deliberately name something other than the current version,
#: because the document is a closed historical record rather than a claim
#: about the system as it stands.
_HISTORICAL = {"release-blockers.md"}


def _status_line(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8").split("\n")[:8]:
        if line.startswith("> Status:"):
            return line
    return None


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_doc_declares_its_status(doc: Path):
    """A document with no freshness claim cannot be checked, and six of them
    had none — which is how the others drifted unnoticed."""
    assert _status_line(doc) is not None, (
        f"{doc.name} has no `> Status:` header, so nothing can tell whether it "
        f"still describes the shipped tool"
    )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_a_doc_that_names_a_version_names_this_one(doc: Path):
    if doc.name in _HISTORICAL:
        return
    line = _status_line(doc)
    assert line is not None
    match = _STATUS_VERSION.search(line)
    if match is None:
        return  # a status that names no version claims nothing about one
    assert match.group("version") == __version__, (
        f"{doc.name} is headed v{match.group('version')} while the package is v{__version__}"
    )


def test_the_version_check_actually_examines_documents():
    """Non-vacuity guard for the check above.

    It silently examined nothing once already, because the pattern did not
    match the headers this repository actually writes. A rule that inspects
    no documents passes forever.
    """
    examined = [
        doc.name
        for doc in DOCS
        if doc.name not in _HISTORICAL
        and (line := _status_line(doc))
        and _STATUS_VERSION.search(line)
    ]

    assert len(examined) >= 8, (
        f"only {len(examined)} document(s) carry a version in their status "
        f"header: {examined}. The check is close to vacuous."
    )


def test_historical_docs_are_declared_rather_than_discovered():
    """The exemption list must name real files, or it silently exempts
    nothing and grows stale itself."""
    for name in _HISTORICAL:
        assert (REPO / "docs" / name).is_file(), f"{name} is exempted but does not exist"


# ---------------------------------------------------------------------------
# Action references, which are functional rather than descriptive
# ---------------------------------------------------------------------------

_REFERENCING = [
    REPO / "README.md",
    *sorted((REPO / "examples").rglob("*.yml")),
    *sorted((REPO / "examples").rglob("*.yaml")),
]


@pytest.mark.parametrize("path", _REFERENCING, ids=lambda p: p.name)
def test_every_action_reference_pins_the_current_release(path: Path):
    """A stale `uses:` is not a typo — it is a working instruction to run an
    old build, and it is the line an adopter copies first."""
    if not path.is_file():
        return
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        match = _ACTION_REF.search(line)
        if not match:
            continue
        assert match.group("version") == __version__, (
            f"{path.name}:{number} pins v{match.group('version')}; "
            f"the current release is v{__version__}"
        )


def test_the_sweep_is_not_vacuous():
    """At least one action reference must exist, or the test above passes by
    finding nothing — which is exactly how the stale pin survived."""
    found = sum(
        1
        for path in _REFERENCING
        if path.is_file() and _ACTION_REF.search(path.read_text(encoding="utf-8"))
    )

    assert found >= 2, f"expected action references in README and examples, found {found}"
