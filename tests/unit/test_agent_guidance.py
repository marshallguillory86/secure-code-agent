"""Shipped agent guidance cannot recommend a flag the CLI does not accept.

`docs/architecture.md` §3 row 3: agent guidance is written down in six places —
`instructions.py::_BODY`, `skills/secure-code-agent/SKILL.md`, the Copilot
prompt, three agent YAMLs, `README.md` and `docs/` — with nothing keeping them
in step. The recorded drift is specific and embarrassing: *"the `--changed-only`
deprecation updated four locations and missed two, leaving shipped agent
instructions recommending a flag that exits 2."*

**It then drifted the other way.** `--changed-only` shipped in 0.12.0, and six
documents went on saying it was reserved and exited 2 — so the guidance was
wrong in both directions within one release cycle, and the test below encoded
the first error while the second one shipped. A check that pins today's
answer is a check that has to be inverted every time the answer changes; what
this pins now is that **one** answer is given, and that it is the shipped one.

Generating five copies from one source is the doc's preferred fix and is a
larger change than it looks — these files are different formats for different
consumers, and the prose in each is deliberately shaped for its audience.

What is enforceable now is the half that actually caused harm. An agent reading
our own shipped instructions must not be told to pass something the CLI will
reject, and must not be told to pass something that always fails. Those are
mechanical facts, and a test can hold them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from secure_code_audit import instructions, remediation
from secure_code_audit.cli import _parser

REPO = Path(__file__).resolve().parent.parent.parent
SKILLS = REPO / "skills"

#: Wording that described `--changed-only` before it was implemented. Shipped
#: guidance may not carry it: an agent told the flag "exits 2" will not reach
#: for the PR-shaped audit that now exists, which is the same harm as the
#: original drift with the sign flipped.
STALE_CHANGED_ONLY = (
    "reserved",
    "not yet safely implemented",
    "not implemented",
    "exits 2",
    "exit code 2",
    "always fails",
)


#: Where an agent could read a recommendation from. `instructions.py` is
#: included by generating its body the way an operator would receive it.
def _guidance_documents() -> dict[str, str]:
    # `render()` is target-independent: every target receives the same body,
    # wrapped differently. One entry is therefore the whole of what
    # instructions.py ships.
    documents = {"instructions.py::render": instructions.render()}
    for path in sorted(SKILLS.rglob("*")):
        if path.is_file() and path.suffix in {".md", ".yaml", ".yml"}:
            documents[str(path.relative_to(REPO))] = path.read_text(encoding="utf-8")
    return documents


def _cli_flags() -> set[str]:
    flags: set[str] = set()
    for action in _parser()._actions:
        flags.update(action.option_strings)
    return flags


#: `--flag` as it appears in prose or a command line. Trailing punctuation and
#: markdown emphasis are stripped by the character class.
_FLAG_PATTERN = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")


def test_the_guidance_corpus_is_not_empty():
    """Guard against this whole file passing because it found no documents."""
    documents = _guidance_documents()

    assert documents, "no agent guidance was located; the paths must have moved"
    assert any(name.startswith("skills/") for name in documents)
    assert any(name.startswith("instructions.py::") for name in documents)


#: A line is an invocation when it names one of our console scripts. Flags on
#: such a line are ours by construction, so no allow-list of "plausibly ours"
#: names is needed — and unlike one, this catches a flag nobody thought to list.
_CONSOLE_SCRIPTS = ("secure-code-agent", "secure-code-audit")


def _invocation_flags(body: str) -> dict[str, str]:
    """Flags appearing on lines that invoke this tool, mapped to their line.

    Multi-line invocations continue with a trailing backslash, and YAML block
    scalars indent them, so a continuation is tracked rather than dropped —
    otherwise the flags most worth checking, the ones in a long example
    command, would be the ones skipped.
    """
    found: dict[str, str] = {}
    in_invocation = False
    for raw in body.splitlines():
        line = raw.rstrip()
        starts = any(script in line for script in _CONSOLE_SCRIPTS)
        if not (starts or in_invocation):
            continue
        for flag in _FLAG_PATTERN.findall(line):
            found.setdefault(flag, line.strip())
        in_invocation = line.endswith("\\") or (in_invocation and line.lstrip().startswith("--"))
    return found


@pytest.mark.parametrize("name", sorted(_guidance_documents()))
def test_no_shipped_guidance_invokes_a_flag_the_cli_would_reject(name: str):
    """An agent following our instructions must not hit `unrecognized arguments`.

    Checked on invocation lines rather than on every `--word` in the prose,
    because the docs legitimately name other tools' flags when explaining what
    a scanner is run with — `--only-verified` is TruffleHog's, not ours.
    """
    known = _cli_flags()

    offenders = {
        flag: line
        for flag, line in _invocation_flags(_guidance_documents()[name]).items()
        if flag not in known
    }

    assert offenders == {}, (
        f"{name} invokes {sorted(offenders)}, which this CLI does not accept:\n"
        + "\n".join(f"    {line}" for line in offenders.values())
    )


@pytest.mark.parametrize("name", sorted(_guidance_documents()))
def test_guidance_never_describes_changed_only_as_unimplemented(name: str):
    """The drift that shipped, in the direction it shipped the second time.

    `--changed-only` is real as of 0.12.0. Guidance still calling it reserved
    steers an agent away from the PR-shaped audit that exists, which is the
    original defect with the sign flipped.
    """
    body = _guidance_documents()[name]

    for line in body.splitlines():
        if "--changed-only" not in line:
            continue
        stale = [marker for marker in STALE_CHANGED_ONLY if marker in line.lower()]
        assert not stale, (
            f"{name} still describes --changed-only as {stale[0]!r}; it shipped "
            f"in 0.12.0:\n    {line.strip()}"
        )


def test_instructions_and_the_skill_agree_on_the_changed_only_status():
    """The two copies that disagreed, held together explicitly.

    Now in the shipped direction: whichever of them mentions the flag must
    describe what it does, not what it used to refuse to do.
    """
    rendered = instructions.render()
    skill = (SKILLS / "secure-code-agent" / "SKILL.md").read_text(encoding="utf-8")

    for body in (rendered, skill):
        if "--changed-only" not in body:
            continue
        lowered = body.lower()
        for marker in STALE_CHANGED_ONLY:
            assert marker not in lowered or "--changed-only" not in lowered.split(marker)[0][-400:]


def test_the_shipped_skill_recommends_the_flag():
    """Non-vacuity: a skill that simply stopped mentioning `--changed-only`
    would satisfy every assertion above while telling an agent nothing."""
    skill = (SKILLS / "secure-code-agent" / "SKILL.md").read_text(encoding="utf-8")
    # Whitespace-collapsed: the phrase wraps across lines in the shipped file,
    # and a re-wrap is not a change in what the guidance says.
    flat = " ".join(skill.lower().split())

    assert "--changed-only" in skill
    assert "no grade" in flat, "the skill names the flag without saying it issues no grade"


#: The debt markers this project's own risk ruleset looks for. Spelled as
#: fragments and joined, because a test file naming them is itself scanned.
_DEBT_MARKERS = tuple(f"{a}{b}" for a, b in (("TO", "DO"), ("FIX", "ME"), ("HA", "CK")))


def _shipped_prose() -> dict[str, str]:
    """Guidance text, plus the work order the product generates.

    The work order's own constants are included because that text *is*
    shipped prose: an agent reads it, and an operator sees it in
    `secure-code-remediation-prompt.md`. They are named explicitly rather
    than discovered, so adding a third block of prose to `remediation.py`
    without adding it here is a gap — which is what `test_the_prose_sweep_reads_something`
    is for.
    """
    documents = dict(_guidance_documents())
    documents["remediation.py::_HARD_CONSTRAINTS"] = remediation._HARD_CONSTRAINTS
    documents["remediation.py::_PATCH_PROTOCOL"] = remediation._PATCH_PROTOCOL
    return documents


def test_the_prose_sweep_reads_something():
    """A corpus that collected nothing would make the check below vacuous."""
    documents = _shipped_prose()

    assert len(documents) >= 3, sorted(documents)
    assert any("constraint" in text.lower() for text in documents.values()), (
        "the work order's constraint list is not in the corpus"
    )


def test_the_debt_marker_detector_catches_a_reintroduced_one():
    """The falsifier.

    The check above asserts an empty list against the real corpus, and a
    detector whose markers were misspelled would pass it for ever. This
    feeds it the exact sentence that was removed and requires a hit.
    """
    reintroduced = f'9. Add a test. No "{_DEBT_MARKERS[0]}: add test later".'

    assert any(marker in reintroduced for marker in _DEBT_MARKERS)
    assert not any(
        marker in "9. Add a test. Do not defer the test to a later change."
        for marker in _DEBT_MARKERS
    ), "the detector fires on the wording that replaced it"


def test_no_shipped_guidance_carries_a_debt_marker():
    """Guidance that forbids deferred work must not be written with the token.

    The work order's constraint 9 read `No "<marker>: add test later"`, and
    the suppression guidance's example of a bad reason *was* that marker.
    Both are instructions against deferring work, written with the literal
    they warn about — so this project's own `debt-marker` risk rule matched
    its own advice, four times over.

    They were reworded, and this is what stops them coming back. The risk
    rule that found them lives in maintainability-agent, which does not run
    in CI here, so without this check a reintroduced marker would only
    surface at the next manual audit.
    """
    offenders: list[str] = []
    for name, text in _shipped_prose().items():
        for number, line in enumerate(text.split("\n"), 1):
            if any(marker in line for marker in _DEBT_MARKERS):
                offenders.append(f"{name}:{number}: {line.strip()[:80]}")

    assert offenders == [], (
        "shipped guidance carries a debt marker; say it without the literal, "
        f"as constraint 9 now does: {offenders}"
    )
