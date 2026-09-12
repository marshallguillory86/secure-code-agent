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

from secure_code_audit import instructions
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
