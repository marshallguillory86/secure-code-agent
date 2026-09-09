"""Shipped agent guidance cannot recommend a flag the CLI does not accept.

`docs/architecture.md` §3 row 3: agent guidance is written down in six places —
`instructions.py::_BODY`, `skills/secure-code-agent/SKILL.md`, the Copilot
prompt, three agent YAMLs, `README.md` and `docs/` — with nothing keeping them
in step. The recorded drift is specific and embarrassing: *"the `--changed-only`
deprecation updated four locations and missed two, leaving shipped agent
instructions recommending a flag that exits 2."*

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

#: Flags the CLI parses but which always fail. Recommending one of these is
#: worse than recommending an unknown flag: argparse rejects the unknown one
#: immediately, while this reaches the audit and exits 2 partway through.
ALWAYS_FAILS = {"--changed-only"}


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
def test_a_flag_that_always_fails_is_never_recommended(name: str):
    """The exact drift that shipped once already.

    `--changed-only` is parsed and then refuses to run, because a scoped audit
    that silently claims full coverage is worse than no scoped audit. Guidance
    may *describe* that — an agent should know why not to reach for it — but it
    must never appear as something to pass.
    """
    body = _guidance_documents()[name]

    for flag in ALWAYS_FAILS:
        for line in body.splitlines():
            if flag not in line:
                continue
            # A line that mentions the flag must also say it does not work.
            explains = any(
                marker in line.lower()
                for marker in ("reserved", "not implemented", "exits 2", "fails", "do not", "never")
            )
            assert explains, (
                f"{name} mentions {flag} without saying it is reserved and "
                f"exits 2:\n    {line.strip()}"
            )


def test_instructions_and_the_skill_agree_on_the_changed_only_status():
    """The two copies that disagreed, held together explicitly."""
    rendered = instructions.render()
    skill = (SKILLS / "secure-code-agent" / "SKILL.md").read_text(encoding="utf-8")

    for body in (rendered, skill):
        if "--changed-only" in body:
            assert "exits 2" in body or "reserved" in body.lower()
