"""One coverage floor, declared in one place.

`pyproject.toml` carries `fail_under = 92` — the house floor, raised to it in
#59 once the suite could clear it. But both workflows passed
`--cov-fail-under=85` on the command line, and a pytest-cov command-line value
beats the config file. So the floor that was raised was not the floor CI
enforced: the gate stayed at 85, and the suite could have shed eight points of
coverage without a single red build. The #59 PR said "so the floor is a floor
rather than an aspiration", which was true of the file and false of the
pipeline.

This is the same shape as `test_one_action_has_one_pin.py` and the
branch-protection rule that named two contexts which did not exist: a rule
written in one place, contradicted in another, with nothing asking whether the
two agreed. Every instance has been silent, because each half is individually
valid — the config parses, the flag is a real flag, the build is green.

So the rule is that the number lives in `pyproject.toml` and nowhere else. A
workflow may run coverage; it may not carry its own threshold. Per the house
rule that an audit which finds a bug class ships a lint that structurally
blocks it, this is that lint.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import tomllib

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

#: Any spelling of the threshold flag, with or without its value attached.
_FAIL_UNDER = re.compile(r"--cov-fail-under(?:[=\s]+(?P<value>[\d.]+))?")

#: A YAML comment, from an unquoted `#` to the end of the line.
_COMMENT = re.compile(r"(?m)(?<!['\"])#.*$")


def _workflow_files() -> list[Path]:
    return sorted(p for p in WORKFLOWS.glob("*.y*ml") if p.is_file())


def _commands(workflow: Path) -> str:
    """The workflow with its comments removed.

    The rule is about what the job *runs*, and a comment naming the flag in
    order to explain why it is absent is the opposite of a violation. This
    lint failed on its own fix for exactly that reason, which is the kind of
    false positive that gets a lint deleted rather than fixed.
    """
    return _COMMENT.sub("", workflow.read_text(encoding="utf-8"))


def test_there_are_workflows_to_check():
    """A glob that matches nothing would make every test below vacuous."""
    assert _workflow_files(), f"no workflow files found under {WORKFLOWS}"


def test_pyproject_declares_the_floor():
    """The single source of truth has to exist for the rule to mean anything."""
    config = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    floor = config["tool"]["coverage"]["report"]["fail_under"]
    assert isinstance(floor, (int, float))
    assert floor >= 92, (
        f"the house coverage floor is 92; pyproject declares {floor}. "
        "Lowering it is a decision, not a fix."
    )


def test_the_detector_bites_on_a_command_and_not_on_a_comment(tmp_path):
    """Keeps the comment-stripping from making this lint toothless.

    `_commands` exists so prose naming the flag does not fail the check. A
    too-greedy version of it would strip the `run:` line as well, and the
    lint would then pass against a workflow that really does override the
    floor — a green check that proves nothing, which is worse than no check.
    """
    violating = tmp_path / "bad.yml"
    violating.write_text(
        "jobs:\n  t:\n    steps:\n"
        "      # we deliberately do not pass --cov-fail-under here\n"
        "      - run: python -m pytest --cov-fail-under=85\n",
        encoding="utf-8",
    )
    found = _FAIL_UNDER.search(_commands(violating))
    assert found is not None, "the detector missed a real --cov-fail-under in a run: line"
    assert found.group("value") == "85"

    clean = tmp_path / "good.yml"
    clean.write_text(
        "jobs:\n  t:\n    steps:\n"
        "      # no --cov-fail-under: the floor is pyproject's fail_under\n"
        "      - run: python -m pytest --cov=secure_code_audit\n",
        encoding="utf-8",
    )
    assert _FAIL_UNDER.search(_commands(clean)) is None, (
        "the detector fired on a comment that only names the flag"
    )


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_no_workflow_carries_its_own_coverage_floor(workflow: Path):
    """Prevents a workflow silently overriding the declared floor.

    A command-line `--cov-fail-under` wins over `pyproject.toml`, so a
    workflow carrying one makes the declared floor decorative. The gate must
    read the number from the file every other reader reads.
    """
    found = _FAIL_UNDER.search(_commands(workflow))
    assert found is None, (
        f"{workflow.relative_to(REPO)} passes --cov-fail-under"
        f"{'=' + found.group('value') if found.group('value') else ''}, which "
        "overrides fail_under in pyproject.toml. Remove the flag and let the "
        "declared floor govern."
    )
