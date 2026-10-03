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
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

#: Any spelling of the threshold flag, with or without its value attached.
_FAIL_UNDER = re.compile(r"--cov-fail-under(?:[=\s]+(?P<value>[\d.]+))?")

#: A YAML comment, from an unquoted `#` to the end of the line.
_COMMENT = re.compile(r"(?m)(?<!['\"])#.*$")


def _pyproject() -> dict:
    """`tomllib` is 3.11+, and this project's support floor is 3.10.

    Same shape as `test_contract_sync.py`'s helper, for the same reason:
    skipping on the oldest interpreter only keeps the check running on the
    rest of the matrix, where a blanket skip would let it rot unnoticed.
    Importing it at module scope instead fails collection for this whole
    file on 3.10, taking the workflow lints down with it.
    """
    toml = pytest.importorskip("tomllib", reason="tomllib is 3.11+")
    return toml.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


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
    floor = _pyproject()["tool"]["coverage"]["report"]["fail_under"]
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


#: A real pytest invocation, not the word appearing inside a flag value —
#: `-o cache_dir=.pytest-cache-ci` mentions pytest and runs nothing.
_INVOCATION = re.compile(r"(?:python3?\s+-m\s+pytest|^\s*pytest)\b", re.M)


def _pytest_commands(workflow: Path) -> list[str]:
    """Every command in this workflow that actually invokes pytest.

    Parsed from the YAML rather than the raw text, so a folded `run: >-`
    block arrives as the single command it becomes — reading raw lines would
    see `--cov` and the `pytest` token on separate lines and could call an
    invocation silent when it is not.
    """
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
    found: list[str] = []
    for job in (doc.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for command in run.splitlines():
                if _INVOCATION.search(command):
                    found.append(command.strip())
    return found


def test_the_invocation_detector_finds_the_real_ones_only():
    """Keeps the check below from passing because it found nothing.

    Two ways this goes quietly wrong: the regex misses `python -m pytest`
    and every workflow looks compliant, or it fires on
    `-o cache_dir=.pytest-cache-ci` and reports a flag value as a command.
    """
    assert _INVOCATION.search("python -m pytest -q")
    assert _INVOCATION.search("  pytest tests/unit/x.py")
    assert not _INVOCATION.search("python -m build -o cache_dir=.pytest-cache-ci")

    total = sum(len(_pytest_commands(w)) for w in _workflow_files())
    assert total >= 5, f"expected at least 5 pytest invocations across CI, found {total}"


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_every_ci_pytest_invocation_declares_its_coverage_intent(workflow: Path):
    """Prevents a CI step inheriting the coverage gate by accident.

    `pyproject.toml` puts `--cov` in `addopts`, so coverage is the default
    for every pytest run and `fail_under = 92` applies to it. That is right
    for the job whose purpose is to measure, and wrong everywhere else: a
    single-file step cannot reach 92 and would fail for a reason unrelated
    to what it tests, and a second full-suite run would pay for coverage
    twice in Actions minutes.

    So silence is not allowed. An invocation either passes `--cov`, meaning
    it is the measuring run, or `--no-cov`, meaning it deliberately is not.
    """
    silent = [
        command
        for command in _pytest_commands(workflow)
        if "--cov" not in command and "--no-cov" not in command
    ]
    assert silent == [], (
        f"{workflow.relative_to(REPO)} has pytest invocations that say nothing "
        f"about coverage: {silent}. Add --no-cov if the step is not the one "
        "measuring it, or --cov if it is."
    )


#: Coverage artifacts a consumer reads, in maintainability-agent's own order.
#: It requires the file to be newer than the moment before it ran the suite,
#: so a committed report cannot set a repository's own test_effectiveness.
CONSUMED_ARTIFACTS = ("coverage.xml", "coverage/lcov.info", "lcov.info")


def _addopts() -> str:
    return _pyproject()["tool"]["pytest"]["ini_options"]["addopts"]


def _writes_a_consumable_artifact(addopts: str) -> bool:
    """Does this addopts string make a run leave a file a consumer can read?"""
    return "--cov-report=xml" in addopts or "--cov-report=lcov" in addopts


def test_the_declared_test_command_writes_a_coverage_artifact_not_just_stdout():
    """Prevents coverage being reported only where no tool can read it.

    `--cov-report=term` prints a percentage for a human and writes nothing.
    maintainability-agent reads an *artifact* — one of CONSUMED_ARTIFACTS —
    and scored `test_effectiveness` as "not measurable" on every audit of
    this repository while the number sat in stdout. Adding `--cov` without
    a file report fixes the visible half and leaves the measured half
    exactly as broken, which is why this asserts the file and not the flag.
    """
    addopts = _addopts()
    assert "--cov=" in addopts, f"addopts does not enable coverage at all: {addopts!r}"
    assert _writes_a_consumable_artifact(addopts), (
        f"addopts reports coverage but writes no artifact a consumer reads: "
        f"{addopts!r}. One of {CONSUMED_ARTIFACTS} must be produced; "
        "--cov-report=term alone is invisible to every tool."
    )


def test_the_coverage_artifact_is_not_committed():
    """A committed report would be provenance the suite did not earn.

    Every run now rewrites `coverage.xml` at the repository root. Tracking
    it would put a generated file in review diffs, and a consumer that
    accepts a stale artifact would be reading the tree's claim about itself
    rather than a measurement — which is the attack its freshness check
    exists to refuse.
    """
    ignored = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "coverage.xml" in ignored, "coverage.xml is written by every run and must be gitignored"

    tracked = subprocess.run(
        ["git", "ls-files", "coverage.xml", "lcov.info", "coverage/lcov.info"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    assert tracked == [], f"a coverage artifact is tracked in git: {tracked}"
