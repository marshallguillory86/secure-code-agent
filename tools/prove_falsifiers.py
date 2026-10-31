"""Prove that each test a change adds fails without the change.

Test first means the test was seen failing before the code that passes it.
Until this gate, that was the author's word: a red commit described as red.
An author controls both the code and its test, so a test that was weakened
until it passed looks, from outside, exactly like one that was right. This
moves "remove the fix and watch the test fail" off the author's word and into
the pipeline:

1. Read from ``git diff BASE HEAD`` every ``test_*`` function in a test module
   the change adds, and every ``def test_*`` the diff adds to a test module
   that already existed. Tests already in a modified file are left alone: they
   may defend work older than this base, and proving them would be a false
   accusation.
2. In a scratch worktree of BASE, put this change's ``tests/`` in place of the
   base's, and run those tests against the base's code (its own ``src/``,
   never an installed copy).
3. Every one must fail. A test that passes there did not need the change it
   came with; a test skipped there proves nothing. Either fails the gate.

A test that cannot even be imported at the base counts as failing, which is
a weaker proof: it shows the test needs the change, not that it measures the
right thing. Those are reported as such.

A test that deliberately describes behaviour older than the change says so
with ``Covers existing behaviour:`` in its own docstring or its module's, and
is reported as exempt rather than inferred.

    python tools/prove_falsifiers.py --base origin/main
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess  # nosec B404 - runs git and pytest only, argv lists, never a shell
import sys
import tempfile
from pathlib import Path

COVERS_EXISTING = "Covers existing behaviour:"
_ADDED_TEST = re.compile(r"^\+\s*(?:async\s+)?def (test_\w+)\b", re.M)
_TIMEOUT = 600
#: One line per test from `pytest -v`: the node id, then its outcome.
_RESULT = re.compile(r"^(\S+::\S+) (PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)\b", re.M)


def _git(root: Path, *args: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is not on PATH")
    result = subprocess.run(  # nosec B603 - git by absolute path, fixed argv, never a shell
        [git, *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env=_clean_env(),
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _clean_env() -> dict[str, str]:
    """No inherited git repository variables, and no ambient pytest options."""
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key != "PYTEST_ADDOPTS"
    }


def _is_test_module(path: str) -> bool:
    name = Path(path).name
    return path.startswith("tests/") and name.startswith("test_") and name.endswith(".py")


def _functions(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return re.findall(r"^\s*(?:async\s+)?def (test_\w+)\b", source, re.M)
    return [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def _exempt(source: str, name: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    if COVERS_EXISTING in (ast.get_docstring(tree) or ""):
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return COVERS_EXISTING in (ast.get_docstring(node) or "")
    return False


def in_scope(root: Path, base: str) -> list[str]:
    """Node ids of the test functions this change adds, sorted and unique."""
    node_ids: set[str] = set()
    added = _git(root, "diff", "--name-only", "--diff-filter=A", base, "HEAD").splitlines()
    for path in added:
        if _is_test_module(path):
            source = (root / path).read_text(encoding="utf-8")
            node_ids.update(f"{path}::{name}" for name in _functions(source))
    modified = _git(root, "diff", "--name-only", "--diff-filter=M", base, "HEAD").splitlines()
    for path in modified:
        if _is_test_module(path):
            diff = _git(root, "diff", "--unified=0", base, "HEAD", "--", path)
            node_ids.update(f"{path}::{name}" for name in _ADDED_TEST.findall(diff))
    return sorted(node_ids)


def _outcomes(output: str, node_ids: list[str]) -> dict[str, str]:
    """`failed`, `import`, `passed`, `skipped` or `not run` for each node id.

    Read from pytest's verbose output, one line per test, so nothing is parsed
    but text this run printed.
    """
    results = _RESULT.findall(output)
    outcomes: dict[str, str] = {}
    for node_id in node_ids:
        path = node_id.split("::")[0]
        mine = {
            status
            for reported, status in results
            if reported == node_id or reported.startswith(f"{node_id}[")
        }
        if mine & {"FAILED", "ERROR", "XFAIL"}:
            outcomes[node_id] = "failed"
        elif "SKIPPED" in mine:
            outcomes[node_id] = "skipped"
        elif mine:
            outcomes[node_id] = "passed"
        elif re.search(rf"^ERROR (?:collecting )?{re.escape(path)}\b", output, re.M):
            outcomes[node_id] = "import"
        else:
            outcomes[node_id] = "not run"
    return outcomes


def run_at_base(root: Path, base: str, node_ids: list[str]) -> dict[str, str]:
    # Resolved: on macOS the temporary directory sits behind a symlink, and a
    # rootdir that does not match the resolved test paths changes the names
    # pytest reports them under.
    scratch = Path(tempfile.mkdtemp(prefix="prove-falsifiers-")).resolve()
    tree = scratch / "base"
    _git(root, "worktree", "add", "--detach", "--quiet", str(tree), base)
    try:
        shutil.rmtree(tree / "tests", ignore_errors=True)
        shutil.copytree(
            root / "tests", tree / "tests", ignore=shutil.ignore_patterns("__pycache__")
        )
        env = _clean_env()
        env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree)])
        # One run per file: a file that cannot be collected at the base stops
        # pytest from running anything else selected alongside it.
        by_file: dict[str, list[str]] = {}
        for node_id in node_ids:
            by_file.setdefault(node_id.split("::")[0], []).append(node_id)
        outcomes: dict[str, str] = {}
        for _path, selected in sorted(by_file.items()):
            completed = subprocess.run(  # nosec B603 - this interpreter's pytest, fixed argv
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-p",
                    "no:cacheprovider",
                    "-o",
                    "addopts=",
                    "--rootdir",
                    str(tree),
                    "-v",
                    "-rA",
                    *selected,
                ],
                cwd=tree,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=_TIMEOUT,
            )
            outcomes.update(_outcomes(completed.stdout + completed.stderr, selected))
        return outcomes
    finally:
        _git(root, "worktree", "remove", "--force", str(tree))
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="the commit the change is measured from")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1], help="repository root"
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    candidates = in_scope(root, args.base)
    exempt = []
    to_prove = []
    for node_id in candidates:
        path, name = node_id.split("::")
        if _exempt((root / path).read_text(encoding="utf-8"), name):
            exempt.append(node_id)
        else:
            to_prove.append(node_id)

    for node_id in exempt:
        print(f"exempt  {node_id}  ({COVERS_EXISTING.rstrip(':').lower()})")
    if not to_prove:
        print(f"nothing to prove: this change adds no test that must fail at {args.base}")
        return 0

    failed = 0
    for node_id, outcome in run_at_base(root, args.base, to_prove).items():
        if outcome == "failed":
            print(f"proven  {node_id}  fails without its change")
        elif outcome == "import":
            print(f"proven  {node_id}  fails at the base on import (a weaker proof)")
        elif outcome == "passed":
            print(f"FAIL    {node_id}  passes without its change")
            failed = 1
        elif outcome == "skipped":
            print(f"FAIL    {node_id}  skipped at the base, which proves nothing")
            failed = 1
        else:
            print(f"FAIL    {node_id}  was not run at the base, which proves nothing")
            failed = 1
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
