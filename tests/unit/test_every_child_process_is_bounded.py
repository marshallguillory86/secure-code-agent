"""No subprocess in this package may run without a timeout.

A security audit that never returns is worse than one that fails: CI shows
a spinner, the operator learns nothing, and nothing in the report says a
scan was skipped. SCA already bounds every child it spawns — eight call
sites, each passing `timeout=` — and `_execution` turns a timeout into exit
124 with a reason, which `test_subprocess_execution` covers. What was
missing is the *class* check: a ninth call site added without `timeout=`
would hang the audit and no test would notice.

This was found by auditing the call sites rather than by a hang, so it is a
falsifier and not a red test: the property held at all eight sites when
this was written. The rule here is that an audit which names a bug class
ships the check that blocks the class, not only the fixes — so the check
exists even though there was nothing to fix.

It matches on the call's *keyword set*, read from the AST, so a reformat or
a reordering cannot hide an unbounded call, and `_proves_itself` below
feeds it a synthetic one to prove the detector still bites.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "secure_code_audit"

#: Every spelling that starts a child process and can block forever.
_SPAWNERS = (
    "subprocess.run",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.call",
    "subprocess.Popen",
)


def _unbounded_calls(path: Path) -> list[str]:
    """`file:line` for each child-process call with no `timeout=` keyword.

    `Popen` is included and would be reported even with `timeout=`, which it
    does not accept — the bound there belongs on `.communicate()`, and the
    honest answer for this package is that it does not use `Popen` at all.
    Listing it means adopting one is a decision somebody makes on purpose.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = ast.unparse(node.func)
        if not func.endswith(_SPAWNERS):
            continue
        supplied = {kw.arg for kw in node.keywords}
        if "timeout" not in supplied:
            offenders.append(f"{path.name}:{node.lineno} {func}()")
    return offenders


def _sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_the_source_tree_is_not_empty():
    """A glob that matched nothing would make the check below vacuous."""
    assert len(_sources()) >= 20, len(_sources())


def test_the_package_spawns_at_least_one_child():
    """And that the detector finds the calls it is meant to be judging.

    An empty inventory would satisfy "no unbounded call" for ever, including
    after someone renamed the import to `from subprocess import run`.
    """
    spawns = 0
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        spawns += sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(_SPAWNERS)
        )

    assert spawns >= 8, (
        f"found {spawns} child-process calls; this package had 8. A drop means "
        "either they were removed or they are now spelled in a way this lint "
        "cannot see, and an unseen call is an unchecked one."
    )


def test_no_child_process_runs_without_a_timeout():
    """The whole point: an audit that cannot finish must not be possible."""
    offenders = [hit for path in _sources() for hit in _unbounded_calls(path)]

    assert offenders == [], (
        f"child process spawned with no timeout: {offenders}. Pass `timeout=`; a "
        "scanner, or a git command waiting on a prompt, would otherwise hang the "
        "audit with no finding and no exit code to explain it."
    )


def test_the_detector_proves_itself(tmp_path):
    """Hand it an unbounded call and a bounded one, and require it to tell them apart."""
    unbounded = tmp_path / "unbounded.py"
    unbounded.write_text(
        "import subprocess\n\n\ndef go(cmd):\n    return subprocess.run(cmd, capture_output=True)\n",
        encoding="utf-8",
    )
    bounded = tmp_path / "bounded.py"
    bounded.write_text(
        "import subprocess\n\n\n"
        "def go(cmd):\n    return subprocess.run(cmd, capture_output=True, timeout=30)\n",
        encoding="utf-8",
    )

    assert _unbounded_calls(unbounded) == ["unbounded.py:5 subprocess.run()"]
    assert _unbounded_calls(bounded) == []
