"""Targets that are not a tidy git repository full of code.

Found by pointing the tool at shapes the calibration corpus never contains.
Every repository in that corpus is a git checkout with a src tree, so three
defects survived 526 tests and a full self-audit:

  * a mistyped path reached the scanners and died with a raw
    `FileNotFoundError` out of `subprocess.py`;
  * a single file as the target died with `NotADirectoryError`, because
    every adapter passed it as a subprocess `cwd` — despite the CLI and
    several adapters carrying `target if target.is_dir() else target.parent`
    precisely so that single-file audits would work;
  * and once running, a single file measured **zero** lines, because
    `rglob` on a file yields nothing. A zero denominator is not normalised
    at all, so the grade became the raw subtotal: a two-line file
    containing `eval(input())` scored 3.59 (B+) instead of 0.00 (F).

None of these are exotic. `secure-code-agent one_file.py` is the first thing
someone tries.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent


def _run(target, *extra: str):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(target),
            "--only-scanners",
            "bandit,builtin_rules",
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )


def _no_traceback(result) -> None:
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, f"crashed rather than reporting:\n{combined[-800:]}"


# ---------------------------------------------------------------------------
# A path that is not there
# ---------------------------------------------------------------------------


def test_a_missing_scan_root_is_an_error_not_a_traceback(tmp_path):
    result = _run(tmp_path / "does-not-exist")

    _no_traceback(result)
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_the_error_names_the_path_the_operator_typed(tmp_path):
    result = _run(tmp_path / "typo-here")

    assert "typo-here" in result.stderr


# ---------------------------------------------------------------------------
# A single file
# ---------------------------------------------------------------------------


def test_a_single_file_can_be_audited(tmp_path):
    """`secure-code-agent one_file.py` is the first thing anyone tries."""
    target = tmp_path / "app.py"
    target.write_text("import os\neval(input())\n", encoding="utf-8")

    result = _run(target, "--json-output", str(tmp_path / "r.json"))

    _no_traceback(result)
    assert result.returncode == 0


def test_a_single_file_is_measured_against_its_own_lines(tmp_path):
    """Zero LOC means no normalisation at all, so the grade becomes the raw
    subtotal — a two-line file scored 3.59 (B+) with `eval(input())` in it."""
    target = tmp_path / "app.py"
    target.write_text("import os\neval(input())\n", encoding="utf-8")
    out = tmp_path / "r.json"

    _run(target, "--json-output", str(out))
    report = json.loads(out.read_text(encoding="utf-8"))

    assert report["score"]["loc_scanned"] == 2
    assert report["score"]["overall"] == 0.0


def test_a_single_file_writes_its_outputs_beside_itself(tmp_path):
    """The root was the file, so the report path became
    `app.py/secure-code-report.md`."""
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    _run(target)

    assert (tmp_path / "secure-code-report.md").is_file()
    assert (tmp_path / "secure-code-remediation-prompt.md").is_file()


def test_a_single_file_still_finds_what_is_in_it(tmp_path):
    """Not crashing is not the same as working."""
    target = tmp_path / "app.py"
    target.write_text("import subprocess\nsubprocess.call('ls', shell=True)\n", encoding="utf-8")
    out = tmp_path / "r.json"

    _run(target, "--json-output", str(out))
    report = json.loads(out.read_text(encoding="utf-8"))

    assert any(f["rule_id"] == "B602" for f in report["findings"])


# ---------------------------------------------------------------------------
# Nothing to scan
# ---------------------------------------------------------------------------


def test_an_empty_directory_does_not_crash(tmp_path):
    result = _run(tmp_path)

    _no_traceback(result)
    assert result.returncode == 0


def test_a_directory_with_no_code_does_not_crash(tmp_path):
    (tmp_path / "README.md").write_text("# hello\n", encoding="utf-8")

    result = _run(tmp_path)

    _no_traceback(result)
    assert result.returncode == 0


def test_an_unreadable_file_does_not_crash_the_run(tmp_path):
    """A file the process cannot open is a fact about the environment, not
    a reason to abandon the audit."""
    readable = tmp_path / "fine.py"
    readable.write_text("x = 1\n", encoding="utf-8")
    blocked = tmp_path / "blocked.py"
    blocked.write_text("eval(1)\n", encoding="utf-8")
    blocked.chmod(0o000)
    try:
        result = _run(tmp_path)
        _no_traceback(result)
        assert result.returncode == 0
    finally:
        blocked.chmod(0o644)
