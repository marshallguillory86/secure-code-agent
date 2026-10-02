"""`SubprocessExecution` — the one place a scanner process is started.

Uses real subprocesses (the current interpreter) rather than mocking
`subprocess.run`, so the sanitised environment, the no-shell rule and the
timeout are observed on a live child.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from secure_code_audit.findings import Finding
from secure_code_audit.scanners._execution import SubprocessExecution


class _Runner(SubprocessExecution):
    name = "probe"


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_exec_returns_stdout_of_a_real_child(tmp_path):
    result = _Runner()._exec(_py("print('hello')"), tmp_path, 30)

    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_exec_runs_in_the_given_directory(tmp_path):
    """The child's cwd is the requested directory, not the caller's."""
    result = _Runner()._exec(_py("import os; print(os.getcwd())"), tmp_path, 30)

    from pathlib import Path

    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()


def test_file_target_is_coerced_to_its_parent_directory(tmp_path):
    """Auditing one file must not die with NotADirectoryError.

    Prevents `secure-code-agent path/to/one.py` crashing out of subprocess.py
    before any scanner ran. The parent assertion rules out running in some
    unrelated directory instead.
    """
    target = tmp_path / "one.py"
    target.write_text("x = 1\n", encoding="utf-8")

    result = _Runner()._exec(_py("import os; print(os.getcwd())"), target, 30)

    from pathlib import Path

    assert result.returncode == 0
    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()


def test_timeout_becomes_exit_124_with_a_reason(tmp_path):
    """A hung scanner returns a 124 result instead of raising.

    Prevents TimeoutExpired escaping into the orchestrator and killing the
    whole audit for one slow tool.
    """
    result = _Runner()._exec(_py("import time; time.sleep(30)"), tmp_path, 1)

    assert result.returncode == 124
    assert result.stdout == ""
    assert "timeout after 1s" in result.stderr


def test_nonzero_exit_is_returned_not_raised(tmp_path):
    """The caller decides what a nonzero exit means (npm audit exits 1 on findings)."""
    result = _Runner()._exec(_py("import sys; sys.exit(3)"), tmp_path, 30, allowed_exits=(0, 1))

    assert result.returncode == 3


def test_a_findings_exit_code_is_passed_through_untouched(tmp_path):
    result = _Runner()._exec(_py("import sys; sys.exit(1)"), tmp_path, 30, allowed_exits=(0, 1))

    assert result.returncode == 1


def test_no_shell_is_used_so_metacharacters_stay_literal(tmp_path):
    """An argument with shell syntax is data, not a command.

    Prevents injection through a path or rule name: if a shell were involved
    the `;` would run `touch`, and the marker file would exist.
    """
    marker = tmp_path / "pwned"
    payload = f"; touch {marker}"

    result = _Runner()._exec(_py("import sys; print(sys.argv[1])") + [payload], tmp_path, 30)

    assert result.stdout.strip() == payload
    assert not marker.exists()


def test_child_does_not_inherit_secrets_from_the_environment(tmp_path, monkeypatch):
    """A secret in the parent's environment must not reach the scanner.

    The PATH assertion guards against passing for the wrong reason (an empty
    environment would also hide the secret, but would break tools).
    """
    monkeypatch.setenv("SECRET_TOKEN", "do-not-forward")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-forward")

    code = "import os; print(os.environ.get('SECRET_TOKEN','')+'|'+os.environ.get('AWS_SECRET_ACCESS_KEY','')+'|'+('PATH' in os.environ).__str__())"
    result = _Runner()._exec(_py(code), tmp_path, 30)

    assert result.stdout.strip() == "||True"


def test_sanitized_env_keeps_exactly_the_allowlist(monkeypatch):
    for key in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(key, f"v-{key}")
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("PYTHONPATH", "/evil")

    env = SubprocessExecution._sanitized_env()

    assert env == {k: f"v-{k}" for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP")}


def test_sanitized_env_omits_allowlisted_names_that_are_unset(monkeypatch):
    """Unset allowlisted names are absent, not empty strings."""
    monkeypatch.delenv("LC_ALL", raising=False)

    assert "LC_ALL" not in SubprocessExecution._sanitized_env()


@pytest.mark.parametrize(
    ("exit_code", "findings_exit", "findings", "expect_reason"),
    [
        (1, 1, [], True),
        (1, 1, ["f"], False),
        (0, 1, [], False),
        (2, 1, [], False),
    ],
    ids=["signalled-and-empty", "signalled-with-findings", "clean-exit", "other-exit"],
)
def test_findings_exit_contradiction_only_when_signalled_and_empty(
    tmp_path, exit_code, findings_exit, findings, expect_reason
):
    """Only "said it found things, parsed none" is a contradiction.

    Prevents a scanner's own findings signal being recorded as a clean scan,
    and conversely prevents ordinary clean/other exits being failed.
    """
    reason = _Runner()._findings_exit_contradiction(
        tmp_path,
        exit_code=exit_code,
        findings_exit=findings_exit,
        findings=[object()] * len(findings),  # type: ignore[list-item]
    )

    assert (reason is not None) is expect_reason


def test_contradiction_reason_names_the_scanner_and_exit_code(tmp_path):
    reason = _Runner()._findings_exit_contradiction(
        tmp_path, exit_code=1, findings_exit=1, findings=[]
    )

    assert reason is not None
    assert "probe" in reason
    assert "exited 1" in reason
    assert "refusing to record this as a clean scan" in reason


def test_findings_list_is_not_mutated_by_the_contradiction_check(tmp_path):
    findings: list[Finding] = []

    _Runner()._findings_exit_contradiction(
        tmp_path, exit_code=1, findings_exit=1, findings=findings
    )

    assert findings == []


def test_exec_result_is_a_completed_process(tmp_path):
    result = _Runner()._exec(_py("pass"), tmp_path, 30)

    assert isinstance(result, subprocess.CompletedProcess)
