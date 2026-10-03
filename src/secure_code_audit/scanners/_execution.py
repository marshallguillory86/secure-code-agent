"""Running a scanner subprocess, and reading its exit code honestly.

Split out of `Scanner` along with command resolution and finding
construction. This is the part that owns the process: a sanitized
environment, no shell, a timeout, and one place that decides whether what
came back is usable.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from secure_code_audit.findings import Finding


class SubprocessExecution:
    """Executing the resolved command, and judging the result.

    A mixin of `Scanner`; `name` comes from there.
    """

    name: str  # supplied by Scanner

    def _exec(
        self,
        args: list[str],
        cwd: Path,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess:
        """Run a scanner subprocess with sanitized env, no shell.

        **This does not judge the exit code.** It returns whatever the
        process did, and the adapter decides what its own tool's codes mean,
        because that knowledge is per-tool: 1 means findings to bandit, 183
        to trufflehog, and failure to hadolint.

        It used to take an `allowed_exits` tuple and do nothing with it —
        both branches returned the process unchanged. Fourteen adapters
        passed one, several then wrote the same tuple again as the check
        that actually ran, and bandit passed `(0, 1)` and checked no exit
        code at all, reporting a clean scan when bandit had failed
        internally. The parameter was deleted rather than implemented:
        enforcing it here would need a way to say "this code is not
        acceptable" that fifteen call sites must act on, for no change in
        behaviour. See `docs/product-intent.md` §8 question 8.

        `cwd` is coerced to a directory. Auditing a single file is supported
        — the CLI and several adapters carry `target if target.is_dir() else
        target.parent` for exactly that — but every adapter passed the raw
        target here, so `secure-code-agent path/to/one.py` died with
        `NotADirectoryError` out of `subprocess.py` before any scanner ran.
        Fixing it once here is better than asking fifteen adapters to
        remember.
        """
        if cwd is not None and not cwd.is_dir():
            cwd = cwd.parent
        env = self._sanitized_env()
        try:
            r = subprocess.run(
                args,
                cwd=str(cwd),
                env=env,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                args=exc.cmd or args,
                returncode=124,
                stdout="",
                stderr=f"timeout after {timeout_seconds}s",
            )
        return r

    @staticmethod
    def _sanitized_env() -> dict[str, str]:
        """A minimal env for subprocesses — keep PATH and locale, drop the rest.
        Prevents accidental secret-leak into the scanner process via env."""
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP")
        return {k: v for k, v in os.environ.items() if k in keep}

    def _findings_exit_contradiction(
        self,
        target: Path,
        *,
        exit_code: int,
        findings_exit: int,
        findings: list[Finding],
    ) -> str | None:
        """Catch "the scanner said it found things, and we parsed none".

        A findings-signalling exit code is the tool asserting it detected
        something. Recording zero findings in that case reports a clean scan
        of a target the scanner just called dirty — the scanner's own signal,
        silently discarded. Fail the scanner instead, so coverage says we do
        not know rather than saying nothing is there.

        Returns the reason when the contradiction holds, else None. The caller
        turns that into `self.failed(...)` — the helper does not build the
        finding itself, because the outcome is the caller's to state.
        """
        if exit_code != findings_exit or findings:
            return None
        return (
            f"{self.name} exited {exit_code} to signal findings but produced no "
            "parseable results; refusing to record this as a clean scan"
        )
