"""A secret scanner that cannot see the working tree is wrong in the worst way.

`gitleaks detect --source` scans *commits*. It was the only pass this adapter
ran, so a plaintext private key sitting in the working tree and not yet
committed produced "no leaks found" — a clean bill of health for a repository
with a key in it, at the exact moment catching it is worth most.

Measured before the fix, on a fixture with one uncommitted key:

    gitleaks detect --source <dir>   ->  no leaks found
    gitleaks git <dir>               ->  no leaks found
    gitleaks dir <dir>               ->  1 leak

Swapping one for the other would only move the hole. A credential committed
and later deleted is still in the object store and still needs rotating —
that is the capability the adapter's old "history-aware" docstring was
reaching for. So both passes run, and `merge_corroborating` collapses the
overlap on anything committed and unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_code_audit.config import Config
from secure_code_audit.findings import Category
from secure_code_audit.scanner_status import ScannerOutcome
from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner


class _Recorder:
    """Captures the argv of every gitleaks invocation and replays a payload."""

    def __init__(self, payloads: dict[str, list[dict]] | None = None, returncode: int = 0):
        self.calls: list[list[str]] = []
        self.payloads = payloads or {}
        self.returncode = returncode

    def __call__(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        self.calls.append(list(args))
        mode = args[1]
        payload = self.payloads.get(mode, [])
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(json.dumps(payload), encoding="utf-8")
        code = 1 if payload else self.returncode
        return type("R", (), {"returncode": code, "stdout": "", "stderr": ""})()

    @property
    def modes(self) -> list[str]:
        return [call[1] for call in self.calls]


def _scanner(target: Path, recorder: _Recorder) -> GitleaksScanner:
    scanner = GitleaksScanner()
    scanner.configure(target, Config())
    scanner._exec = recorder
    scanner.is_available = lambda: True
    return scanner


def _hit(path: str) -> dict:
    return {
        "RuleID": "private-key",
        "Description": "Private Key",
        "File": path,
        "StartLine": 1,
        "EndLine": 1,
        "Match": "REDACTED",
    }


# ---------------------------------------------------------------------------
# Which passes run
# ---------------------------------------------------------------------------


def test_a_git_repository_is_scanned_both_ways(tmp_path):
    (tmp_path / ".git").mkdir()
    recorder = _Recorder()

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert recorder.modes == ["dir", "git"]
    assert result.outcome is ScannerOutcome.COMPLETED
    assert result.scope == "working tree and git history"


def test_a_plain_directory_is_still_scanned(tmp_path):
    """An extracted tarball has no history and is a supported target.

    Reporting "failed" here would be a false alarm; reporting COMPLETED
    without saying history was not examined would be a false assurance. The
    scope line is how both are avoided.
    """
    recorder = _Recorder()

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert recorder.modes == ["dir"]
    assert result.outcome is ScannerOutcome.COMPLETED
    assert result.scope == "working tree (not a git repository)"


def test_the_deprecated_detect_subcommand_is_not_used(tmp_path):
    """`detect` is deprecated in gitleaks 8 and is history-only. Naming it
    here means a revert to the old invocation fails rather than silently
    reintroducing the blind spot."""
    (tmp_path / ".git").mkdir()
    recorder = _Recorder()

    _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert "detect" not in recorder.modes
    for call in recorder.calls:
        assert "--source" not in call


# ---------------------------------------------------------------------------
# What each pass contributes
# ---------------------------------------------------------------------------


def test_a_working_tree_secret_is_found(tmp_path):
    """The case that was silently missed."""
    (tmp_path / ".git").mkdir()
    recorder = _Recorder({"dir": [_hit(str(tmp_path / "UNCOMMITTED.key"))]})

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert [f.file_path.name for f in result.findings] == ["UNCOMMITTED.key"]
    assert result.findings[0].category is Category.SECRETS


def test_a_history_only_secret_is_still_found(tmp_path):
    """The capability that must not be traded away for the fix."""
    (tmp_path / ".git").mkdir()
    recorder = _Recorder({"git": [_hit("deleted/HISTORY.key")]})

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert [f.file_path.name for f in result.findings] == ["HISTORY.key"]


def test_both_are_reported_together(tmp_path):
    (tmp_path / ".git").mkdir()
    recorder = _Recorder(
        {
            "dir": [_hit(str(tmp_path / "live.key"))],
            "git": [_hit("gone.key")],
        }
    )

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())

    assert sorted(f.file_path.name for f in result.findings) == ["gone.key", "live.key"]


def test_the_overlap_between_passes_collapses_to_one_finding(tmp_path):
    """A committed, unchanged secret is seen twice and is one secret."""
    from secure_code_audit.findings import merge_corroborating

    (tmp_path / ".git").mkdir()
    same = str(tmp_path / "committed.key")
    recorder = _Recorder({"dir": [_hit(same)], "git": [_hit(same)]})

    result = _scanner(tmp_path, recorder).scan(tmp_path, Config())
    assert len(result.findings) == 2

    assert len(merge_corroborating(result.findings)) == 1


# ---------------------------------------------------------------------------
# Failure is still failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("failing_mode", ["dir", "git"])
def test_either_pass_failing_fails_the_scanner(tmp_path, failing_mode):
    """Half a secret scan reported as a whole one is the absence-of-evidence
    failure this tool exists to prevent."""
    (tmp_path / ".git").mkdir()

    class _Broken(_Recorder):
        def __call__(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
            self.calls.append(list(args))
            if args[1] == failing_mode:
                return type("R", (), {"returncode": 2, "stdout": "", "stderr": "boom"})()
            Path(args[args.index("--report-path") + 1]).write_text("[]", encoding="utf-8")
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    result = _scanner(tmp_path, _Broken()).scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED
    assert failing_mode in result.reason


def test_unparseable_output_from_either_pass_fails(tmp_path):
    (tmp_path / ".git").mkdir()

    class _Garbage(_Recorder):
        def __call__(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
            self.calls.append(list(args))
            Path(args[args.index("--report-path") + 1]).write_text("not json", encoding="utf-8")
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    result = _scanner(tmp_path, _Garbage()).scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED
    assert "parse failure" in result.reason
