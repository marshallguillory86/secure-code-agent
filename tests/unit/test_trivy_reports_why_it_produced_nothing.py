"""When a required scanner produces nothing, say what it said.

**Found by running this repository's own audit.** Every one of the sixty
committed rows in `.secure-code/history.jsonl` carries
`coverage_complete: false`, because `trivy` is a required scanner and has
been failing for a long time. The reason recorded, every time:

    required scanner 'trivy' did not complete: failed
    trivy emitted no SARIF output

What trivy actually said, captured by reproducing the adapter's own
invocation:

    FATAL  remote Maven repository returned 429 Too Many Requests for
    https://repo.maven.apache.org/... Retry-After: 1525.
    The repository blocks all subsequent requests from this IP until the
    block clears. To avoid this, populate the local Maven cache before
    scanning (e.g. run `mvn dependency:resolve` and cache ~/.m2 in CI).

A cause and a remedy, in hand, discarded. The operator was told a required
scanner failed and given nothing to act on — which is the
absence-of-evidence failure this tool exists to prevent, committed by the
tool itself. It also explains twenty-minute trivy invocations in the local
suite: it was retrying against Maven with backoff.

**Two things were wrong, and they compound.**

The adapter's other two failure paths both carry `r.stderr` — the timeout
path and the bad-exit path. This one, the only path with no diagnosis of
its own, is the one that threw the text away.

And trivy's exit **1** was being accepted as a findings code. Without
`--exit-code`, which this adapter does not pass, trivy exits 0 on success
whether or not it found anything, and 1 on a fatal error. So `1` was
treated as "fine" and the run fell through to the empty-output branch,
losing the error on the way. D30 is the decision that an adapter judges its
own tool's exit codes; this is that judgement being wrong for trivy.

The fix stays evidence-first rather than code-first: *output* decides
success, and the exit code only colours the message. A trivy that returns 1
with usable SARIF is still parsed, because the findings are the thing. A
trivy that returns anything with no SARIF has failed, and the reason says
what it said.
"""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit.config import Config
from secure_code_audit.scanner_status import ScannerOutcome
from secure_code_audit.scanners.trivy_scanner import TrivyScanner

#: Trivy's real message, trimmed. The 429 and the Retry-After are what make
#: it actionable: wait, or populate the cache.
_FATAL = (
    "2026-10-04T15:50:44-07:00\tFATAL\tError\tremote Maven repository returned "
    "429 Too Many Requests for https://repo.maven.apache.org/maven2/org/apache/"
    "commons/commons-parent/105/commons-parent-105.pom. Retry-After: 1525.\n"
    "The repository blocks all subsequent requests from this IP until the block "
    "clears.\nTo avoid this, populate the local Maven cache before scanning."
)

_EMPTY_SARIF = json.dumps(
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}]}
)


def _mock(monkeypatch, *, code: int, stderr: str, sarif: str | None):
    """Run the adapter with a controlled exit code and `--output` behaviour.

    `sarif=None` leaves the output file as the adapter created it — empty —
    which is exactly what a FATAL trivy does: it opens nothing and writes
    nothing, so the zero-byte file Python made is what remains.
    """
    monkeypatch.setattr(TrivyScanner, "is_available", lambda self, cfg=None: True)
    monkeypatch.setattr(TrivyScanner, "command", ("trivy",), raising=False)

    def fake_exec(self, args, **kwargs):
        if sarif is not None:
            out = Path(args[args.index("--output") + 1])
            out.write_text(sarif, encoding="utf-8")
        return CompletedProcess(args=args, returncode=code, stdout="", stderr=stderr)

    monkeypatch.setattr(TrivyScanner, "_exec", fake_exec)
    return TrivyScanner()


def test_a_fatal_trivy_reports_what_trivy_said(monkeypatch, tmp_path):
    """The defect: the diagnosis was in hand and the reason omitted it."""
    scanner = _mock(monkeypatch, code=1, stderr=_FATAL, sarif=None)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED, result.outcome
    assert "429" in result.reason, (
        f"trivy named a rate limit and a remedy and the reason dropped both: {result.reason!r}"
    )
    assert "Maven" in result.reason, result.reason


def test_the_reason_still_says_no_output_was_produced(monkeypatch, tmp_path):
    """The operator needs both halves: what happened, and what the tool said."""
    scanner = _mock(monkeypatch, code=1, stderr=_FATAL, sarif=None)

    result = scanner.scan(tmp_path, Config())

    assert "SARIF" in result.reason, result.reason


def test_an_empty_output_with_a_silent_tool_still_fails_clearly(monkeypatch, tmp_path):
    """A tool that says nothing at all must not produce an empty reason.

    The falsifier for the fix: appending stderr must not be the only content,
    or a silent failure reads as a blank.
    """
    scanner = _mock(monkeypatch, code=0, stderr="", sarif=None)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED
    assert result.reason and result.reason.strip(), result.reason
    assert "SARIF" in result.reason, result.reason


def test_exit_one_with_usable_output_is_still_a_completed_scan(monkeypatch, tmp_path):
    """The falsifier that keeps the fix evidence-first rather than code-first.

    Output decides. A trivy that returns 1 and still wrote parseable SARIF has
    done its job, and reclassifying that as a failure would discard real
    findings over an exit code — the opposite mistake, and the one D30 warns
    about from the other side.
    """
    scanner = _mock(monkeypatch, code=1, stderr="", sarif=_EMPTY_SARIF)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.COMPLETED, result.reason


def test_a_clean_zero_exit_with_output_is_unchanged(monkeypatch, tmp_path):
    """The ordinary success path, pinned because the branch is being edited."""
    scanner = _mock(monkeypatch, code=0, stderr="", sarif=_EMPTY_SARIF)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.COMPLETED, result.reason
    assert list(result.findings) == []


def test_a_hard_failure_exit_still_reports_its_stderr(monkeypatch, tmp_path):
    """Unchanged: the path that always carried the text keeps carrying it."""
    scanner = _mock(monkeypatch, code=2, stderr="trivy: unknown flag --nope", sarif=None)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED
    assert "unknown flag" in result.reason, result.reason
