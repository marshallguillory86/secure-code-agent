"""Adapters parsed against real captured scanner output.

`docs/architecture.md` §4: for a tool whose entire purpose is parsing other
tools' output formats, every parser was verified against *the author's belief
about the format* rather than the format. Two instances of that class had
already happened — the OSV-Scanner v1→v2 CLI change and `pip-audit --locked`
semantics — each caught by hand during review rather than by a test.

Each file in `tests/fixtures/scanner-output/` is genuine output from the named
tool at the recorded version, captured by running it against a small
deliberately-vulnerable tree. Local paths are rewritten to `/repo` and
`/home/user`; nothing else is edited. When a scanner is upgraded, recapture
rather than patch — a fixture edited by hand to make a test pass is the belief
this file exists to stop trusting.

**Not every scanner is here.** Only tools installable on the machine that did
the capture could produce real output; the rest are named in
`SCANNERS_WITHOUT_A_REAL_CAPTURE` so the gap is visible rather than forgotten,
and `test_the_capture_gap_is_declared_not_silent` fails if that list drifts out
of step with the fixtures directory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.findings import Severity
from secure_code_audit.scanner_status import ScannerOutcome
from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner
from secure_code_audit.scanners.gosec_scanner import GosecScanner
from secure_code_audit.scanners.njsscan_scanner import NjsscanScanner
from secure_code_audit.scanners.pip_audit_scanner import PipAuditScanner
from secure_code_audit.scanners.rubocop_scanner import RubocopScanner

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "scanner-output"

#: Tools whose output is not captured here, and why. Every one of these is a
#: parser still verified only against a hand-written mock. Capturing them needs
#: the tool installed, which the machine doing the capture did not have.
SCANNERS_WITHOUT_A_REAL_CAPTURE: dict[str, str] = {
    "bandit": "not installed on the capture host",
    "checkov": "not installed on the capture host",
    "hadolint": "not installed on the capture host",
    "npm_audit": "needs a resolved lockfile and a registry fetch",
    "osv_scanner": "not installed on the capture host",
    "scorecard": "needs a GitHub remote and an API token",
    "trivy": "not installed on the capture host",
    "trufflehog": "not installed on the capture host",
    "builtin_rules": "runs in-process; it has no external output format to drift",
    "semgrep": "captured as SARIF, exercised by the offline-ruleset suite",
}


#: Credential shapes that must never appear in a committed capture. Built from
#: character classes rather than examples so this file carries no token of its
#: own — see `test_no_capture_leaks_a_local_path_or_a_live_secret`.
_SECRET_SHAPES = {
    "GitHub token": r"gh[pousr]_[A-Za-z0-9]{36}",
    "AWS secret key": r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])",
    "AWS access key id": r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])",
    "private key block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
}


def _configured(scanner, command: str):
    scanner._resolved_command = (command,)
    return scanner


def _stub_exec(scanner, monkeypatch, stdout: str, code: int = 0):
    from subprocess import CompletedProcess

    monkeypatch.setattr(
        scanner,
        "_exec",
        lambda *a, **k: CompletedProcess(args=["x"], returncode=code, stdout=stdout, stderr=""),
    )


def _fixture(name: str) -> str:
    path = FIXTURES / name
    assert path.exists(), f"missing capture: {path}"
    return path.read_text(encoding="utf-8")


def test_njsscan_real_output_parses_to_one_finding_per_occurrence(tmp_path, monkeypatch):
    scanner = _configured(NjsscanScanner(), "njsscan")
    _stub_exec(scanner, monkeypatch, _fixture("njsscan.json"), code=1)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.COMPLETED
    ids = {f.rule_id for f in result.findings}
    # These are njsscan's own rule ids, not ours — if it renames one, this
    # fails instead of the adapter quietly reporting fewer findings.
    assert {"node_md5", "node_insecure_random_generator", "node_tls_reject"} <= ids
    assert all(f.line_start > 0 for f in result.findings)
    assert all(str(f.file_path).endswith(".js") for f in result.findings)


def test_rubocop_real_output_parses_security_cops(tmp_path, monkeypatch):
    scanner = _configured(RubocopScanner(), "rubocop")
    _stub_exec(scanner, monkeypatch, _fixture("rubocop.json"), code=1)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.COMPLETED
    cops = {f.rule_id for f in result.findings}
    assert {"Security/Eval", "Security/MarshalLoad", "Security/YAMLLoad"} <= cops
    # `convention` is RuboCop's own severity for these, and it must not land
    # as INFORMATIONAL or the findings drop out of a severity gate.
    assert all(f.severity is not Severity.INFORMATIONAL for f in result.findings)


def test_gitleaks_real_output_parses_a_redacted_secret(tmp_path, monkeypatch):
    scanner = _configured(GitleaksScanner(), "gitleaks")
    payload = _fixture("gitleaks.json")

    def fake_exec(args, **kwargs):
        from subprocess import CompletedProcess

        Path(args[args.index("--report-path") + 1]).write_text(payload, encoding="utf-8")
        return CompletedProcess(args=args, returncode=1, stdout="", stderr="")

    monkeypatch.setattr(scanner, "_exec", fake_exec)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.COMPLETED
    assert result.findings, "gitleaks captured a real secret; the adapter parsed none"
    # The adapter namespaces gitleaks' own rule id under the scanner name.
    assert {"gitleaks.github-pat", "gitleaks.generic-api-key"} <= {
        f.rule_id for f in result.findings
    }
    # --redact is passed, so the capture holds no live secret and neither
    # should the finding.
    assert all("REDACTED" in (f.message or "") or f.code_snippet is None for f in result.findings)


def test_gosec_real_no_toolchain_output_is_a_failure_not_a_clean_scan(tmp_path, monkeypatch):
    """The captured proof of the defect the gosec adapter exists to prevent.

    This is gosec 2.29.0's genuine output on a host with no Go toolchain:
    exit 1, well-formed JSON, an empty `Issues` list, and the real failure
    recorded only under `Golang errors`.
    """
    raw = json.loads(_fixture("gosec-no-toolchain.json"))
    assert raw["Issues"] == [], "the capture no longer demonstrates the empty-Issues case"
    assert raw["Golang errors"], "the capture no longer carries the load failure"

    scanner = _configured(GosecScanner(), "gosec")
    _stub_exec(scanner, monkeypatch, _fixture("gosec-no-toolchain.json"), code=1)

    result = scanner.scan(tmp_path, Config())

    assert result.outcome is ScannerOutcome.FAILED
    assert "go command required" in result.reason


def test_pip_audit_real_output_parses_vulnerabilities(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    scanner = _configured(PipAuditScanner(), "pip-audit")
    _stub_exec(scanner, monkeypatch, _fixture("pip-audit.json"), code=1)

    config = Config()
    config.scanners["pip_audit"] = ScannerConfig(mode="requirements")
    result = scanner.scan(tmp_path, config)

    assert result.outcome is ScannerOutcome.COMPLETED
    assert result.findings, "the capture holds 23 vulnerabilities; the adapter parsed none"
    assert all(f.rule_id.startswith("pip_audit.") for f in result.findings)
    assert any("GHSA" in f.rule_id or "PYSEC" in f.rule_id for f in result.findings)
    # Scope is what makes the result reproducible: which inputs were audited.
    assert result.scope is not None and "mode=requirements" in result.scope


def test_the_capture_gap_is_declared_not_silent():
    """A parser with no real capture is a known risk, not an unknown one.

    §4's point is that a parser verified only against a mock is verified
    against a belief. Where that is still true, it has to be *stated* — an
    undocumented gap is the same silence this project rejects everywhere else.
    """
    from secure_code_audit import scanners

    captured = {path.stem.split("-")[0] for path in FIXTURES.glob("*")}
    # Fixture filenames use the tool's own spelling; map to scanner ids.
    captured = {"pip_audit" if name == "pip" else name for name in captured}

    for name in scanners.SCANNERS:
        assert name in captured or name in SCANNERS_WITHOUT_A_REAL_CAPTURE, (
            f"{name!r} has neither a real captured output fixture nor an entry "
            f"in SCANNERS_WITHOUT_A_REAL_CAPTURE explaining why not"
        )

    stale = [
        name
        for name in SCANNERS_WITHOUT_A_REAL_CAPTURE
        if name in captured and name not in {"semgrep"}
    ]
    assert stale == [], (
        f"these scanners now have real captures and should be removed from "
        f"SCANNERS_WITHOUT_A_REAL_CAPTURE: {stale}"
    )


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*")), ids=lambda p: p.name)
def test_no_capture_leaks_a_local_path_or_a_live_secret(path: Path):
    """Captures are committed artifacts, and they came off someone's laptop."""
    body = path.read_text(encoding="utf-8")

    assert "/Users/" not in body or "/home/user" in body, f"{path.name} leaks a home directory"
    assert "/private/tmp" not in body, f"{path.name} leaks a local temp path"
    # gitleaks is run with --redact; the others never see a secret. If a
    # recapture ever drops --redact this fails rather than committing the key.
    #
    # Matched by *shape*, not by literal. An earlier version of this test named
    # the exact tokens used during capture — and gitleaks then flagged this
    # file, correctly: a test guarding against committing a secret had
    # committed a secret-shaped string. A pattern also catches tokens from a
    # future recapture, which a literal never would.
    for label, pattern in _SECRET_SHAPES.items():
        assert not re.search(pattern, body), f"{path.name} contains an unredacted {label}"
