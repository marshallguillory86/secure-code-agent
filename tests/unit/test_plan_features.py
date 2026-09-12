"""Scope conformance, scoped audits, the untriaged headline, and the MCP door.

Four items from the review, each closing a specific objection:

- *"Only verify is mechanical, and only for silencing and regressions — not
  for 'did you rewrite the session model.'"* → `Scope`.
- *"`--changed-only` always exits 2. A PR-shaped tool that cannot do a
  PR-shaped audit is missing the run people will actually schedule."*
- *"A staff engineer who sees Django at F turns the gate off."*
- *"It is named agent and there is no chat door."*
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import Verdict
from secure_code_audit.verify import Scope, measure_scope


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "src" / "b.py").write_text("y = 2\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "-A"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    # Inherited environment plus `--no-verify`: this machine runs a
    # commit-identity hook, and a stripped env broke it in a way that read as
    # the feature failing rather than the fixture.
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "commit",
            "--no-verify",
            "-qm",
            "base",
        ],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_IDENTITY_OVERRIDE": "1"},
    )
    return root


def _head(root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _finding(path: Path) -> Finding:
    return Finding(
        rule_id="B602",
        scanner="bandit",
        fingerprint="fp",
        canonical_cwe="CWE-78",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=path,
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="m",
    )


# ---------------------------------------------------------------------------
# Scope: the blast radius
# ---------------------------------------------------------------------------


def test_a_change_confined_to_cited_files_is_conformant(tmp_path):
    root = _repo(tmp_path)
    since = _head(root)
    (root / "src" / "a.py").write_text("x = 2\n", encoding="utf-8")

    scope = measure_scope([_finding(root / "src" / "a.py")], root, since)

    assert scope.known
    assert scope.conformant
    assert scope.collateral == ()


def test_a_change_outside_the_order_is_collateral(tmp_path):
    """The 'while I was in there' patch, made mechanical."""
    root = _repo(tmp_path)
    since = _head(root)
    (root / "src" / "a.py").write_text("x = 2\n", encoding="utf-8")
    (root / "src" / "b.py").write_text("y = 3\n", encoding="utf-8")

    scope = measure_scope([_finding(root / "src" / "a.py")], root, since)

    assert scope.known
    assert not scope.conformant
    assert scope.collateral == ("src/b.py",)
    assert "EXCEEDED" in scope.headline()


def test_a_new_file_counts_as_collateral(tmp_path):
    """Untracked, because an agent handed a work order has not committed."""
    root = _repo(tmp_path)
    since = _head(root)
    (root / "src" / "brand_new.py").write_text("z = 1\n", encoding="utf-8")

    scope = measure_scope([_finding(root / "src" / "a.py")], root, since)

    assert "src/brand_new.py" in scope.collateral


def test_our_own_artifacts_are_not_collateral(tmp_path):
    """The verifying run writes these a second before measuring. Counting
    them would make every verification exceed its scope."""
    root = _repo(tmp_path)
    since = _head(root)
    report = root / "before.json"
    report.write_text("{}", encoding="utf-8")

    scope = measure_scope([_finding(root / "src" / "a.py")], root, since, ours=[report])

    assert "before.json" not in scope.collateral


@pytest.mark.parametrize(
    ("root_arg", "since", "expect"),
    [(None, "abc", "no repository root"), ("repo", None, "records no commit")],
)
def test_an_unmeasurable_scope_is_unknown_never_conformant(tmp_path, root_arg, since, expect):
    """A failed measurement must not read as a clean result — the same rule
    the coverage axis applies to scanners."""
    root = _repo(tmp_path) if root_arg else None

    scope = measure_scope([], root, since)

    assert not scope.known
    assert not scope.conformant
    assert expect in (scope.reason or "")


def test_an_unknown_scope_says_so_in_its_headline():
    assert "unknown" in Scope(reason="no baseline commit recorded").headline()


# ---------------------------------------------------------------------------
# The untriaged headline
# ---------------------------------------------------------------------------


def _verdict(untriaged: int, grade: str | None = "F") -> Verdict:
    return Verdict(
        estimate=0.0, estimated_letter="F", verified_grade=grade, reasons=(), untriaged=untriaged
    )


def test_an_untriaged_run_leads_with_the_work_not_the_letter():
    headline = _verdict(untriaged=12).headline()

    assert "12 finding(s), none triaged" in headline
    assert "starting position" in headline
    assert "F" not in headline


def test_a_triaged_run_reports_its_grade_normally():
    assert _verdict(untriaged=0, grade="A").headline() == "score 0.00 (A)"


def test_triage_does_not_withhold_the_grade():
    """Deliberately decoupled. `reasons` answers *did we look*; triage answers
    *did you review*. Folding them together made a verified grade unreachable
    on first contact for any repository with one finding."""
    verdict = _verdict(untriaged=5, grade="B")

    assert verdict.verified_grade == "B"
    assert verdict.reasons == ()


# ---------------------------------------------------------------------------
# The MCP door
# ---------------------------------------------------------------------------


def test_the_mcp_module_imports_without_the_mcp_package():
    """The dependency is optional, so importing the package must not need it."""
    from secure_code_audit import mcp_server

    assert callable(mcp_server.main)


def test_the_mcp_audit_returns_the_work_order_first(tmp_path):
    from secure_code_audit.mcp_server import _audit

    root = _repo(tmp_path)
    (root / "src" / "bad.py").write_text(
        "import subprocess\ndef r(a):\n    return subprocess.call('ls '+a, " + "shell=True)\n",
        encoding="utf-8",
    )

    result = _audit(str(root), ["--only-scanners", "builtin_rules"])

    assert result["audit_ran"] is True
    assert result["work_order"], "the work order is the product; it must come back"
    assert "producer" in result


def test_the_mcp_audit_leaves_no_report_in_the_tree(tmp_path):
    """A chat surface does not get to leave reports in someone's repository.

    The one exception is `.secure-code/history.jsonl`, this tool's own state
    directory, because that is how the trend works across runs. The first
    version of this test asserted *nothing* was written and failed on
    exactly that file — the tidier claim was the false one, so the claim was
    corrected rather than the behaviour.
    """
    from secure_code_audit.mcp_server import _audit

    root = _repo(tmp_path)
    before = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}

    _audit(str(root), ["--only-scanners", "builtin_rules"])

    after = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    added = after - before

    assert added <= {".secure-code/history.jsonl"}, f"left behind: {sorted(added)}"
    assert not any(name.startswith("secure-code-report") for name in added)


def test_a_missing_path_is_an_error_not_an_audit(tmp_path):
    from secure_code_audit.mcp_server import _audit

    result = _audit(str(tmp_path / "nope"))

    assert result["audit_ran"] is False
    assert "does not exist" in result["error"]


def test_the_json_report_records_the_commit(tmp_path):
    """The input scope conformance needs. Without it the measurement reports
    itself unknown rather than guessing."""
    from secure_code_audit.cli import main

    root = _repo(tmp_path)
    out = tmp_path / "r.json"
    main([str(root), "--only-scanners", "builtin_rules", "--json-output", str(out)])

    assert json.loads(out.read_text(encoding="utf-8"))["commit"] == _head(root)
