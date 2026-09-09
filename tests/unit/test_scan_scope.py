"""`paths.exclude_patterns` is the scan scope for findings, not only for files.

Five of fifteen adapters can push an exclusion down to their tool. The rest
have no flag for it, or read it from a config file inside the audited tree that
D1 forbids us honouring. So the setting was true for Bandit and a polite
fiction for Checkov, RuboCop, Trivy, Semgrep and the rest — and this repository
proved it: CI reported a Checkov "Basic Auth Credentials" hit inside a
committed pip-audit *fixture*, and two RuboCop findings inside a file whose
entire purpose is to be vulnerable, all under a config listing `tests/` as
excluded.

The scoring consequence is the sharp one. `exclude_patterns` is also the
denominator — `loc_under()` counts only non-excluded files — so findings from
excluded paths were being scored against lines that were never counted. The
numerator and the denominator were measuring different repositories.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit import config as config_mod
from secure_code_audit.cli import _drop_excluded
from secure_code_audit.findings import Category, Confidence, Finding, Severity


def _finding(path: Path, rule_id: str = "r", scanner: str = "checkov") -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner=scanner,
        fingerprint=f"{rule_id}:{path}",
        canonical_cwe=None,
        owasp_top10=None,
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


def _config(*patterns: str) -> config_mod.Config:
    cfg = config_mod.Config()
    cfg.exclude_patterns = patterns
    return cfg


def test_a_finding_inside_an_excluded_directory_is_dropped(tmp_path):
    (tmp_path / "tests").mkdir()
    excluded = tmp_path / "tests" / "vulnerable.rb"
    kept = tmp_path / "app.rb"

    result = _drop_excluded(
        [_finding(excluded, "Security/MarshalLoad"), _finding(kept, "real")],
        tmp_path,
        _config("tests/"),
    )

    assert [f.rule_id for f in result] == ["real"]


def test_the_scanner_that_produced_it_is_irrelevant(tmp_path):
    """Enforced once, for every adapter and every SARIF import alike.

    Bandit already excludes; Checkov cannot. A rule that depends on which tool
    happened to find something is not a scan scope.
    """
    (tmp_path / "vendor").mkdir()
    path = tmp_path / "vendor" / "thing.py"

    for scanner in ("bandit", "checkov", "rubocop", "trivy", "external_sarif"):
        finding = _finding(path, scanner=scanner)
        assert _drop_excluded([finding], tmp_path, _config("vendor/")) == [], scanner


def test_a_control_finding_is_never_dropped(tmp_path):
    """The exemption that keeps a failed scanner from going silent.

    Control findings carry the scan root as their path. If the root matched a
    pattern — or a future pattern were broad enough to — dropping
    "bandit could not run" would convert a failed scanner back into a silent
    one, which is the single failure this project exists to prevent.
    """
    control = _finding(tmp_path, "bandit.tool_unavailable")

    assert _drop_excluded([control], tmp_path, _config("*", "**", "tests/")) == [control]


def test_no_exclusions_configured_changes_nothing(tmp_path):
    findings = [_finding(tmp_path / "a.py"), _finding(tmp_path / "b.py")]

    assert _drop_excluded(findings, tmp_path, _config()) == findings


def test_a_path_outside_the_scan_root_is_kept(tmp_path):
    """`is_excluded` cannot make a relative path, so it must not guess.

    An imported SARIF can name absolute paths from another machine. Dropping
    those because they do not sit under this root would silently discard
    exactly the coverage the import was supplied for.
    """
    outside = Path("/elsewhere/app.py")

    assert _drop_excluded([_finding(outside)], tmp_path, _config("tests/")) != []


def test_a_file_target_excludes_relative_to_its_parent(tmp_path):
    """The scan root can be a single file; exclusions still resolve."""
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()

    result = _drop_excluded(
        [_finding(tmp_path / "tests" / "t.py"), _finding(target)],
        target,
        _config("tests/"),
    )

    assert [f.file_path for f in result] == [target]
