"""Every consumer of `Finding.file_path`, handed a repository-relative path.

`findings.anchor` makes finding paths repository-relative. That is only safe
if nothing downstream resolves one against the process working directory —
the D5 failure, which made `exclude_patterns` fail open. So each consumer that
touches the disk is exercised with a relative path from a working directory
that is *not* the repository, where a bare `resolve()` names the wrong file.

The compatibility half is here too. Paths were absolute through 0.12.1, and
what users recorded against them has to keep meaning what it meant: a `*/`
glob written to swallow the checkout prefix, an absolute `file:`, a
fingerprint pinned from an old report, and a baseline.
"""

from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path

import pytest

from secure_code_audit import baseline, suppressions
from secure_code_audit import config as config_mod
from secure_code_audit.cli import _drop_excluded, _restrict_to_changed
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.triage import Tier, tier_of
from secure_code_audit.verify import measure_scope

REPO = Path(__file__).resolve().parent.parent.parent


def _finding(
    path: str | Path,
    *,
    rule_id: str = "B602",
    category: Category = Category.CODE_VULNERABILITIES,
    snippet: str | None = "subprocess call",
) -> Finding:
    path = Path(path)
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=Finding.make_fingerprint(
            canonical_cwe=None, rule_id=rule_id, file_path=path, code_snippet=snippet
        ),
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=path,
        line_start=1,
        line_end=1,
        code_snippet=snippet,
        message="m",
    )


def _rule(**keys) -> suppressions.SuppressionRule:
    return suppressions.SuppressionRule(
        rule_id=keys.pop("rule_id", "B602"),
        reason="reviewed",
        expires=datetime.date.today() + datetime.timedelta(days=30),
        **keys,
    )


@pytest.fixture
def elsewhere(tmp_path, monkeypatch) -> Path:
    """A working directory that is not the repository."""
    away = tmp_path / "elsewhere"
    away.mkdir()
    monkeypatch.chdir(away)
    return away


# ---------------------------------------------------------------------------
# Suppressions — what users already wrote keeps matching
# ---------------------------------------------------------------------------


def test_a_repository_relative_paths_glob_matches(tmp_path):
    assert _rule(paths=("src/*.py",)).matches(_finding("src/app.py"), tmp_path)


def test_a_star_slash_glob_written_for_absolute_paths_still_matches(tmp_path):
    """This repository's own `.scignore.yaml` is written this way."""
    assert _rule(paths=("*/src/app.py",)).matches(_finding("src/app.py"), tmp_path)
    assert _rule(paths=("**/app.py",)).matches(_finding("app.py"), tmp_path)


def test_the_compatibility_does_not_widen_a_glob_to_another_directory(tmp_path):
    assert not _rule(paths=("src/*.py",)).matches(_finding("lib/src/app.py"), tmp_path)
    assert not _rule(paths=("*/src/app.py",)).matches(_finding("src/app.pyc"), tmp_path)


def test_a_file_entry_matches_exactly_and_by_suffix(tmp_path):
    assert _rule(file="src/app.py").matches(_finding("src/app.py"), tmp_path)
    assert _rule(file="app.py").matches(_finding("src/app.py"), tmp_path)
    assert not _rule(file="src/other.py").matches(_finding("src/app.py"), tmp_path)


def test_an_absolute_file_entry_still_matches_its_file(tmp_path):
    entry = _rule(file=str(tmp_path / "src" / "app.py"))

    assert entry.matches(_finding("src/app.py"), tmp_path)
    assert not entry.matches(_finding("src/other.py"), tmp_path)


def test_a_fingerprint_pinned_from_an_older_report_still_matches(tmp_path):
    finding = _finding("src/app.py")
    old = _finding(tmp_path / "src" / "app.py").fingerprint

    assert old != finding.fingerprint
    assert _rule(fingerprint=old, line=1).matches(finding, tmp_path)
    assert _rule(fingerprint=finding.fingerprint, line=1).matches(finding, tmp_path)
    assert not _rule(fingerprint=old, line=1).matches(finding, tmp_path / "moved")


def test_this_repositorys_own_suppressions_still_match_what_they_name():
    """Every `*/`-prefixed glob here was written against an absolute path."""
    rules, errors = suppressions.load(REPO / ".scignore.yaml")
    assert not errors
    checked = 0
    for rule in rules:
        for pattern in rule.paths:
            assert pattern.startswith("*/"), pattern
            named = _finding(pattern.removeprefix("*/"), rule_id=rule.rule_id)
            assert rule.matches(named, REPO), f"{rule.rule_id} no longer matches {pattern}"
            checked += 1
    assert checked, "no path entries were checked"


# ---------------------------------------------------------------------------
# Baseline — an upgrade does not make every acknowledged finding new
# ---------------------------------------------------------------------------


def test_a_baseline_recorded_with_absolute_paths_still_matches(tmp_path):
    path = tmp_path / "baseline.json"
    baseline.write(path, [_finding(tmp_path / "src" / "app.py")], {})
    old = baseline.load(path)

    (marked,) = baseline.mark_new([_finding("src/app.py")], old, tmp_path)

    assert marked.is_new is False


def test_bumping_an_old_baseline_keeps_history_and_writes_the_portable_id(tmp_path):
    path = tmp_path / "baseline.json"
    baseline.write(path, [_finding(tmp_path / "src" / "app.py")], {})
    old = baseline.load(path)
    (first_seen,) = {entry.first_seen for entry in old.values()}

    current = _finding("src/app.py")
    baseline.write(path, [current], old, tmp_path)
    bumped = baseline.load(path)

    assert set(bumped) == {current.fingerprint}
    assert bumped[current.fingerprint].first_seen == first_seen
    assert bumped[current.fingerprint].file_path == "src/app.py"


# ---------------------------------------------------------------------------
# Consumers that read the disk
# ---------------------------------------------------------------------------


def test_a_variable_reference_is_read_from_the_repository_not_the_cwd(tmp_path, elsewhere):
    """D18 reads the flagged line back; a relative path must find it."""
    (tmp_path / "ci.yml").write_text("run: curl -u $" + "TOKEN: https://x\n", encoding="utf-8")
    secret = _finding("ci.yml", rule_id="gitleaks.curl-auth-user", category=Category.SECRETS)

    assert tier_of(secret, root=tmp_path) is Tier.REVIEW


def test_exclusions_and_own_artifacts_apply_to_relative_paths(tmp_path, elsewhere):
    cfg = config_mod.Config()
    cfg.exclude_patterns = ("vendor/",)
    report = tmp_path / "secure-code-report.md"
    control = _finding(Path("."), rule_id="bandit.tool_error")
    kept = _finding("src/app.py")

    result = _drop_excluded(
        [_finding("vendor/lib.py"), _finding("secure-code-report.md"), control, kept],
        tmp_path,
        cfg,
        frozenset({report.resolve()}),
        tmp_path,
    )

    assert result == [control, kept]


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_IDENTITY_OVERRIDE": "1"},
    )


def _committed_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "sub").mkdir(parents=True)
    for name in ("a.py", "b.py", "sub/c.py"):
        (root / "src" / name).write_text("x = 1\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "-c", "commit.gpgsign=false", "commit", "--no-verify", "-qm", "base")
    return root


def test_changed_only_places_a_relative_path_from_any_directory(tmp_path, elsewhere):
    root = _committed_repo(tmp_path)
    (root / "src" / "a.py").write_text("x = 2\n", encoding="utf-8")

    kept, _ = _restrict_to_changed([_finding("src/a.py"), _finding("src/b.py")], root, "HEAD")

    assert [f.file_path for f in kept] == [Path("src/a.py")]


def test_scope_cites_a_relative_path_from_a_subdirectory(tmp_path, monkeypatch):
    """A bare `resolve()` from `src/` would cite `src/src/a.py`."""
    root = _committed_repo(tmp_path)
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (root / "src" / "a.py").write_text("x = 2\n", encoding="utf-8")
    monkeypatch.chdir(root / "src")

    scope = measure_scope([_finding("src/a.py")], root, head)

    assert scope.known
    assert tuple(scope.cited) == ("src/a.py",)
    assert not scope.collateral
