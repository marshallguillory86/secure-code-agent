"""The tool must not audit its own output.

Third defect found by the self-audit, and the only one that reaches every
user rather than just this repository.

`secure-code-report.md` is the default Markdown target and it lands in the
root of the audited tree. The next run scanned it: 446KB of quoted findings,
complete with the code snippets that produced them. gitleaks duly reported a
"secret" at line 11,529 of the report — the redacted evidence from the
previous run, read back as source.

The score moved with it, so two identical audits of an unchanged repository
disagreed, which is the reproducibility promise (P6) broken by the tool's own
side effect.

`.gitignore` is no defence: scanners read the filesystem, not the index. Nor
is a suppression, because this is not a false positive worth accepting — it
is a file that was never in scope. So every path the run is about to write,
plus the baseline and suppression files it maintains, is dropped from its own
findings.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent

# A string Bandit reports as B105 (hardcoded_password_string), so the report
# written from it contains that same string as a quoted snippet.
BAIT = 'password = "hunter2-not-a-real-credential"\n'


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(BAIT, encoding="utf-8")
    (tmp_path / "cfg.json").write_text(json.dumps({"version": 1, "gates": {}}), encoding="utf-8")
    return tmp_path


def _audit(target: Path, *extra: str) -> dict:
    out = target / "report.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(target),
            "--config",
            str(target / "cfg.json"),
            "--only-scanners",
            "bandit,builtin_rules",
            "--json-output",
            str(out),
            "--output",
            str(target / "report.md"),
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert out.exists()
    return json.loads(out.read_text(encoding="utf-8"))


def test_the_markdown_report_is_not_a_finding_source(project):
    """Run twice. The report written by the first must not be scanned by the
    second — the exact sequence the self-audit hit."""
    first = _audit(project)
    assert (project / "report.md").exists(), "fixture never wrote a report"

    second = _audit(project)

    from_report = [f for f in second["findings"] if "report.md" in f["file_path"]]
    assert from_report == [], "the audit scored its own report: " + str(
        [(f["file_path"], f["rule_id"]) for f in from_report]
    )
    assert len(second["findings"]) == len(first["findings"])


def test_two_identical_runs_agree(project):
    """P6 in its smallest form. A tool whose own output changes its next
    answer is not reproducible, however pinned its inputs are."""
    first = _audit(project)
    second = _audit(project)

    assert second["score"]["overall"] == first["score"]["overall"]
    assert second["score"]["per_category_count"] == first["score"]["per_category_count"]


def test_the_json_report_is_not_a_finding_source(project):
    """`--json-output` lands in the tree too, and carries the same snippets."""
    _audit(project)
    second = _audit(project)

    assert [f for f in second["findings"] if "report.json" in f["file_path"]] == []


def test_the_baseline_is_not_a_finding_source(project):
    """The baseline is written by this tool and quotes finding text."""
    baseline = project / "baseline.json"
    _audit(project, "--bump-baseline", "--baseline", str(baseline))
    assert baseline.exists()

    second = _audit(project, "--baseline", str(baseline))

    assert [f for f in second["findings"] if "baseline.json" in f["file_path"]] == []


def test_the_real_source_file_is_still_scanned(project):
    """The exclusion must be surgical. Dropping the report is right; dropping
    the code it describes would be the same bug wearing a different hat."""
    report = _audit(project)

    assert any("app.py" in f["file_path"] for f in report["findings"]), (
        "the fixture's own source produced no findings, so this suite proves nothing"
    )
