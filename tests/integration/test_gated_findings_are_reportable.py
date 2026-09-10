"""A gate reason the operator cannot act on is not a gate, it is an alarm.

Found by the tool's own self-audit, in the tool's own three-axis change.

The run failed its gate with:

    ✗ 1 finding(s) in categories ['secrets']
    ✗ 1 new finding(s) since baseline

and the JSON it wrote alongside contained fourteen findings, none of them a
secret. The escalated finding lived on the test-tree axis, and the axis blocks
carry only counts. So the build failed, correctly, and the report gave nobody
a file to open.

The cause was one rebound name. `partition_by_path` returns the primary set,
it was assigned back over `all_findings`, and everything downstream that read
that name at face value silently narrowed with it:

  * the report — the symptom above;
  * the baseline. `baseline.write` then recorded only primary findings, so
    every side-axis finding stayed absent from it and `fail_on_new` re-flagged
    the same test-tree secret as new on every run, forever. A baseline that
    cannot absorb a finding is a gate that can never go green.

421 tests passed throughout. They checked the partition, the gating and the
axis summaries in isolation, and none of them asserted the one property that
ties those together: whatever trips the gate must be findable in the report.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent


def _run(target: Path, out: Path, *extra: str, scanners: str = "bandit") -> dict:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(target),
            "--config",
            str(target / "cfg.json"),
            "--only-scanners",
            scanners,
            "--json-output",
            str(out),
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert out.exists(), "the audit produced no report"
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A tree whose only HIGH finding is in its test directory."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    # B608: string-built SQL. HIGH, and deliberately in the test tree.
    (tmp_path / "tests" / "test_q.py").write_text(
        "def q(u):\n    return \"SELECT * FROM t WHERE u = '%s'\" % u\n",
        encoding="utf-8",
    )
    (tmp_path / "cfg.json").write_text(
        json.dumps({"version": 1, "gates": {"fail_on_category": ["code_vulnerabilities"]}}),
        encoding="utf-8",
    )
    return tmp_path


def test_the_finding_that_tripped_the_gate_is_in_the_report(tmp_path):
    """The property that was missing, reproduced end to end.

    Only `secrets` escalate off a side axis (`GATED_FROM_ANY_AXIS`), and no
    in-process rule emits that category, so this one test needs gitleaks. It
    no longer needs a *commit*, because the working-tree pass now exists —
    which is the other defect this session fixed, and a small proof of it.
    """
    if shutil.which("gitleaks") is None:
        pytest.skip("needs gitleaks")

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(
        ["openssl", "genrsa", "-out", str(tmp_path / "tests" / "fixture.key"), "2048"],
        check=True,
        capture_output=True,
    )
    (tmp_path / "cfg.json").write_text(
        json.dumps({"version": 1, "gates": {"fail_on_category": ["secrets"]}}),
        encoding="utf-8",
    )

    report = _run(tmp_path, tmp_path / "r.json", scanners="gitleaks")

    assert report["gate"]["passed"] is False, "fixture did not trip the gate"
    assert "fail_on_category" in report["gate"]["tripped"]

    reported = {(f["file_path"], f["rule_id"]) for f in report["findings"]}
    assert any("fixture.key" in path for path, _ in reported), (
        f"the gate tripped on a secret the report does not contain: {sorted(reported)}"
    )


def test_the_escalated_secret_is_still_not_scored(tmp_path):
    """Reported and gated, and still not grading the code condition."""
    if shutil.which("gitleaks") is None:
        pytest.skip("needs gitleaks")

    (tmp_path / "tests").mkdir()
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(
        ["openssl", "genrsa", "-out", str(tmp_path / "tests" / "fixture.key"), "2048"],
        check=True,
        capture_output=True,
    )
    (tmp_path / "cfg.json").write_text(
        json.dumps({"version": 1, "gates": {"fail_on_category": ["secrets"]}}),
        encoding="utf-8",
    )

    report = _run(tmp_path, tmp_path / "r.json", scanners="gitleaks")

    assert report["gate"]["passed"] is False
    assert report["score"]["per_category_count"]["secrets"] == 0
    assert report["score"]["overall"] == 5.0


def test_a_side_axis_finding_is_reported_but_marked_unscored(project, tmp_path):
    """Present in the array, and honest about not counting toward the grade.

    This is why the axis tag exists: one complete array, each entry saying
    which axis it belongs to, so a consumer neither misses findings nor
    double-counts them by also summing the axis blocks.
    """
    report = _run(project, tmp_path / "r.json")

    side = [f for f in report["findings"] if "test_q.py" in f["file_path"]]

    assert side, "the test-tree finding is missing from findings[]"
    assert all(f["axis"] == "test tree" for f in side)
    assert all(f["scored"] is False for f in side)


def test_the_score_still_ignores_it(project, tmp_path):
    """Reporting it must not start grading it — the whole point of the split."""
    report = _run(project, tmp_path / "r.json")

    assert report["score"]["per_category_count"]["code_vulnerabilities"] == 0


def test_the_axis_block_and_the_findings_array_agree(project, tmp_path):
    """Two views of one set. If they disagree, one of them is lying."""
    report = _run(project, tmp_path / "r.json")

    tagged = sum(1 for f in report["findings"] if f["axis"] == "test tree")

    assert tagged == report["reported_not_scored"]["test_tree"]["count"]


def test_suppressing_a_side_axis_finding_does_not_move_it_into_the_score(project, tmp_path):
    """Accepting a finding must not promote it.

    Also found by the self-audit. `summarize_axis` filtered suppressed
    findings out of `AxisReport.findings`, which is the membership the
    renderer reads to tag each finding with its axis. A suppressed test-tree
    finding therefore matched no axis, fell through to the "primary" default,
    and was published as `axis: primary, scored: true` — so suppressing one
    gitleaks false positive silently moved it into the scored set.

    The class docstring had promised the opposite the whole time: "Reported,
    never discarded: every finding is carried in full."
    """
    suppressions = project / ".scignore.yaml"
    suppressions.write_text(
        "- rule_id: B608\n"
        '  paths: ["*/tests/*"]\n'
        '  reason: "deliberate SQL string in a test double"\n'
        '  expires: "2027-09-10"\n',
        encoding="utf-8",
    )

    report = _run(project, tmp_path / "r.json")

    side = [f for f in report["findings"] if "test_q.py" in f["file_path"]]
    assert side, "the finding vanished entirely"
    assert all(f["suppressed"] for f in side), "fixture did not suppress"
    assert all(f["axis"] == "test tree" for f in side), (
        "suppressing moved the finding to the primary axis: " + str([f["axis"] for f in side])
    )
    assert all(f["scored"] is False for f in side)


def test_a_suppressed_finding_is_a_member_of_its_axis_but_not_a_count(project, tmp_path):
    """Both halves. Membership complete, totals live-only.

    An operator who accepted a finding should not keep reading it in the
    axis total, and a consumer resolving which axis a finding belongs to
    must still be able to find it.
    """
    (project / ".scignore.yaml").write_text(
        "- rule_id: B608\n"
        '  paths: ["*/tests/*"]\n'
        '  reason: "deliberate SQL string in a test double"\n'
        '  expires: "2027-09-10"\n',
        encoding="utf-8",
    )

    report = _run(project, tmp_path / "r.json")

    assert report["reported_not_scored"]["test_tree"]["count"] == 0
    assert any(f["axis"] == "test tree" for f in report["findings"])


def test_a_side_axis_finding_can_be_baselined(project, tmp_path):
    """`fail_on_new` must be satisfiable.

    A baseline written without side-axis findings leaves them permanently
    new, so a gate configured with `fail_on_new` can never go green no matter
    what the operator does. The self-audit hit exactly this: the same
    test-tree secret was reported as new on every run.
    """
    baseline = project / "baseline.json"
    _run(project, tmp_path / "r1.json", "--bump-baseline", "--baseline", str(baseline))

    assert baseline.exists(), "no baseline was written"

    second = _run(project, tmp_path / "r2.json", "--baseline", str(baseline))

    # Assert the finding is *there* before asserting it is not new. Without
    # this the test passes vacuously under the very bug it guards: when the
    # side-axis finding never reaches the report, "nothing is new" is
    # trivially true and the baseline is never actually exercised.
    side = [f for f in second["findings"] if "test_q.py" in f["file_path"]]
    assert side, "the side-axis finding is absent, so this proves nothing"

    still_new = [f for f in side if f["is_new"]]
    assert still_new == [], (
        "findings remain new after being baselined, so fail_on_new can never "
        "be satisfied: " + str([f["file_path"] for f in still_new])
    )

    # And it really is recorded, not merely absent from both sides.
    recorded = json.loads(baseline.read_text(encoding="utf-8"))
    assert "test_q.py" in json.dumps(recorded), "the baseline omits the side-axis finding"
