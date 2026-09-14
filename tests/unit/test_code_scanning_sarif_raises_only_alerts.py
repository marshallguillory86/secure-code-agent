"""What reaches GitHub code scanning is what should become an alert, and nothing else.

`sarif._suppressions` marks every test-tree and documentation finding, and
every `.scignore.yaml` suppression, with the SARIF-standard `suppressions`
array. GitHub code scanning does not act on that field: an upload opens an
alert for each result whether it carries one or not. GitHub's own
`advanced-security/dismiss-alerts` action exists only to bridge that.

It stayed invisible while finding paths were absolute, because GitHub could
not place those results on a pull request's lines. D20 made paths
repository-relative, and the next pull request here — two new test files —
carried fourteen code-scanning review threads for `assert` in pytest, which
branch protection then required resolved before merge. Every repository using
this project's action with SARIF upload gets the same.

So the file uploaded to code scanning omits results that carry `suppressions`,
while `--sarif-output` keeps writing every result with its suppression, as the
record. The population is every reason `_suppressions` suppresses, derived from
`sarif._SIDE_AXES`, plus an operator suppression and a live finding.

**Omitting must not hide a finding the build fails on.** A secret on a side
axis is marked suppressed in the record, and the gate still escalates it from
any axis (`scoring.GATED_FROM_ANY_AXIS`). It stays in the upload. What is left
out is only what nothing acts on: the test tree's and documentation's other
findings, and entries an operator reviewed with a reason and an expiry — which
return as a live critical finding when they lapse.
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from secure_code_audit import sarif
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import GATED_FROM_ANY_AXIS

REPO = Path(__file__).resolve().parents[2]


def _finding(
    name: str, *, suppressed: bool = False, category: Category = Category.CODE_VULNERABILITIES
) -> Finding:
    path = Path(f"src/{name}.py")
    return Finding(
        rule_id=f"R-{name}",
        scanner="bandit",
        fingerprint=Finding.make_fingerprint(
            canonical_cwe=None, rule_id=f"R-{name}", file_path=path, code_snippet=name
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
        code_snippet=name,
        message=name,
        suppressed=suppressed,
        suppression_note="reviewed" if suppressed else None,
    )


def _population() -> tuple[list[Finding], dict[str, str], set[str]]:
    """Every way a result can be marked suppressed, each paired with what the
    upload must do with it.

    Returns the findings, the axis of each by rule id, and the rule ids the
    upload must carry. A side-axis finding in a category the gate escalates
    from any axis (`scoring.GATED_FROM_ANY_AXIS`: a secret in a test fixture)
    is marked suppressed in the record and still has to reach code scanning,
    because the build fails on it.
    """
    axes: dict[str, str] = {}
    findings = [
        _finding("live"),
        _finding("operator", suppressed=True),
        _finding("operator_secret", suppressed=True, category=Category.SECRETS),
        _finding("dependency", category=Category.DEPENDENCIES),
    ]
    axes["R-dependency"] = "dependencies"
    alerts = {"R-live", "R-dependency"}
    for axis in sorted(sarif._SIDE_AXES):
        slug = axis.replace(" ", "_")
        findings.append(_finding(slug))
        axes[f"R-{slug}"] = axis
        for category in sorted(GATED_FROM_ANY_AXIS, key=lambda c: c.value):
            name = f"{slug}_{category.value}"
            findings.append(_finding(name, category=category))
            axes[f"R-{name}"] = axis
            alerts.add(f"R-{name}")
    return findings, axes, alerts


def _results(document: dict) -> list[dict]:
    return [result for run in document["runs"] for result in run["results"]]


def test_the_population_covers_every_reason_to_suppress():
    findings, axes, alerts = _population()
    assert sarif._SIDE_AXES and set(sarif._SIDE_AXES) <= set(axes.values())
    assert GATED_FROM_ANY_AXIS, "no escalated category; the exception would go untested"
    assert any(f.suppressed for f in findings)
    assert alerts < {f.rule_id for f in findings}


def test_the_upload_holds_exactly_the_alerts():
    findings, axes, alerts = _population()

    def axis_of(f):
        return axes.get(f.rule_id, "primary")

    record = sarif.emit(findings, None, axis_of)
    upload = sarif.emit(findings, None, axis_of, alerts_only=True)

    suppressed = {r["ruleId"] for r in _results(record) if r.get("suppressions")}
    assert suppressed - alerts, "nothing was left out; the check would be vacuous"

    uploaded = {r["ruleId"] for r in _results(upload)}
    assert uploaded == alerts, (
        f"missing from code scanning: {sorted(alerts - uploaded)}; "
        f"alerting on what should not: {sorted(uploaded - alerts)}"
    )
    assert not any(r.get("suppressions") for r in _results(upload))
    # A rule with no result left would still describe a check nobody reported.
    assert {rule["id"] for rule in upload["runs"][0]["tool"]["driver"]["rules"]} == alerts


def test_a_secret_the_gate_fails_on_is_never_kept_from_code_scanning():
    """The build fails on a test-fixture secret (`fail_on_category: [secrets]`).
    A Security tab that does not show the finding failing the build would be
    the upload hiding a true, actionable result."""
    secret = _finding("fixture_key", category=Category.SECRETS)

    for axis in sarif._SIDE_AXES:
        upload = sarif.emit([secret], None, lambda _f, axis=axis: axis, alerts_only=True)
        assert [r["ruleId"] for r in _results(upload)] == ["R-fixture_key"], axis


def test_the_record_still_keeps_every_result():
    """Suppressed, not omitted — in the file a person reads."""
    findings, axes, _ = _population()
    record = sarif.emit(findings, None, lambda f: axes.get(f.rule_id, "primary"))

    assert len(_results(record)) == len(findings)


def test_an_upload_with_nothing_to_alert_on_is_still_a_sarif_document():
    """An empty upload is how GitHub learns the old alerts are gone."""
    findings, _, _ = _population()
    quiet = [replace(f, suppressed=True, suppression_note="reviewed") for f in findings]

    upload = sarif.emit(quiet, None, alerts_only=True)

    assert upload["version"] == "2.1.0" and _results(upload) == []


# ---------------------------------------------------------------------------
# Through the CLI, with the real Bandit
# ---------------------------------------------------------------------------


def test_the_cli_writes_the_record_and_the_upload(tmp_path):
    tree = tmp_path / "repo"
    (tree / "tests").mkdir(parents=True)
    (tree / "tests" / "test_app.py").write_text("def test_it():\n    assert 1\n", encoding="utf-8")
    call = "subprocess.call(x, shell" + "=True)"
    (tree / "app.py").write_text(
        f"import subprocess\n\n\ndef f(x):\n    {call}\n    assert x\n", encoding="utf-8"
    )
    expires = (datetime.date.today() + datetime.timedelta(days=90)).isoformat()
    (tree / ".scignore.yaml").write_text(
        f'- rule_id: B101\n  paths: ["app.py"]\n  reason: reviewed\n  expires: "{expires}"\n',
        encoding="utf-8",
    )
    record, upload = tmp_path / "record.sarif", tmp_path / "upload.sarif"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(tree),
            "--only-scanners",
            "bandit",
            "--sarif-output",
            str(record),
            "--code-scanning-sarif-output",
            str(upload),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert upload.exists(), result.stdout[-800:] + result.stderr[-800:]

    def located(path: Path) -> set[tuple[str, str, bool]]:
        return {
            (
                r["ruleId"],
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                bool(r.get("suppressions")),
            )
            for r in _results(json.loads(path.read_text(encoding="utf-8")))
        }

    kept = located(record)
    assert ("B101", "tests/test_app.py", True) in kept, kept
    assert ("B101", "app.py", True) in kept, kept
    assert ("B602", "app.py", False) in kept, kept

    sent = located(upload)
    assert ("B602", "app.py", False) in sent, sent
    assert not {entry for entry in sent if entry[2] or entry[0] == "B101"}, sent


def test_the_configured_output_is_written_too(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"outputs": {"code_scanning_sarif_path": "alerts.sarif"}}), encoding="utf-8"
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(tree),
            "--config",
            str(config),
            "--only-scanners",
            "bandit",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )

    assert (tree / "alerts.sarif").exists()


# ---------------------------------------------------------------------------
# Every upload this project ships sends the upload file
# ---------------------------------------------------------------------------


def _upload_steps() -> list[tuple[str, str]]:
    """(file, sarif_file value) for every step uploading this tool's SARIF.

    Identified by the upload category, because the repository also uploads
    OpenSSF Scorecard's own SARIF, which this tool does not write.
    """
    files = [REPO / "action.yml", *sorted((REPO / ".github" / "workflows").glob("*.y*ml"))]
    steps: list[tuple[str, str]] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"\n\s*- name:", text):
            if "codeql-action/upload-sarif" not in block:
                continue
            category = re.search(r"category:\s*(.+)", block)
            if not category or not category.group(1).strip().startswith("secure-code-agent"):
                continue
            match = re.search(r"sarif_file:\s*(.+)", block)
            steps.append((path.name, match.group(1).strip() if match else ""))
    return steps


def test_every_shipped_upload_sends_the_code_scanning_file():
    steps = _upload_steps()
    assert {name for name, _ in steps} >= {"action.yml", "ci.yml"}, steps
    wrong = [(name, value) for name, value in steps if "code-scanning" not in value]
    assert not wrong, f"these upload the record, which GitHub turns into alerts wholesale: {wrong}"


def test_the_upload_file_is_this_tools_own_output_and_never_scanned():
    from secure_code_audit.config import DEFAULT_EXCLUDES, DEFAULT_OUTPUTS

    name = DEFAULT_OUTPUTS["code_scanning_sarif_path"]
    assert f"**/{name}" in DEFAULT_EXCLUDES
