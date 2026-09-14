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

REPO = Path(__file__).resolve().parents[2]


def _finding(name: str, *, suppressed: bool = False) -> Finding:
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
        category=Category.CODE_VULNERABILITIES,
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


def _population() -> tuple[list[Finding], dict[str, str]]:
    """One finding per way to be suppressed, and one that is not."""
    axes: dict[str, str] = {}
    findings = [_finding("live"), _finding("operator", suppressed=True)]
    for axis in sorted(sarif._SIDE_AXES):
        slug = axis.replace(" ", "_")
        findings.append(_finding(slug))
        axes[f"R-{slug}"] = axis
    return findings, axes


def _results(document: dict) -> list[dict]:
    return [result for run in document["runs"] for result in run["results"]]


def test_the_population_covers_every_reason_to_suppress():
    findings, axes = _population()
    assert set(axes.values()) == set(sarif._SIDE_AXES) and sarif._SIDE_AXES
    assert any(f.suppressed for f in findings)


def test_the_upload_holds_exactly_the_results_that_carry_no_suppression():
    findings, axes = _population()

    def axis_of(f):
        return axes.get(f.rule_id, "primary")

    record = sarif.emit(findings, None, axis_of)
    upload = sarif.emit(findings, None, axis_of, alerts_only=True)

    suppressed = {r["ruleId"] for r in _results(record) if r.get("suppressions")}
    live = {r["ruleId"] for r in _results(record) if not r.get("suppressions")}
    assert suppressed and live, "the record lost a kind of result; the check would be vacuous"

    uploaded = {r["ruleId"] for r in _results(upload)}
    assert uploaded == live
    assert not any(r.get("suppressions") for r in _results(upload))
    # A rule with no result left would still describe a check nobody reported.
    assert {rule["id"] for rule in upload["runs"][0]["tool"]["driver"]["rules"]} == live


def test_the_record_still_keeps_every_result():
    """Suppressed, not omitted — in the file a person reads."""
    findings, axes = _population()
    record = sarif.emit(findings, None, lambda f: axes.get(f.rule_id, "primary"))

    assert len(_results(record)) == len(findings)


def test_an_upload_with_nothing_to_alert_on_is_still_a_sarif_document():
    """An empty upload is how GitHub learns the old alerts are gone."""
    findings, _ = _population()
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
