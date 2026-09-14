"""A finding's path is repository-relative POSIX, whichever scanner reported it.

Reported from `maintainability-agent`, which runs this tool with an absolute
scan root. Its `.scignore.yaml` carried a reviewed entry for
`gitleaks.curl-auth-user` keyed by `paths:` to two workflow files, and all
five findings came back `suppressed: false` as live criticals. Bandit findings
did the same. Checkov findings on the same run matched their `paths:` entries.

The cause was not gitleaks. `Finding.file_path` had no single convention:
`Scanner._rooted` made every adapter-built path absolute (D5), the two
adapters that build through SARIF ingest left theirs relative, and every
consumer guessed. `SuppressionRule.matches` ran a repository-relative glob
against an absolute path, which cannot match. This project's own
`.scignore.yaml` shows the workaround that grew around it — every glob opens
with `*/` to swallow the checkout prefix.

The same absolute path fed the fingerprint, so a baseline recorded on one
machine matched nothing on another, or in CI.

The population is every registered scanner, not the one that was reported.
Each one is made to report a finding in both shapes seen in the wild —
absolute and relative to the scan root — and the real CLI pipeline has to
produce the same repository-relative path, the same fingerprint wherever the
checkout lives, and a matching `paths:` suppression, for all of them.
"""

from __future__ import annotations

import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from secure_code_audit import cli
from secure_code_audit import scanners as registry
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner

REPO = Path(__file__).resolve().parent.parent.parent

#: A suppression must expire within a year of the day it is read.
_EXPIRES = (datetime.date.today() + datetime.timedelta(days=180)).isoformat()

# ---------------------------------------------------------------------------
# Every registered scanner, through the real pipeline
# ---------------------------------------------------------------------------


def _shapes(name: str) -> dict[str, str]:
    """The two path shapes an adapter can hand the pipeline, keyed by shape."""
    return {"absolute": f"src/{name}_absolute.py", "relative": f"src/{name}_relative.py"}


def _stub_every_scanner(monkeypatch) -> None:
    """Replace each adapter's subprocess with a report in both path shapes."""

    def scan(self, target, config):
        root = target if target.is_dir() else target.parent
        shapes = _shapes(self.name)
        return self.completed(
            [
                self._make_finding(
                    rule_id=f"{self.name}.probe",
                    message="probe",
                    file_path=root / shapes["absolute"],
                    line_start=1,
                    line_end=None,
                    code_snippet=f"probe {self.name} absolute",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CODE_VULNERABILITIES,
                ),
                self._make_finding(
                    rule_id=f"{self.name}.probe",
                    message="probe",
                    file_path=Path(shapes["relative"]),
                    line_start=1,
                    line_end=None,
                    code_snippet=f"probe {self.name} relative",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.CODE_VULNERABILITIES,
                ),
            ]
        )

    for cls in registry.SCANNERS.values():
        monkeypatch.setattr(cls, "scan", scan)
    monkeypatch.setattr(Scanner, "is_available", lambda self: True)
    monkeypatch.setattr(Scanner, "binary_version", lambda self: "stub")


def _checkout(parent: Path, *, suppress: bool, subdir: str = "") -> Path:
    """A repository root, with the probe files under `subdir` when given."""
    tree = parent / "checkout"
    scanned = tree / subdir
    (scanned / "src").mkdir(parents=True)
    (tree / ".git").mkdir()
    for name in registry.SCANNERS:
        for rel in _shapes(name).values():
            (scanned / rel).write_text("x = 1\n", encoding="utf-8")
    if suppress:
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        (tree / ".scignore.yaml").write_text(
            '- rule_id: "*"\n'
            '  paths: ["src/*.py"]\n'
            "  reason: reviewed probe findings\n"
            f"  expires: {_EXPIRES}\n"
            "- rule_id: nothing.matches\n"
            "  file: nowhere.py\n"
            "  reason: lapsed on purpose\n"
            f"  expires: {yesterday}\n",
            encoding="utf-8",
        )
    return tree


def _config_enabling_everything(parent: Path, paths: dict | None = None) -> Path:
    path = parent / "every-scanner.json"
    document: dict = {"scanners": {name: {"enabled": True} for name in registry.SCANNERS}}
    if paths:
        document["paths"] = paths
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _audit(
    monkeypatch,
    parent: Path,
    *,
    suppress: bool,
    extra: tuple[str, ...] = (),
    subdir: str = "",
    paths: dict | None = None,
) -> dict:
    tree = _checkout(parent, suppress=suppress, subdir=subdir)
    out = parent / "report.json"
    # Somewhere that is not the tree: a consumer resolving a relative path
    # against the process working directory must not be rescued by luck.
    elsewhere = parent / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    cli.main(
        [
            str(tree / subdir),
            "--config",
            str(_config_enabling_everything(parent, paths)),
            "--json-output",
            str(out),
            *extra,
        ]
    )
    return {"tree": tree, "report": json.loads(out.read_text(encoding="utf-8"))}


def _probes(report: dict) -> list[dict]:
    return [f for f in report["findings"] if f["rule_id"].endswith(".probe")]


def _identity(findings: list[dict]) -> list[tuple[str, str, str]]:
    return sorted((f["scanner"], f["file_path"], f["fingerprint"]) for f in findings)


def test_every_registered_scanner_reports_a_repository_relative_path(tmp_path, monkeypatch):
    _stub_every_scanner(monkeypatch)
    run = _audit(monkeypatch, tmp_path, suppress=False)
    probes = _probes(run["report"])

    population = {f["scanner"] for f in probes}
    assert population, "no scanner reached the report; the check below would be vacuous"
    assert population == set(registry.SCANNERS)

    expected = {(name, rel) for name in registry.SCANNERS for rel in _shapes(name).values()}
    assert {(f["scanner"], f["file_path"]) for f in probes} == expected


def test_a_paths_suppression_matches_every_scanner_and_both_shapes(tmp_path, monkeypatch):
    """The reported defect, across the whole population."""
    _stub_every_scanner(monkeypatch)
    report = _audit(monkeypatch, tmp_path, suppress=True)["report"]
    probes = _probes(report)

    assert {f["scanner"] for f in probes} == set(registry.SCANNERS)
    live = sorted((f["scanner"], f["file_path"]) for f in probes if not f["suppressed"])
    assert live == [], f"a repository-relative paths: glob missed {live}"

    # The lapsed entry becomes a finding of its own, and it names the file
    # the way every other finding does.
    (lapsed,) = [f for f in report["findings"] if f["scanner"] == "suppressions"]
    assert lapsed["file_path"] == ".scignore.yaml"


def test_a_subdirectory_audit_is_relative_to_the_repository_and_still_classified(
    tmp_path, monkeypatch
):
    """Test patterns are relative to the scan target; finding paths to the root.

    `api/src/x.py` is `src/x.py` to a pattern written for the `api` target. A
    classifier reading the repository-relative path against the target would
    look for `api/api/src/x.py` and file every finding as primary.
    """
    _stub_every_scanner(monkeypatch)
    probes = _probes(
        _audit(
            monkeypatch,
            tmp_path,
            suppress=False,
            subdir="api",
            paths={"test_patterns": ["src/*"]},
        )["report"]
    )

    assert {f["scanner"] for f in probes} == set(registry.SCANNERS)
    assert {f["file_path"] for f in probes} == {
        f"api/{rel}" for name in registry.SCANNERS for rel in _shapes(name).values()
    }
    assert {f["axis"] for f in probes} == {"test tree"}


def test_fingerprints_do_not_depend_on_where_the_checkout_lives(tmp_path, monkeypatch):
    """A baseline made on a laptop has to mean something in CI."""
    _stub_every_scanner(monkeypatch)
    (tmp_path / "a").mkdir()
    (tmp_path / "b" / "deeper").mkdir(parents=True)
    first = _probes(_audit(monkeypatch, tmp_path / "a", suppress=False)["report"])
    second = _probes(_audit(monkeypatch, tmp_path / "b" / "deeper", suppress=False)["report"])

    assert first and _identity(first) == _identity(second)
    for f in first:
        assert f["fingerprint"] == Finding.make_fingerprint(
            canonical_cwe=f["canonical_cwe"],
            rule_id=f["rule_id"],
            file_path=Path(f["file_path"]),
            code_snippet=f["code_snippet"],
        )


def test_no_written_output_names_the_checkout(tmp_path, monkeypatch):
    """SARIF, Markdown, the work order and the baseline are read elsewhere.

    An absolute path in any of them names one machine: GitHub code scanning
    cannot place a SARIF result at `/home/runner/work/...`, and a baseline
    carrying it is a record of where someone's laptop kept the repository.
    """
    _stub_every_scanner(monkeypatch)
    sarif = tmp_path / "out.sarif"
    run = _audit(
        monkeypatch,
        tmp_path,
        suppress=False,
        extra=("--sarif-output", str(sarif), "--bump-baseline"),
    )
    tree = run["tree"]

    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for sarif_run in json.loads(sarif.read_text(encoding="utf-8"))["runs"]
        for result in sarif_run["results"]
        if result["ruleId"].endswith(".probe")
    }
    assert uris and not any(uri.startswith("/") for uri in uris), sorted(uris)[:5]

    baseline = json.loads((tree / "secure-code-baseline.json").read_text(encoding="utf-8"))
    paths = {entry["file_path"] for entry in baseline["entries"].values()}
    assert paths and not any(p.startswith("/") for p in paths), sorted(paths)[:5]

    for name in ("secure-code-report.md", "secure-code-remediation-prompt.md"):
        text = (tree / name).read_text(encoding="utf-8")
        probe_lines = [line for line in text.splitlines() if "_absolute.py" in line]
        assert probe_lines, f"{name} lists no probe finding; the check would be vacuous"
        assert not [line for line in probe_lines if str(tree) in line], name


# ---------------------------------------------------------------------------
# The real tools, audited the way maintainability-agent audits
# ---------------------------------------------------------------------------


def _git(tree: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=tree,
        check=True,
        capture_output=True,
    )


def _real_repository(parent: Path) -> Path:
    """A committed tree with one gitleaks hit and one Bandit hit.

    Both lines are assembled from parts, so this source matches neither rule —
    this repository audits its own tests, and spelling a vulnerable pattern
    out has created a finding here three times already.
    """
    tree = parent / "repo"
    (tree / ".github" / "workflows").mkdir(parents=True)
    (tree / "src").mkdir()
    auth = "cu" + "rl -u " + "admin:" + "Sup3r" + "S3cretPassw0rd"
    (tree / ".github" / "workflows" / "ci.yml").write_text(
        f"jobs:\n  x:\n    steps:\n      - run: {auth} https://example.com/api\n",
        encoding="utf-8",
    )
    call = "subprocess.call(x, shell" + "=True)"
    (tree / "src" / "app.py").write_text(
        f"import subprocess\n\n\ndef f(x):\n    {call}\n", encoding="utf-8"
    )
    (tree / ".scignore.yaml").write_text(
        "- rule_id: gitleaks.curl-auth-user\n"
        '  paths: [".github/workflows/ci.yml"]\n'
        "  reason: reviewed fixture\n"
        f"  expires: {_EXPIRES}\n"
        "- rule_id: B602\n"
        '  paths: ["src/*.py"]\n'
        "  reason: reviewed fixture\n"
        f"  expires: {_EXPIRES}\n",
        encoding="utf-8",
    )
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-qm", "init")
    return tree


def _run_cli(target: str, cwd: Path, scanners: str, out: Path) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            target,
            "--only-scanners",
            scanners,
            "--json-output",
            str(out),
        ],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    assert out.exists(), result.stdout[-800:] + result.stderr[-800:]
    return json.loads(out.read_text(encoding="utf-8"))


def _findings_of(report: dict, rule_id: str) -> list[dict]:
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


@pytest.mark.parametrize("target_form", ["absolute", "dot"])
def test_bandit_honours_a_paths_suppression(tmp_path, target_form):
    tree = _real_repository(tmp_path)
    target, cwd = (str(tree), tmp_path) if target_form == "absolute" else (".", tree)
    report = _run_cli(target, cwd, "bandit", tmp_path / "bandit.json")

    hits = _findings_of(report, "B602")
    assert hits, "bandit reported nothing; the fixture no longer exercises the defect"
    assert {f["file_path"] for f in hits} == {"src/app.py"}
    assert all(f["suppressed"] for f in hits)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks is not installed")
@pytest.mark.parametrize("target_form", ["absolute", "dot"])
def test_gitleaks_honours_a_paths_suppression(tmp_path, target_form):
    """The reported shape: gitleaks, a workflow file, a reviewed entry."""
    tree = _real_repository(tmp_path)
    target, cwd = (str(tree), tmp_path) if target_form == "absolute" else (".", tree)
    report = _run_cli(target, cwd, "gitleaks", tmp_path / "gitleaks.json")

    hits = _findings_of(report, "gitleaks.curl-auth-user")
    assert hits, "gitleaks reported nothing; the fixture no longer exercises the defect"
    assert {f["file_path"] for f in hits} == {".github/workflows/ci.yml"}
    assert all(f["suppressed"] for f in hits)
