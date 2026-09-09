"""The three adapters wired by D12: njsscan, RuboCop and gosec.

Every payload here is a real capture, trimmed. The gosec cases matter most:
that tool reports a total failure to read the target as well-formed JSON with
an empty `Issues` list, so the difference between "clean" and "never opened the
repository" lives entirely in fields a naive adapter would not read.
"""

import json
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit.config import Config
from secure_code_audit.findings import Severity
from secure_code_audit.scanners.gosec_scanner import GosecScanner
from secure_code_audit.scanners.njsscan_scanner import NjsscanScanner
from secure_code_audit.scanners.rubocop_scanner import RubocopScanner


def _proc(stdout="", stderr="", code=0):
    return CompletedProcess(args=["scanner"], returncode=code, stdout=stdout, stderr=stderr)


def _configured(scanner, command):
    scanner._resolved_command = (command,)
    return scanner


# --------------------------------------------------------------------------
# njsscan
# --------------------------------------------------------------------------

_NJSSCAN_PAYLOAD = {
    "errors": [],
    "njsscan_version": "1.0.0",
    "nodejs": {
        "node_md5": {
            "files": [
                {
                    "file_path": "/repo/app.js",
                    "match_lines": [8, 8],
                    "match_position": [34, 58],
                    "match_string": "crypto.createHash('md5')",
                },
                {
                    "file_path": "/repo/other.js",
                    "match_lines": [3, 4],
                    "match_position": [1, 9],
                    "match_string": "createHash('md5')",
                },
            ],
            "metadata": {
                "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                "description": "MD5 is a weak hash.",
                "owasp-web": "A9",
                "severity": "WARNING",
            },
        }
    },
    "templates": {},
}


def test_njsscan_flattens_one_finding_per_occurrence(tmp_path, monkeypatch):
    """njsscan groups by rule; a report needs one finding per site.

    Two occurrences of `node_md5` under a single key must not collapse into one
    finding, or a file with the same defect in ten places reports as one.
    """
    scanner = _configured(NjsscanScanner(), "njsscan")
    monkeypatch.setattr(
        scanner, "_exec", lambda *a, **k: _proc(json.dumps(_NJSSCAN_PAYLOAD), code=1)
    )

    findings = scanner.scan(tmp_path, Config()).findings

    assert len(findings) == 2
    assert {f.rule_id for f in findings} == {"node_md5"}
    assert {str(f.file_path) for f in findings} == {"/repo/app.js", "/repo/other.js"}
    # The shared metadata reaches every occurrence, not just the first.
    assert all(f.message == "MD5 is a weak hash." for f in findings)
    assert all(f.severity is Severity.MEDIUM for f in findings)
    # match_lines is [start, end]; a multi-line match keeps its end.
    spans = {(f.line_start, f.line_end) for f in findings}
    assert spans == {(8, 8), (3, 4)}


def test_njsscan_reads_the_templates_bucket_too(tmp_path, monkeypatch):
    payload = {
        "nodejs": {},
        "templates": {
            "express_xss": {
                "files": [{"file_path": "/repo/v.pug", "match_lines": [2, 2]}],
                "metadata": {"description": "unescaped", "severity": "ERROR"},
            }
        },
    }
    scanner = _configured(NjsscanScanner(), "njsscan")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload), code=1))

    assert [f.rule_id for f in scanner.scan(tmp_path, Config()).findings] == ["express_xss"]


def test_njsscan_reports_timeout_and_unparseable_output(tmp_path, monkeypatch):
    scanner = _configured(NjsscanScanner(), "njsscan")

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stderr="slow", code=124))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "njsscan.tool_timeout"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout="not json"))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "njsscan.tool_error"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout=""))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "njsscan.tool_error"


def test_njsscan_survives_a_malformed_section(tmp_path, monkeypatch):
    payload = {"nodejs": ["not", "a", "dict"], "templates": {"r": "not a dict"}}
    scanner = _configured(NjsscanScanner(), "njsscan")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload)))

    assert scanner.scan(tmp_path, Config()).findings == ()


# --------------------------------------------------------------------------
# RuboCop
# --------------------------------------------------------------------------


def test_rubocop_parses_security_offenses(tmp_path, monkeypatch):
    payload = {
        "files": [
            {
                "path": "app.rb",
                "offenses": [
                    {
                        "cop_name": "Security/Eval",
                        "message": "The use of `eval` is a serious security risk.",
                        "severity": "convention",
                        "location": {"start_line": 9, "last_line": 9},
                    },
                    {
                        "cop_name": "Security/MarshalLoad",
                        "message": "Avoid using `Marshal.load`.",
                        "severity": "error",
                        "location": {"start_line": 13, "last_line": 13},
                    },
                ],
            }
        ],
        "summary": {"offense_count": 2},
    }
    scanner = _configured(RubocopScanner(), "rubocop")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload), code=1))

    findings = scanner.scan(tmp_path, Config()).findings

    assert [f.rule_id for f in findings] == ["Security/Eval", "Security/MarshalLoad"]
    assert [f.line_start for f in findings] == [9, 13]
    assert findings[1].severity is Severity.HIGH


def test_a_convention_severity_is_not_demoted_out_of_the_gate(tmp_path, monkeypatch):
    """RuboCop calls most Security cops `convention`, its mildest real level.

    That is a linter's word for "style rule", and most Security cops carry it.
    Mapping it to INFORMATIONAL would drop `eval` out of any gate that filters
    on severity — the finding would be present in the report and absent from
    the decision, which is the worst of both.
    """
    payload = {
        "files": [
            {
                "path": "a.rb",
                "offenses": [
                    {
                        "cop_name": "Security/Eval",
                        "message": "risk",
                        "severity": "convention",
                        "location": {"start_line": 1},
                    }
                ],
            }
        ]
    }
    scanner = _configured(RubocopScanner(), "rubocop")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload), code=1))

    assert scanner.scan(tmp_path, Config()).findings[0].severity is Severity.MEDIUM


def test_rubocop_is_restricted_to_security_and_ignores_the_targets_config(tmp_path, monkeypatch):
    """Two invariants that are the whole reason this adapter is defensible.

    `--only Security` is what makes a style linter a security scanner.
    `--force-default-config` is D1: the audited tree's `.rubocop.yml` can
    disable cops and `require:` Ruby that RuboCop would then load and run, so a
    repository must not get to choose what is found in it.
    """
    seen: list[list[str]] = []

    def fake_exec(args, **kwargs):
        seen.append(list(args))
        return _proc(json.dumps({"files": []}))

    scanner = _configured(RubocopScanner(), "rubocop")
    monkeypatch.setattr(scanner, "_exec", fake_exec)
    scanner.scan(tmp_path, Config())

    assert seen[0][seen[0].index("--only") + 1] == "Security"
    assert "--force-default-config" in seen[0]


def test_rubocop_reports_timeout_and_unparseable_output(tmp_path, monkeypatch):
    scanner = _configured(RubocopScanner(), "rubocop")

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stderr="slow", code=124))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "rubocop.tool_timeout"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout="{"))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "rubocop.tool_error"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout=" "))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "rubocop.tool_error"


def test_rubocop_skips_malformed_entries_rather_than_raising(tmp_path, monkeypatch):
    payload = {"files": [None, {"path": "a.rb", "offenses": [None, "x"]}]}
    scanner = _configured(RubocopScanner(), "rubocop")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload)))

    assert scanner.scan(tmp_path, Config()).findings == ()


# --------------------------------------------------------------------------
# gosec — the silent-empty cases
# --------------------------------------------------------------------------

#: Captured verbatim from gosec 2.29.0 on a host with no Go toolchain. Note
#: `Issues: []` and exit 1: the run is a total failure and the payload is
#: well-formed.
_GOSEC_NO_TOOLCHAIN = {
    "Golang errors": {
        "/repo/pkg": [
            {
                "line": 0,
                "column": 0,
                "error": (
                    'loading files from package "/repo/pkg": err: go command '
                    'required, not found: exec: "go": executable file not '
                    "found in $PATH: stderr: "
                ),
            }
        ]
    },
    "Issues": [],
    "Stats": {"files": 0, "lines": 0, "nosec": 0, "found": 0},
    "GosecVersion": "2.29.0",
}


def test_gosec_without_a_go_toolchain_is_a_failure_not_a_clean_scan(tmp_path, monkeypatch):
    """The defect this adapter exists to avoid.

    gosec reports a total inability to read the repository as valid JSON with
    an empty `Issues` list. An adapter that parses `Issues` and returns `[]`
    reports a clean Go scan of a repository gosec never opened, and coverage
    would record a pass. Absence of evidence must not arrive as evidence of
    absence.
    """
    scanner = _configured(GosecScanner(), "gosec")
    monkeypatch.setattr(
        scanner, "_exec", lambda *a, **k: _proc(json.dumps(_GOSEC_NO_TOOLCHAIN), code=1)
    )

    findings = scanner.scan(tmp_path, Config()).findings

    assert [f.rule_id for f in findings] == ["gosec.tool_error"]
    assert "could not load the Go packages" in findings[0].message
    assert "go command required" in findings[0].message


def test_gosec_reporting_zero_files_with_no_error_is_still_not_clean(tmp_path, monkeypatch):
    """The quieter half of the same failure.

    A load that reads nothing and records no error is not a scanned
    repository. Either applicability should have excluded us, or something
    failed without saying so; neither is a pass.
    """
    payload = {"Golang errors": {}, "Issues": [], "Stats": {"files": 0, "found": 0}}
    scanner = _configured(GosecScanner(), "gosec")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload)))

    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "gosec.tool_error"


def test_gosec_parses_issues_when_it_actually_read_the_tree(tmp_path, monkeypatch):
    payload = {
        "Golang errors": {},
        "Issues": [
            {
                "severity": "HIGH",
                "confidence": "HIGH",
                "cwe": {"id": "78", "url": "https://cwe.mitre.org/data/definitions/78.html"},
                "rule_id": "G204",
                "details": "Subprocess launched with a potential tainted input",
                "file": "/repo/main.go",
                "code": 'exec.Command("sh", "-c", userInput)',
                "line": "12",
                "column": "42",
            }
        ],
        "Stats": {"files": 3, "lines": 90, "found": 1},
    }
    scanner = _configured(GosecScanner(), "gosec")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload), code=1))

    findings = scanner.scan(tmp_path, Config()).findings

    assert len(findings) == 1
    assert findings[0].rule_id == "G204"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].line_start == 12
    assert "CWE-78" in findings[0].message
    assert findings[0].file_path == Path("/repo/main.go")


def test_gosec_reads_a_line_span(tmp_path, monkeypatch):
    """gosec writes a multi-line finding as the string "12-14"."""
    payload = {
        "Golang errors": {},
        "Issues": [{"rule_id": "G401", "details": "weak", "file": "a.go", "line": "12-14"}],
        "Stats": {"files": 1, "found": 1},
    }
    scanner = _configured(GosecScanner(), "gosec")
    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(json.dumps(payload), code=1))

    finding = scanner.scan(tmp_path, Config()).findings[0]

    assert (finding.line_start, finding.line_end) == (12, 14)


def test_gosec_passes_no_fail_so_findings_do_not_read_as_a_crash(tmp_path, monkeypatch):
    seen: list[list[str]] = []

    def fake_exec(args, **kwargs):
        seen.append(list(args))
        return _proc(json.dumps({"Issues": [], "Stats": {"files": 1}}))

    scanner = _configured(GosecScanner(), "gosec")
    monkeypatch.setattr(scanner, "_exec", fake_exec)
    scanner.scan(tmp_path, Config())

    assert "-no-fail" in seen[0]
    assert any(a.endswith("/...") for a in seen[0])


def test_gosec_reports_timeout_and_unparseable_output(tmp_path, monkeypatch):
    scanner = _configured(GosecScanner(), "gosec")

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stderr="slow", code=124))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "gosec.tool_timeout"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout="<html>"))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "gosec.tool_error"

    monkeypatch.setattr(scanner, "_exec", lambda *a, **k: _proc(stdout=""))
    assert scanner.scan(tmp_path, Config()).findings[0].rule_id == "gosec.tool_error"
