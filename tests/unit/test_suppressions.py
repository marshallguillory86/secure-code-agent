"""Suppressions loader + apply + expired-rule findings."""

import datetime
import subprocess
import sys
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import SEVERITY_WEIGHT
from secure_code_audit.suppressions import (
    apply,
    expired_findings,
    load,
    unused_findings,
)


def _f(rule_id="B608", file_path=Path("a.py")):
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint="x",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line_start=1,
        line_end=None,
        code_snippet=None,
        message="m",
    )


def _write(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def test_missing_file_yields_no_rules(tmp_path):
    rules, errors = load(tmp_path / "missing.yaml")
    assert rules == []
    assert errors == []


def test_reason_required(tmp_path):
    p = tmp_path / ".scignore.yaml"
    _write(p, "- rule_id: B608\n  expires: '2099-01-01'\n  reason: ''\n")
    _, errors = load(p)
    assert errors
    assert any("reason" in e for e in errors)


def test_expires_required(tmp_path):
    p = tmp_path / ".scignore.yaml"
    _write(p, "- rule_id: B608\n  reason: 'r'\n")
    _, errors = load(p)
    assert errors
    assert any("expires" in e for e in errors)


def test_max_ttl_enforced(tmp_path):
    far = (datetime.date.today() + datetime.timedelta(days=400)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'r'\n  expires: '{far}'\n")
    _, errors = load(p)
    assert errors
    assert any("days" in e for e in errors)


def test_wildcard_requires_file_or_paths(tmp_path):
    """An unscoped `rule_id: '*'` suppresses the entire audit.

    This test used to expire in 2099, so the loader rejected it for
    exceeding the maximum TTL and never reached the wildcard check at all —
    and the assertion looked for "file" or "paths" *anywhere* in the error,
    which the TTL message satisfied via the tmp_path in its prefix. It
    passed against an unguarded wildcard. The expiry below is inside the TTL
    so the entry gets as far as the rule it is about, and the error is
    matched by its own words.
    """
    near = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: '*'\n  reason: 'too broad'\n  expires: '{near}'\n")

    rules, errors = load(p)

    assert rules == []
    assert any("requires `file` or `paths`" in e for e in errors), errors


def test_apply_suppresses_matching_rule(tmp_path):
    near = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'known'\n  expires: '{near}'\n")
    rules, errors = load(p)
    assert not errors
    out = apply([_f()], rules)
    assert out[0].suppressed is True
    assert "known" in out[0].suppression_note


def test_apply_does_not_suppress_expired(tmp_path):
    past = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'stale'\n  expires: '{past}'\n")
    rules, _ = load(p)
    out = apply([_f()], rules)
    assert out[0].suppressed is False


def test_expired_findings_emit_critical(tmp_path):
    past = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'shipped late'\n  expires: '{past}'\n")
    rules, _ = load(p)
    expired = expired_findings(rules, p)
    assert len(expired) == 1
    assert expired[0].severity is Severity.CRITICAL


def test_a_present_but_unloadable_suppression_file_fails_the_run(tmp_path, capsys):
    """An unusable suppression file must stop the run, not warn and continue.

    A suppression file that exists is an explicit instruction. Ignoring it
    silently changes which findings are reported, and "my suppressions
    applied" then looks identical to "my suppressions were skipped". This
    happened for real: PyYAML was missing, so an entire .scignore.yaml was
    a no-op while the run exited 0 and reported the suppressed finding as
    live. The warning was on stderr and scrolled past unread.
    """
    from secure_code_audit.cli import main

    # A git repo, because suppressions resolve against the repository root
    # rather than the scan target.
    subprocess.run(["git", "init", "-q", "."], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / ".scignore.yaml").write_text("not: valid: yaml: [\n", encoding="utf-8")

    code = main([str(tmp_path), "--json-output", str(tmp_path / "out.json")])

    assert code == 1
    assert "could not be applied" in capsys.readouterr().err


def test_no_suppression_file_is_not_an_error(tmp_path):
    """Repositories that use no suppressions are unaffected by the above."""
    from secure_code_audit.cli import main

    subprocess.run(["git", "init", "-q", "."], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    assert main([str(tmp_path), "--json-output", str(tmp_path / "out.json")]) == 0


# --- identity at the real scanner boundary -----------------------------------------


def _gitleaks_findings(*lines: int):
    """Findings built by the production gitleaks adapter, not hand-made fingerprints.

    The previous version of these tests invented fingerprints and asserted against them, which
    proved the matcher worked on values that could never occur. It missed that the adapter
    produces IDENTICAL fingerprints for different secrets: make_fingerprint excludes the line so
    reformatting cannot break baseline identity, and gitleaks reports REDACTED evidence.
    """
    from pathlib import Path

    from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner

    scanner = GitleaksScanner.__new__(GitleaksScanner)
    hits = [
        {
            "RuleID": "generic-api-key",
            "File": "api/tests/x.py",
            "StartLine": n,
            "Match": "key = REDACTED",
            "Description": "Generic API Key",
        }
        for n in lines
    ]
    return scanner._parse(hits, Path("."))


def test_two_distinct_secrets_share_a_fingerprint_at_the_real_boundary():
    """Pins the property that makes `fingerprint` alone insufficient. If this ever stops being
    true, the guidance in the schema docs needs revisiting — it is not a bug, it is why `line`
    exists."""
    first, second = _gitleaks_findings(18, 999)
    assert first.fingerprint == second.fingerprint
    assert first.line_start != second.line_start


def test_a_fingerprint_and_line_pinned_entry_suppresses_only_its_own_finding():
    import datetime

    from secure_code_audit.suppressions import SuppressionRule

    first, second = _gitleaks_findings(18, 999)
    rule = SuppressionRule(
        rule_id="gitleaks.generic-api-key",
        reason="deliberate test canary",
        expires=datetime.date(2099, 1, 1),
        file="api/tests/x.py",
        fingerprint=first.fingerprint,
        line=18,
    )
    assert rule.matches(first) is True
    assert rule.matches(second) is False


def test_a_fingerprint_only_entry_still_covers_a_second_secret():
    """Honest about the residual: without `line`, the collision above means a second secret in
    the same file is still suppressed. Documented so the narrow form is chosen knowingly."""
    import datetime

    from secure_code_audit.suppressions import SuppressionRule

    first, second = _gitleaks_findings(18, 999)
    rule = SuppressionRule(
        rule_id="gitleaks.generic-api-key",
        reason="r",
        expires=datetime.date(2099, 1, 1),
        file="api/tests/x.py",
        fingerprint=first.fingerprint,
    )
    assert rule.matches(second) is True


# --- malformed configuration must fail closed --------------------------------------


def _load_entry(tmp_path, extra: str):
    from secure_code_audit.suppressions import load

    path = tmp_path / "s.yaml"
    path.write_text(
        "- file: a/b.py\n"
        "  rule_id: gitleaks.generic-api-key\n"
        "  reason: r\n"
        "  expires: 2027-01-01\n"
        f"  {extra}\n",
        encoding="utf-8",
    )
    return load(path)


@pytest.mark.parametrize(
    "extra",
    [
        'fingerprint: ""',  # empty
        "fingerprint: 0",  # not 16 hex
        "fingerprint: NOTHEXNOTHEX",  # wrong alphabet
        "fingerpint: 0aaa689f8a967d8c",  # typo — previously ignored, silently widening the entry
        'line: "abc"',  # wrong type
        "line: 0",  # not a real line
        "line: true",  # bool is not an int here
        "unexpected: value",  # unknown field
    ],
)
def test_malformed_or_unknown_fields_are_rejected_not_ignored(tmp_path, extra):
    rules, errors = _load_entry(tmp_path, extra)
    assert rules == [], f"{extra!r} produced a usable rule"
    assert errors, f"{extra!r} was silently accepted"


def test_a_well_formed_narrow_entry_loads(tmp_path):
    rules, errors = _load_entry(tmp_path, "fingerprint: 0aaa689f8a967d8c\n  line: 18")
    assert errors == []
    assert rules[0].fingerprint == "0aaa689f8a967d8c" and rules[0].line == 18


# ---------------------------------------------------------------------------
# Malformed at the document level, and in the required fields
# ---------------------------------------------------------------------------
#
# The loader returns `(rules, errors)` and `cli._do_audit` refuses to report
# when `errors` is non-empty. So a shape that produces neither a rule nor an
# error is the dangerous one: the file reads as applied, the entries silently
# do nothing, and the findings the operator reviewed come back as live
# criticals. Each case below is a document the loader has to *name*.


@pytest.mark.parametrize(
    "document, message",
    [
        # A single entry written without the leading `-`. YAML parses it
        # happily as a mapping, which is the easy version of this mistake.
        ("rule_id: B608\nreason: r\nexpires: 2099-01-01\n", "top-level must be a list"),
        ("- just a string\n", "must be a mapping"),
        ("- reason: r\n  expires: 2027-01-01\n", "'rule_id' is required"),
        # Matches YYYY-MM-DD, and is not a date. Without the second check the
        # regex is the whole validation and February gets 30 days.
        ("- rule_id: B608\n  reason: r\n  expires: '2027-02-30'\n", "not parseable"),
    ],
)
def test_a_malformed_document_is_named_rather_than_skipped(tmp_path, document, message):
    path = tmp_path / ".scignore.yaml"
    _write(path, document)

    rules, errors = load(path)

    assert rules == []
    assert any(message in e for e in errors), errors


def test_an_unquoted_impossible_date_is_reported_by_the_loader_not_raised(tmp_path):
    """PRODUCT BUG — the loader lets a bare ValueError out of `load`.

    `expires: 2027-02-30` unquoted is a YAML *timestamp*, and PyYAML's
    `construct_yaml_timestamp` raises a plain `ValueError` ("day is out of
    range for month"). That is not a `yaml.YAMLError`, so the `except
    yaml.YAMLError` around `safe_load` does not catch it and the exception
    leaves `load`, which documents itself as returning
    `(rules, validation_errors)`.

    Through the CLI `main`'s blanket `except ValueError` turns it into
    `ERROR: day is out of range for month` — no file, no entry number, and
    none of the fail-closed wording the suppression path uses for every
    other malformed entry. The quoted spelling of the same mistake is
    reported properly, so which of two identical typos an operator can
    diagnose depends on whether they used quotes.

    Left failing deliberately: the fix belongs in `suppressions.load`
    (catch `ValueError` alongside `yaml.YAMLError`), which is product code.
    """
    path = tmp_path / ".scignore.yaml"
    _write(path, "- rule_id: B608\n  reason: r\n  expires: 2027-02-30\n")

    rules, errors = load(path)

    assert rules == []
    assert any(str(path) in e for e in errors), errors


def test_a_suppression_file_without_pyyaml_is_an_error_not_an_empty_ruleset(tmp_path, monkeypatch):
    """The original incident, at the loader.

    PyYAML was missing, `load` swallowed the ImportError, and an entire
    `.scignore.yaml` became a no-op while the run still exited 0 and
    reported every suppressed finding as live. Returning no rules *and* no
    errors is what made that silent, so the error is the thing under test.
    """
    monkeypatch.setitem(sys.modules, "yaml", None)
    path = tmp_path / ".scignore.yaml"
    _write(path, "- rule_id: B608\n  reason: r\n  expires: 2027-01-01\n")

    rules, errors = load(path)

    assert rules == []
    assert any("pyyaml not installed" in e for e in errors), errors


def _rule(tmp_path, body: str):
    """One loaded rule, asserting the fixture itself is valid."""
    path = tmp_path / ".scignore.yaml"
    _write(path, body)
    rules, errors = load(path)
    assert errors == [], errors
    assert len(rules) == 1
    return path, rules


def test_a_suppression_that_matches_nothing_is_reported(tmp_path):
    """A suppression whose subject is gone reads as protection and protects nothing.

    This is the half `test_no_suppression_path_matches_nothing.py` cannot
    reach. That lint catches a glob whose *file* is gone; it passed against
    the real incident, where `scanners/base.py` still existed and the
    subprocess code had moved out of it to two new modules. The `B404` and
    `B603` entries still named `base.py`, matched a real tracked file, and
    covered nothing — four reviewed findings came back as new work while
    the entries meant to cover them sat there looking active.

    Only a run that has the findings in hand can answer this, which is why
    it belongs here and not in a lint over the file.
    """
    path, rules = _rule(
        tmp_path,
        "- rule_id: B999\n  reason: covers a scanner we no longer run\n  expires: 2026-12-01\n",
    )

    found = unused_findings(rules, [_f(rule_id="B608")], path)

    assert len(found) == 1
    assert "B999" in found[0].message
    assert found[0].rule_id == "suppressions.unused.B999"


def test_a_suppression_that_still_matches_is_not_reported(tmp_path):
    """The falsifier. Reporting every rule would make the check noise.

    A suppression doing its job is the normal case, and a check that fires
    on it would be turned off within a week.
    """
    path, rules = _rule(
        tmp_path,
        "- rule_id: B608\n  reason: parameterized elsewhere\n  expires: 2026-12-01\n",
    )

    assert unused_findings(rules, [_f(rule_id="B608")], path) == []


def test_an_expired_suppression_is_not_also_reported_as_unused(tmp_path):
    """One entry must not produce two findings about itself.

    An expired rule does not suppress — `apply` skips it — so it matches
    nothing in practice and would otherwise be reported twice: once as
    expired, which is CRITICAL and actionable, and once as unused, which
    would be wrong. Expiry is the more specific statement, so it wins.
    """
    path, rules = _rule(
        tmp_path,
        "- rule_id: B608\n  reason: ran out of time\n  expires: 2020-01-01\n",
    )

    assert rules[0].expired
    assert expired_findings(rules, path) != []
    assert unused_findings(rules, [_f(rule_id="B608")], path) == []


def test_an_unused_suppression_cannot_move_the_score(tmp_path):
    """INFORMATIONAL carries weight 0.0, and that is load-bearing here.

    Tidiness must not change a grade. A repository with stale suppressions
    is not more vulnerable for having them, and a finding that moved the
    number would make this check something operators suppress in turn.
    """
    path, rules = _rule(
        tmp_path,
        "- rule_id: B999\n  reason: stale\n  expires: 2026-12-01\n",
    )

    found = unused_findings(rules, [], path)

    assert found[0].severity is Severity.INFORMATIONAL
    assert SEVERITY_WEIGHT[found[0].severity] == 0.0
    assert found[0].category is Category.POLICY_DOCS


def test_no_findings_at_all_still_reports_every_rule_as_unused(tmp_path):
    """A clean tree does not excuse a suppression from having a subject.

    Zero findings is the case where every suppression is unused, and the
    tempting shortcut — treat an empty finding list as "nothing to say" —
    would hide exactly the repository that has fixed everything and never
    cleaned up its .scignore.yaml.
    """
    path, rules = _rule(
        tmp_path,
        "- rule_id: B608\n  reason: parameterized elsewhere\n  expires: 2026-12-01\n",
    )

    assert len(unused_findings(rules, [], path)) == 1
