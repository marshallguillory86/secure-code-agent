from pathlib import Path

from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
    severity_at_or_above,
)


def test_severity_from_string_aliases():
    assert Severity.from_string("HIGH") is Severity.HIGH
    assert Severity.from_string("error") is Severity.HIGH
    assert Severity.from_string("warning") is Severity.MEDIUM
    assert Severity.from_string("moderate") is Severity.MEDIUM
    assert Severity.from_string("note") is Severity.LOW
    assert Severity.from_string("info") is Severity.INFORMATIONAL
    assert Severity.from_string("nonsense") is Severity.INFORMATIONAL


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFORMATIONAL.rank


def test_severity_at_or_above_inclusive():
    assert severity_at_or_above(Severity.MEDIUM) == {
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    }


def test_confidence_parses_loose():
    assert Confidence.from_string("HIGH") is Confidence.HIGH
    assert Confidence.from_string("med") is Confidence.MEDIUM
    assert Confidence.from_string("") is Confidence.MEDIUM   # default


def test_fingerprint_stable_under_whitespace_drift():
    a = Finding.make_fingerprint(
        canonical_cwe="CWE-89",
        rule_id="B608",
        file_path=Path("dashboard/api.py"),
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
    )
    b = Finding.make_fingerprint(
        canonical_cwe="CWE-89",
        rule_id="B608",
        file_path=Path("dashboard/api.py"),
        # extra whitespace — normalized away
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {uid}')    \n",
    )
    assert a == b


def test_fingerprint_differs_across_files():
    a = Finding.make_fingerprint(
        canonical_cwe="CWE-89", rule_id="B608",
        file_path=Path("a.py"), code_snippet="x",
    )
    b = Finding.make_fingerprint(
        canonical_cwe="CWE-89", rule_id="B608",
        file_path=Path("b.py"), code_snippet="x",
    )
    assert a != b


def test_fingerprint_falls_back_to_rule_id_when_no_cwe():
    a = Finding.make_fingerprint(
        canonical_cwe=None, rule_id="custom.rule",
        file_path=Path("a.py"), code_snippet="x",
    )
    b = Finding.make_fingerprint(
        canonical_cwe=None, rule_id="custom.rule",
        file_path=Path("a.py"), code_snippet="x",
    )
    assert a == b


def test_category_enum_round_trip():
    for cat in Category:
        assert Category(cat.value) is cat
