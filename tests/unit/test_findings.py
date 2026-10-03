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
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    }


def test_confidence_parses_loose():
    assert Confidence.from_string("HIGH") is Confidence.HIGH
    assert Confidence.from_string("med") is Confidence.MEDIUM
    assert Confidence.from_string("") is Confidence.MEDIUM  # default


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
        canonical_cwe="CWE-89",
        rule_id="B608",
        file_path=Path("a.py"),
        code_snippet="x",
    )
    b = Finding.make_fingerprint(
        canonical_cwe="CWE-89",
        rule_id="B608",
        file_path=Path("b.py"),
        code_snippet="x",
    )
    assert a != b


def test_fingerprint_falls_back_to_rule_id_when_no_cwe():
    a = Finding.make_fingerprint(
        canonical_cwe=None,
        rule_id="custom.rule",
        file_path=Path("a.py"),
        code_snippet="x",
    )
    b = Finding.make_fingerprint(
        canonical_cwe=None,
        rule_id="custom.rule",
        file_path=Path("a.py"),
        code_snippet="x",
    )
    assert a == b


def test_category_enum_round_trip():
    for cat in Category:
        assert Category(cat.value) is cat


def test_the_fingerprint_matches_what_suppressions_accept():
    """The 16-character slice is a contract with operators, not a detail.

    A `silent-truncation` risk rule matches the hex-digest slice in
    `make_fingerprint`, and the decision recorded there is that it stays.
    This is what makes that decision enforced rather than merely written
    down. The slice is described rather than quoted, because quoting it
    here reproduced the finding in the test file — which is the third time
    in this session that spelling out a matched pattern in prose created a
    second copy of it.

    `suppressions._VALID_FINGERPRINT` validates an operator's
    `fingerprint:` entry as exactly 16 hex characters; the loader's error
    message, `README.md` and `docs/design.md` all state it. So widening or
    narrowing the slice would not be a refactor — it would silently stop
    every pinned suppression and every committed baseline from matching,
    and a `fingerprint:` entry is the narrowest and most deliberate
    suppression an operator can write.

    A falsifier, not a red test: the property already held. It exists so
    that changing the slice fails here, beside the reasoning, instead of
    failing in an operator's next audit.
    """
    from secure_code_audit.suppressions import _VALID_FINGERPRINT

    fingerprint = Finding.make_fingerprint(
        canonical_cwe="CWE-89",
        rule_id="B608",
        file_path=Path("src/app.py"),
        code_snippet="query = f'SELECT {x}'",
    )

    # The pattern is `[0-9a-f]{16}`, so this single assertion already carries
    # the length, the alphabet and the case. A separate `== .lower()` check
    # sat here and was both redundant and shaped like a tautology, which
    # MA's `vacuous-assertion` rule said out loud.
    assert len(fingerprint) == 16, fingerprint
    assert _VALID_FINGERPRINT.fullmatch(fingerprint), (
        f"{fingerprint!r} is not what the suppression loader accepts; a pinned "
        "fingerprint: entry would no longer match the finding it names"
    )


def test_the_fingerprint_is_stable_for_the_same_finding():
    """Baseline identity depends on it being a function of its inputs alone.

    Not a tautology: `make_fingerprint` normalises the snippet, so two
    callers formatting the same line differently must agree. A fingerprint
    that moved with whitespace would make every reformat read as a new
    finding, and `fail_on_new` would fail the build for a reindent.
    """
    args = {"canonical_cwe": "CWE-89", "rule_id": "B608", "file_path": Path("src/app.py")}

    first = Finding.make_fingerprint(**args, code_snippet="query =  f'SELECT  {x}'")
    second = Finding.make_fingerprint(**args, code_snippet="query = f'SELECT {x}'")

    assert first == second
