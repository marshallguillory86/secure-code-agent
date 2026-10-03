"""The standards table is data now, so a bad edit must fail loudly.

The mapping was 416 lines of Python, which meant it could only be wrong in
the ways Python rejects at import. As `data/standards.yaml` it is something
an operator edits, so every way a row can be malformed needs a message that
names the file, the row and the rule.

The failure direction is what makes this worth testing properly. A loader
that skipped a malformed row would report that rule's findings as
*unmapped* — no CWE, no OWASP category, no fix hint, and no Top-25 weight —
which is indistinguishable from a rule nobody has curated yet. The score
would move and nothing would say why. So the loader raises, and the audit
fails closed, rather than quietly producing a thinner table.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Severity
from secure_code_audit.standards import (  # noqa: I001
    _DATA_FILE,
    _MAP,
    OWASP_TOP10_2021_URL,
    _load_table,
    lookup,
    owasp_url,
)

_GOOD_ROW = """version: 1
entries:
  - scanner: bandit
    rule_id: B000
    canonical_cwe: CWE-89
    owasp_top10: A03
    asvs_section: V5.3.4
    nist_ssdf: PW.5.1
    category: code_vulnerabilities
    severity: high
    confidence: high
    short_desc: A thing.
    fix_hint: Do the other thing.
"""


def _table(tmp_path: Path, text: str):
    path = tmp_path / "standards.yaml"
    path.write_text(text, encoding="utf-8")
    return _load_table(path)


def test_a_well_formed_row_loads(tmp_path):
    """The falsifier.

    Every other test here asserts a refusal, and a loader that raised on
    everything would satisfy all of them. This asserts it accepts the exact
    shape they are each one deviation from, and that the values arrive as
    enums rather than the strings the file holds.
    """
    table = _table(tmp_path, _GOOD_ROW)

    assert list(table) == [("bandit", "B000")]
    entry = table[("bandit", "B000")]
    assert entry.canonical_cwe == "CWE-89"
    assert entry.category is Category.CODE_VULNERABILITIES
    assert entry.severity is Severity.HIGH
    assert entry.confidence is Confidence.HIGH
    assert entry.fix_hint == "Do the other thing."


def test_the_shipped_table_is_the_one_the_code_expects():
    """Guards the data file against an edit that drops or rewrites a rule.

    B102 is the entry with the most history behind it: Bandit files `exec()`
    under CWE-78, which is *OS* command injection, and that mislabel reached
    the OWASP mapping, SARIF, the work order and the Top-25 bonus before
    corroboration caught it. If a data edit ever reverts it, this says so.
    """
    entry = lookup("bandit", "B102")

    assert entry is not None
    assert entry.canonical_cwe == "CWE-95"
    assert entry.owasp_top10 == "A03"
    assert entry.category is Category.CODE_VULNERABILITIES
    assert entry.severity is Severity.HIGH
    assert entry.confidence is Confidence.MEDIUM


def test_the_shipped_table_is_not_suspiciously_small():
    """A loader bug that returned a few rows would pass every lookup test
    that happened to name a surviving rule."""
    assert len(_MAP) >= 30, f"the shipped table has only {len(_MAP)} entries"
    assert _DATA_FILE.is_file()


def test_a_row_that_is_not_a_mapping_is_refused(tmp_path):
    """A list item that is a bare string names the row, not just the file."""
    with pytest.raises(ValueError, match="entry #0: must be a mapping"):
        _table(tmp_path, "version: 1\nentries:\n  - just a string\n")


def test_a_row_without_a_scanner_or_rule_id_is_refused(tmp_path):
    """Both halves of the key are required; one alone indexes nothing."""
    with pytest.raises(ValueError, match="'scanner' and 'rule_id' are both required"):
        _table(tmp_path, "version: 1\nentries:\n  - canonical_cwe: CWE-89\n")


def test_an_unknown_field_is_refused_and_named(tmp_path):
    """Prevents a typo silently downgrading a curated rule to an unmapped one.

    `cannonical_cwe` is a plausible misspelling. Ignored, it would leave the
    rule with no CWE — so no OWASP category, no Top-25 weight — while the
    file still read as though the rule were curated.
    """
    text = _GOOD_ROW.replace("canonical_cwe: CWE-89", "cannonical_cwe: CWE-89")
    with pytest.raises(ValueError, match="cannonical_cwe"):
        _table(tmp_path, text)


def test_a_missing_short_desc_is_refused(tmp_path):
    """It is the only prose a reader gets for a rule in some outputs."""
    text = _GOOD_ROW.replace("    short_desc: A thing.\n", "")
    with pytest.raises(ValueError, match="'short_desc' is required"):
        _table(tmp_path, text)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("category", "not_a_category"),
        ("severity", "extremely_high"),
        ("confidence", "probably"),
    ],
)
def test_an_invalid_enum_value_is_refused_and_names_the_rule(tmp_path, field, bad):
    """These three are the scoring inputs, so a wrong one moves the grade.

    The message has to name the rule, because an operator editing a 400-line
    table needs to know which row to look at.
    """
    current = {"category": "code_vulnerabilities", "severity": "high", "confidence": "high"}[field]
    text = _GOOD_ROW.replace(f"{field}: {current}", f"{field}: {bad}")
    with pytest.raises(ValueError, match="bandit/B000"):
        _table(tmp_path, text)


def test_a_duplicate_rule_is_refused(tmp_path):
    """Two rows for one rule means one is ignored, and which depends on order.

    Silently taking the last would make the table's meaning a function of
    where in the file somebody pasted their entry.
    """
    doubled = _GOOD_ROW + _GOOD_ROW.split("entries:\n", 1)[1]

    with pytest.raises(ValueError, match="duplicate rule bandit/B000"):
        _table(tmp_path, doubled)


def test_entries_must_be_a_list(tmp_path):
    """A mapping under `entries:` is the shape someone reaches for first."""
    with pytest.raises(ValueError, match="'entries' must be a list"):
        _table(tmp_path, "version: 1\nentries:\n  bandit: {}\n")


def test_an_empty_document_yields_an_empty_table(tmp_path):
    """Not an error at this layer.

    An empty table is a legitimate state for an *overlay*, which shares this
    loader. The shipped file being empty is caught by the size test above
    rather than by refusing emptiness here, which would make an overlay that
    an operator has not filled in yet a hard failure.
    """
    assert _table(tmp_path, "version: 1\nentries: []\n") == {}


def test_owasp_url_deep_links_a_known_bucket():
    """A reader following a standards citation should land on the category.

    Uncovered until the table moved out of this module: 400 statements of
    dict literal diluted the file's coverage enough to hide six untested
    lines. Removing them is what made the gap visible.
    """
    url = owasp_url("A03")

    assert url.startswith(OWASP_TOP10_2021_URL)
    assert url.endswith("/")
    assert "A03_2021-Injection" in url
    assert owasp_url("A03:2021-Injection") == url, "the long form must resolve the same"


def test_owasp_url_falls_back_to_the_index_for_an_unknown_bucket():
    """Legacy 2017 ids and anything unmapped must not produce a dead link.

    A fabricated deep link is worse than the index: it looks authoritative
    and 404s, which is the kind of thing a reader blames the finding for.
    """
    assert owasp_url("A11") == OWASP_TOP10_2021_URL
    assert owasp_url("not-a-bucket") == OWASP_TOP10_2021_URL
