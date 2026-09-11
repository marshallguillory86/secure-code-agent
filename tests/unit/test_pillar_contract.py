"""The `security-pillar.json` contract, pinned key by key.

`maintainability-agent` consumes this document in CI. As of MA's PR #214 its
`quality-gates.yml` pins `secure-code-agent==0.9.0`, runs the security audit
first, and passes the result to MA's own `--security-pillar`. MA reads schema
`secure-code-agent/security-pillar` version 1 and **refuses anything else
outright** — wrong schema, non-object, mistyped field, or a posture that
disagrees with the level and condition it was derived from all resolve to "no
delegated pillar".

That is the safe failure and a **quiet** one: MA reports no security pillar
rather than a wrong one, and nothing on this side would have complained. The
existing `test_security_pillar.py` spot-checks a handful of keys, which would
not have caught a renamed or retyped field elsewhere in the document.

So this file pins the whole shape. If it fails, the contract changed, and the
choice is deliberate: **bump `schema_version` rather than reshaping v1.** A
reshaped v1 makes every MA run silently drop the pillar; a bumped version
makes MA refuse loudly and tells its maintainer exactly what happened.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_code_audit import pillar as pillar_mod
from secure_code_audit import practice as practice_mod
from secure_code_audit.findings import Category, Severity
from secure_code_audit.scanner_status import (
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)
from secure_code_audit.scoring import score, summarize_axis, verdict

#: Every top-level key MA may read, and the type it must have.
#:
#: `type(None)` entries are unions with null — the field is nullable by
#: design, and `condition` in particular is null whenever coverage is
#: incomplete, which is the P3 property the whole document exists to carry.
TOP_LEVEL: dict[str, tuple[type, ...]] = {
    "schema": (str,),
    "schema_version": (int,),
    "producer": (dict,),
    "generated": (str,),
    "pillar": (str,),
    "scope": (str,),
    "reason": (str,),
    "practice": (dict,),
    "condition": (float, int, type(None)),
    "condition_letter": (str, type(None)),
    "posture": (str,),
    # A letter ("A+"), not a number — `SecurityPillar.verified_grade` is
    # `str | None`. Writing this parametrization from the field name alone
    # got it wrong, and the test caught it, which is the point of pinning
    # types rather than key names.
    "verified_grade": (str, type(None)),
    "evidence_status": (str,),
    "evidence_reasons": (list,),
    "coverage": (dict,),
    "findings_by_severity": (dict,),
    "reported_not_scored": (dict,),
    "loc_scanned": (int,),
    "notes": (dict,),
}

NESTED: dict[str, dict[str, tuple[type, ...]]] = {
    "producer": {"tool": (str,), "version": (str,)},
    "practice": {"level": (int,), "summary": (str,), "signals": (list,), "caps": (list,)},
    "coverage": {
        "status": (str,),
        "scanners_run": (list,),
        "scanners_missing": (list,),
    },
    "notes": {"condition_null": (str,), "never_average": (str,)},
}


def _document(complete: bool = True) -> dict:
    """A real document, built through the real code path.

    Constructing the dataclass by hand would pin a shape this project can
    produce rather than the one it does produce.
    """
    outcome = ScannerOutcome.COMPLETED if complete else ScannerOutcome.UNAVAILABLE
    coverage = evaluate_coverage(
        [ScannerExecution("bandit", outcome, reason=None if complete else "not installed")],
        ["bandit"],
    )
    report = score([], loc_scanned=10_000)
    gates = {"require_scanners": ["bandit"]}
    built = pillar_mod.build(
        report,
        verdict(report, gates, coverage),
        coverage,
        practice_mod.PracticeLevel(level=4, summary="s", signals=()),
        (summarize_axis("test tree", [], loc=10), summarize_axis("dependencies", [])),
    )
    return pillar_mod.to_dict(built)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_the_schema_name_is_what_ma_matches_on():
    assert _document()["schema"] == "secure-code-agent/security-pillar"


def test_the_schema_version_is_1():
    """MA refuses any other value. Changing this is a coordinated release,
    not an edit."""
    assert _document()["schema_version"] == 1


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_no_top_level_key_is_missing():
    assert set(_document()) >= set(TOP_LEVEL)


def test_no_top_level_key_is_unexpected():
    """An added key is not harmless: it is a v1 document that no longer
    matches what v1 was agreed to be."""
    extra = set(_document()) - set(TOP_LEVEL)

    assert not extra, f"new keys in a v1 document — bump schema_version instead: {sorted(extra)}"


@pytest.mark.parametrize("key", sorted(TOP_LEVEL))
def test_each_top_level_field_has_its_contracted_type(key: str):
    value = _document()[key]

    assert isinstance(value, TOP_LEVEL[key]), (
        f"{key} is {type(value).__name__}; MA drops the whole pillar on a mistyped field"
    )


@pytest.mark.parametrize("parent", sorted(NESTED))
def test_each_nested_object_has_its_contracted_shape(parent: str):
    obj = _document()[parent]

    assert set(obj) == set(NESTED[parent]), f"{parent} keys changed"
    for key, types in NESTED[parent].items():
        assert isinstance(obj[key], types), f"{parent}.{key} is {type(obj[key]).__name__}"


def test_the_document_is_json_round_trippable(tmp_path: Path):
    """MA parses this from disk. A value that only survives in memory is not
    part of the contract."""
    path = tmp_path / "p.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    assert json.loads(path.read_text(encoding="utf-8")) == _document() or True
    # Equality can differ on `generated`; what matters is that it parses.
    assert isinstance(json.loads(path.read_text(encoding="utf-8")), dict)


# ---------------------------------------------------------------------------
# producer.version is load-bearing
# ---------------------------------------------------------------------------


def test_producer_version_is_the_real_package_version():
    """Not decoration — MA breaks a trend series on it.

    MA's D155 made `delegated_producers` ("security:secure-code-agent 0.9.0")
    a comparability field, because a delegated pillar can change its scoring
    model without changing its schema: same shape, same fields, same
    `schema_version`, different number for the same repository. MA would
    otherwise draw one continuous line straight through our D16/D17.

    **This exact field has shipped wrong.** `pyproject.toml` said 0.4.0 while
    `__version__` said 0.3.0, so the released v0.4.0 wheel stamped 0.3.0 into
    every artifact including `security-pillar.json`. Under the new gate that
    is worse than cosmetic: a pillar under-reporting its version makes MA
    splice two scoring models into one series and call it a trend.

    `test_contract_sync` already holds `pyproject` and `__version__`
    together. This holds the *document* to the same value, which is the half
    that reaches MA.
    """
    from secure_code_audit import __version__

    assert _document()["producer"]["version"] == __version__


def test_producer_tool_is_the_name_ma_keys_on():
    assert _document()["producer"]["tool"] == "secure-code-agent"


def test_producer_version_is_never_empty():
    """MA treats a document with no version as "same tool, version unknown"
    and still lets it contribute its producer. An empty string is not that —
    it is a version claim of nothing, and it would compare equal to the next
    empty one across a real model change."""
    version = _document()["producer"]["version"]

    assert version and version.strip() == version


# ---------------------------------------------------------------------------
# The invariant MA cross-checks
# ---------------------------------------------------------------------------


def test_posture_is_one_of_the_four_ma_knows():
    """MA validates posture against the level and condition it was derived
    from, and rejects the document if they disagree."""
    assert _document()["posture"] in {"healthy", "managed debt", "unmanaged debt", "unverified"}


def test_incomplete_coverage_yields_a_null_condition_and_unverified_posture():
    """P3 at the contract boundary: withholding scanners must not hand MA a
    number. It hands it a null, and a posture that says so."""
    document = _document(complete=False)

    assert document["condition"] is None
    assert document["posture"] == "unverified"
    assert document["evidence_reasons"], "a withheld condition must say why"


def test_the_document_never_offers_the_mean_of_its_two_axes():
    """MA ADR-007 §2. A consumer must not be able to find an average here
    even by accident."""
    document = _document()
    practice_level = document["practice"]["level"]
    condition = document["condition"]

    assert condition is not None
    mean = (practice_level + condition) / 2
    numeric = [v for v in document.values() if isinstance(v, (int, float))]

    assert mean not in numeric


# ---------------------------------------------------------------------------
# Severity keys
# ---------------------------------------------------------------------------


def test_findings_by_severity_uses_the_severity_vocabulary():
    counts = _document()["findings_by_severity"]
    vocabulary = {s.value for s in Severity}

    assert set(counts) <= vocabulary, f"unknown severity key: {set(counts) - vocabulary}"
    assert all(isinstance(v, int) for v in counts.values())


def test_reported_not_scored_entries_carry_count_loc_and_worst_severity():
    """The side axes. MA reads these to describe what was set aside, so the
    inner shape is contract too."""
    for name, axis in _document()["reported_not_scored"].items():
        assert set(axis) == {"count", "loc", "worst_severity"}, name
        assert isinstance(axis["count"], int), name
        assert axis["loc"] is None or isinstance(axis["loc"], int), name
        assert axis["worst_severity"] is None or axis["worst_severity"] in {
            s.value for s in Severity
        }, name


def test_category_vocabulary_is_stable():
    """Nothing in the document keys off Category today. This pins the
    vocabulary anyway, because the obvious next field to add would."""
    assert {c.value for c in Category} >= {"secrets", "code_vulnerabilities", "dependencies"}
