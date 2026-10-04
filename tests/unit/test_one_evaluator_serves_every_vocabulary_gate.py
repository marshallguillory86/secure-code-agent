"""One evaluator for every gate that matches a finding against a vocabulary.

MA reported `_gate_fail_on_severity` and `_gate_fail_on_category` in
`scoring.py` as a near-duplicate pair at similarity 1.0 — fourteen lines
that differ only in a config key, an attribute name and a noun. Nothing is
wrong with either copy today; this is the drift that *would* be wrong, and
it is specific rather than aesthetic. Each copy independently:

- **lowercases the configured values**, which is what lets a config say
  `fail_on_severity: ["HIGH"]` and still gate. A copy that skipped it
  would accept the config, match nothing and pass the build — the worst
  failure a gate has, because it looks configured.
- **excludes suppressed findings**, which is what makes a suppression with
  a reason and an expiry mean anything. A copy that dropped it would fail
  builds on findings an operator had already dispositioned.

Both properties are invisible when they break: the gate does not error, it
just stops gating or starts over-gating. So the two gates now share one
evaluator and one table, and this is the lint that keeps the next
vocabulary gate from arriving as a third copy.

The structural check is tied to the schema rather than to a list written
here: a gate whose items carry an `enum` is by definition "match a finding
against this vocabulary", so the schema is what decides which gates the
table must serve. Adding `fail_on_confidence` to the schema and
hand-rolling its evaluator fails this file.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Severity
from secure_code_audit.scoring import _VOCABULARY_GATES, evaluate_gates, score

from .test_scoring import _f

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "secure-code-agent.schema.json"


def _schema_vocabulary_gates() -> dict[str, list[str]]:
    """Gate keys whose configured value is a list drawn from a fixed enum.

    `require_scanners` is an array too, but of scanner names rather than of
    finding attributes, and it is evaluated from the coverage report instead
    of by matching a finding — so it is not one of these.
    """
    gates = json.loads(SCHEMA.read_text(encoding="utf-8"))["properties"]["gates"]["properties"]
    return {
        name: spec["items"]["enum"]
        for name, spec in gates.items()
        if spec.get("type") == "array" and "enum" in spec.get("items", {})
    }


def test_the_schema_still_declares_vocabulary_gates():
    """Without this, every check below is vacuous on an empty mapping."""
    found = _schema_vocabulary_gates()

    assert set(found) == {"fail_on_severity", "fail_on_category"}, sorted(found)


def test_every_vocabulary_gate_in_the_schema_is_served_by_the_shared_table():
    """A third copy of the pair would leave its gate out of the table."""
    declared = {gate.name for gate in _VOCABULARY_GATES}

    assert declared == set(_schema_vocabulary_gates()), (
        f"table serves {sorted(declared)}, schema declares "
        f"{sorted(_schema_vocabulary_gates())}. A vocabulary gate missing from "
        "_VOCABULARY_GATES is one with its own hand-rolled evaluator, which is "
        "how the severity/category pair came to be duplicated."
    )


def test_each_table_entry_names_a_real_finding_attribute():
    """The table drives `getattr`, so a typo there would raise at gate time."""
    one = _f(Severity.HIGH, Category.SECRETS)

    for gate in _VOCABULARY_GATES:
        value = getattr(one, gate.attribute)
        assert hasattr(value, "value"), f"{gate.name} names {gate.attribute!r}, which has no .value"


def _config_value(gate, finding) -> list[str]:
    """What an operator would write to gate on this finding's own value."""
    return [getattr(finding, gate.attribute).value.upper()]


@pytest.mark.parametrize("gate", _VOCABULARY_GATES, ids=lambda g: g.name)
def test_a_vocabulary_gate_matches_the_config_case_insensitively(gate):
    """`["HIGH"]` must gate exactly as `["high"]` does.

    The schema's enum is lowercase, but an operator writing by hand is not,
    and a gate that silently matches nothing is worse than one that refuses.
    """
    finding = _f(Severity.HIGH, Category.SECRETS)
    report = score([finding], loc_scanned=10_000)

    result = evaluate_gates([finding], report, {gate.name: _config_value(gate, finding)})

    assert not result.passed, f"{gate.name} ignored an upper-case configured value"
    assert gate.name in result.tripped


@pytest.mark.parametrize("gate", _VOCABULARY_GATES, ids=lambda g: g.name)
def test_a_vocabulary_gate_never_trips_on_a_suppressed_finding(gate):
    """A suppression carries a reason and an expiry; the gate must honour it."""
    finding = _f(Severity.HIGH, Category.SECRETS)
    suppressed = replace(finding, suppressed=True)
    report = score([suppressed], loc_scanned=10_000)

    result = evaluate_gates([suppressed], report, {gate.name: _config_value(gate, finding)})

    assert result.passed, f"{gate.name} tripped on a suppressed finding: {result.reasons}"


@pytest.mark.parametrize("gate", _VOCABULARY_GATES, ids=lambda g: g.name)
def test_a_vocabulary_gate_is_not_configured_when_its_list_is_empty(gate):
    """An absent or empty list means "not configured", not "match everything"."""
    finding = _f(Severity.CRITICAL, Category.SECRETS)
    report = score([finding], loc_scanned=10_000)

    assert evaluate_gates([finding], report, {}).passed
    assert evaluate_gates([finding], report, {gate.name: []}).passed


@pytest.mark.parametrize("gate", _VOCABULARY_GATES, ids=lambda g: g.name)
def test_a_vocabulary_gate_names_itself_and_its_vocabulary_in_the_reason(gate):
    """The operator reads the reason to find which gate stopped them, and on what.

    Both messages were written by hand in their own copy; sharing one
    evaluator must not flatten them into one anonymous sentence.
    """
    finding = _f(Severity.HIGH, Category.SECRETS)
    report = score([finding], loc_scanned=10_000)

    result = evaluate_gates([finding], report, {gate.name: _config_value(gate, finding)})
    reason = " ".join(result.reasons)

    assert "1 finding(s)" in reason, reason
    assert gate.phrase in reason, f"{gate.name} reason {reason!r} omits {gate.phrase!r}"
    assert getattr(finding, gate.attribute).value in reason, reason
