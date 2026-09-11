"""A first run is not a regression, and must not be reported as one.

`fail_on_new` is the default gate (D15) — the only policy measured to catch
an introduced SQL injection without failing half of well-maintained code.
Its cost is the first run, where there is no baseline and every finding is
therefore new.

That is fine, and the message was not. The gate said:

    ✗ 2 new finding(s) since baseline

with no baseline in existence. "Since baseline" claims one exists and that
these appeared after it — the opposite of the truth, and precisely the
moment a new adopter decides whether the tool is worth keeping.

`load()` returns an empty mapping for a baseline that is absent, unreadable
or genuinely empty, so those three were indistinguishable downstream. The
middle one matters on its own: a corrupted baseline silently turns an
established repository back into a first run, failing the build with a
message blaming the code.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.baseline import State, state
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import evaluate_gates, score

EMPTY_SCORE = score([], 1000)


def _new_finding() -> Finding:
    return Finding(
        rule_id="B608",
        scanner="bandit",
        fingerprint="fp1",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        file_path=Path("src/app.py"),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="m",
        is_new=True,
    )


def _reason(baseline_state: str) -> str:
    result = evaluate_gates(
        [_new_finding()],
        EMPTY_SCORE,
        {"fail_on_new": True, "_baseline_state": baseline_state},
    )
    assert result.passed is False
    return " ".join(result.reasons)


# ---------------------------------------------------------------------------
# Telling the three states apart
# ---------------------------------------------------------------------------


def test_a_missing_baseline_is_absent(tmp_path):
    assert state(tmp_path / "nope.json") is State.ABSENT


def test_a_valid_baseline_is_present(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"entries": {}}), encoding="utf-8")

    assert state(path) is State.PRESENT


def test_a_corrupt_baseline_is_unreadable(tmp_path):
    """Distinct from absent, because the causes and the fixes differ."""
    path = tmp_path / "b.json"
    path.write_text("{ this is not json", encoding="utf-8")

    assert state(path) is State.UNREADABLE


def test_a_json_scalar_is_unreadable(tmp_path):
    """Valid JSON is not the same as a valid baseline."""
    path = tmp_path / "b.json"
    path.write_text('"a string"', encoding="utf-8")

    assert state(path) is State.UNREADABLE


# ---------------------------------------------------------------------------
# What the operator is told
# ---------------------------------------------------------------------------


def test_a_first_run_says_there_is_nothing_to_compare_against():
    reason = _reason("absent")

    assert "no baseline exists yet" in reason
    assert "since baseline" not in reason


def test_a_first_run_says_what_to_do_next():
    """A gate failure an adopter cannot act on is an adopter lost."""
    reason = _reason("absent")

    assert "--bump-baseline" in reason


def test_a_broken_baseline_blames_the_baseline_not_the_code():
    reason = _reason("unreadable")

    assert "could not be parsed" in reason
    assert "--bump-baseline" not in reason


def test_a_real_regression_still_reads_as_one():
    """The ordinary case must keep its ordinary wording."""
    reason = _reason("present")

    assert reason == "1 new finding(s) since baseline"


def test_an_unknown_state_falls_back_to_the_plain_message():
    """A caller that does not pass the state gets the old behaviour rather
    than a message asserting something it has not checked."""
    result = evaluate_gates([_new_finding()], EMPTY_SCORE, {"fail_on_new": True})

    assert "since baseline" in " ".join(result.reasons)
