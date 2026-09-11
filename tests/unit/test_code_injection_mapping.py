"""One `exec()` is one defect, however many scanners see it.

Bandit's `B102` (`exec`) was mapped to **CWE-78**, and `B307` (`eval`) had no
curated entry at all so it inherited the CWE Bandit itself reports — also
CWE-78. CWE-78 is *OS* command injection, the shell weakness that
B602/B603/B605/B607 cover. `eval` and `exec` compile and run Python; no shell
is involved.

The mislabel travelled everywhere a CWE goes: the OWASP mapping, SARIF, the
work order, and the Top-25 bonus.

**How it was found.** Corroboration merges findings from different scanners
when they share a CWE. Bandit's `B102` and this project's own
`sca.python.eval` fire on the same `exec(compile(...))` line in Flask's
`config.py`; CWE-78 and CWE-95 are not shared, so the merge never happened and
one defect was scored twice. Flask carried four such pairs.

The project already had a convention — semgrep's offline profile, RuboCop and
the built-in rules all file eval-family injection as CWE-95 — and Bandit was
the only scanner out of step.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
    merge_corroborating,
)
from secure_code_audit.standards import CWE_TOP25_2025, is_top25, lookup

# ---------------------------------------------------------------------------
# The mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", ["B102", "B307"])
def test_eval_family_is_code_injection_not_os_command_injection(rule_id: str):
    entry = lookup("bandit", rule_id)

    assert entry is not None, f"{rule_id} has no curated entry, so it falls back to Bandit's CWE"
    assert entry.canonical_cwe == "CWE-95"


@pytest.mark.parametrize("rule_id", ["B602"])
def test_the_shell_rules_keep_cwe_78(rule_id: str):
    """The fix must not overshoot: these really are OS command injection."""
    entry = lookup("bandit", rule_id)

    assert entry is not None and entry.canonical_cwe == "CWE-78"


def test_the_builtin_eval_rule_agrees_with_bandit():
    """Corroboration keys on a shared CWE, so agreement *is* the mechanism."""
    bandit = lookup("bandit", "B307")
    builtin = lookup("builtin_rules", "sca.python.eval")

    assert bandit is not None and builtin is not None
    assert bandit.canonical_cwe == builtin.canonical_cwe


# ---------------------------------------------------------------------------
# The merge it unblocks
# ---------------------------------------------------------------------------


def _finding(scanner: str, rule_id: str, cwe: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner=scanner,
        fingerprint=f"{scanner}:{rule_id}",
        canonical_cwe=cwe,
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        file_path=Path("src/flask/config.py"),
        line_start=209,
        line_end=209,
        code_snippet="exec(compile(...))",
        message="m",
    )


def test_two_scanners_on_one_line_merge_into_one_finding():
    """The Flask case, reduced."""
    merged = merge_corroborating(
        [
            _finding("bandit", "B102", "CWE-95"),
            _finding("builtin_rules", "sca.python.eval", "CWE-95"),
        ]
    )

    assert len(merged) == 1
    assert merged[0].corroborated_by


def test_the_same_line_under_the_old_mapping_would_not_have_merged():
    """Pins the cause, so a regression to CWE-78 fails here and not only in a
    corpus run nobody re-reads."""
    unmerged = merge_corroborating(
        [
            _finding("bandit", "B102", "CWE-78"),
            _finding("builtin_rules", "sca.python.eval", "CWE-95"),
        ]
    )

    assert len(unmerged) == 2


# ---------------------------------------------------------------------------
# The bonus the correction would otherwise have removed
# ---------------------------------------------------------------------------


def test_eval_injection_still_counts_as_top25():
    """CWE-95 is a documented ChildOf CWE-94, which is on the list.

    Describing the weakness accurately must not be what removes its Top-25
    weight — that would make the honest mapping the one that scores softer.
    """
    assert "CWE-95" not in CWE_TOP25_2025, "this test is about the child, not the list"
    assert is_top25("CWE-95") is True


def test_an_unrelated_cwe_is_still_not_top25():
    """The parent map must widen membership, not dissolve it."""
    assert is_top25("CWE-489") is False
    assert is_top25(None) is False


def test_a_listed_cwe_is_unaffected():
    assert is_top25("CWE-89") is True
    assert is_top25("CWE-78") is True
