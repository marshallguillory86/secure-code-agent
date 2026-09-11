"""PASS is a claim that something was checked.

Out of the box, with no configuration at all, a 200,000-line repository
containing SQL injection, `shell=True` command injection, `pickle.loads`,
MD5 and `eval` reported:

    secure-code-agent · score 4.06 — grade withheld (A- unverified) · gate PASS

Every word of that is technically defensible — the grade *was* withheld, and
no gate tripped because `DEFAULT gates` is `{}` and an absent gate cannot
trip — and the whole line still tells a reader their repository is fine.

The work order got it right at the same moment: seven findings in §FIX, SQL
injection and `shell=True` among them. So the first-class output worked and
the summary line undid it.

`_require_configured_gates` already refuses `--fail-on-gate` in this
situation and calls it "a green build with no security floor". This carries
the same fact far enough to reach the line a person reads.

**`passed` is unchanged.** No gate tripped, which is true, and flipping it
would break every ungated CI run that currently exits 0. What changes is
what we *claim*: `configured` says which gates could have failed, and the
summary distinguishes "nothing tripped" from "nothing was checked".
"""

from __future__ import annotations

from secure_code_audit.scoring import evaluate_gates, score

EMPTY_SCORE = score([], 1000)


def _gate(config: dict):
    return evaluate_gates([], EMPTY_SCORE, config)


# ---------------------------------------------------------------------------
# Configured, or merely not tripped
# ---------------------------------------------------------------------------


def test_no_gates_is_not_enforcement():
    result = _gate({})

    assert result.passed is True  # nothing tripped, which is true
    assert result.enforced is False  # but nothing was checked
    assert result.configured == ()


def test_a_real_gate_is_enforcement():
    result = _gate({"fail_on_severity": ["critical", "high"]})

    assert result.enforced is True
    assert "fail_on_severity" in result.configured


def test_an_empty_severity_list_is_not_enforcement():
    """A key that is present but inert provides no floor. An empty list
    matches nothing, and treating it as configured is how an empty policy
    passes for a real one."""
    assert _gate({"fail_on_severity": []}).enforced is False


def test_a_zero_min_score_is_not_enforcement():
    """No score can fall below zero."""
    assert _gate({"min_score": 0}).enforced is False


def test_a_positive_min_score_is_enforcement():
    assert _gate({"min_score": 4.0}).enforced is True


def test_an_empty_cap_map_is_not_enforcement():
    assert _gate({"max_unsuppressed": {}}).enforced is False


def test_every_configured_gate_is_named():
    """The operator should be able to see which policy is in force without
    re-reading their config."""
    result = _gate({"fail_on_severity": ["high"], "fail_on_new": True, "min_score": 3.0})

    assert set(result.configured) == {"fail_on_severity", "fail_on_new", "min_score"}


# ---------------------------------------------------------------------------
# Enforcement does not change what passes
# ---------------------------------------------------------------------------


def test_reporting_honesty_does_not_change_exit_semantics():
    """`passed` still means "no gate tripped". Flipping it for unconfigured
    runs would fail every ungated CI job that currently exits 0 — a
    behaviour change hiding inside a reporting fix."""
    assert _gate({}).passed is True
    assert _gate({"fail_on_severity": ["critical"]}).passed is True


def test_a_tripped_gate_still_fails():
    from pathlib import Path

    from secure_code_audit.findings import Category, Confidence, Finding, Severity

    finding = Finding(
        rule_id="B602",
        scanner="bandit",
        fingerprint="fp",
        canonical_cwe="CWE-78",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=Path("src/app.py"),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="m",
    )
    result = evaluate_gates([finding], EMPTY_SCORE, {"fail_on_severity": ["high"]})

    assert result.passed is False
    assert result.enforced is True
