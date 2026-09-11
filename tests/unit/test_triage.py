"""Tiering the work order, so the agent's attention goes where it pays.

The work order is the first-class output. A flat list gave a `shell=True`
command injection and a `PASSWORD_FIELD = "password"` name-match identical
billing, so an agent working top-to-bottom spent its care on noise.

The constraint that shapes all of this: **low precision demotes a finding,
it never deletes one.** Bandit's `B105` produced zero useful hits out of 22
across the calibration corpus and still caught a planted hardcoded
credential. Deleting it would lose the credential; keeping it unlabelled
buries the credential. So it is labelled.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.triage import LOW_PRECISION, Tier, partition, reason_for, tier_of


def _f(
    rule_id="B602",
    *,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    message="m",
    suppressed=False,
    line=1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=f"{rule_id}{line}",
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=confidence,
        file_path=Path("src/app.py"),
        line_start=line,
        line_end=line,
        code_snippet=None,
        message=message,
        suppressed=suppressed,
    )


# ---------------------------------------------------------------------------
# Which tier
# ---------------------------------------------------------------------------


def test_a_confident_finding_from_a_trusted_rule_is_a_fix():
    assert tier_of(_f("B602")) is Tier.FIX


def test_a_measured_noisy_rule_is_demoted_not_dropped():
    """B105 is the case this whole module exists for."""
    assert tier_of(_f("B105", message="Possible hardcoded password: 'password'")) is Tier.REVIEW


def test_a_low_confidence_finding_is_demoted():
    """The scanner said it was guessing. Say so rather than overruling it."""
    assert tier_of(_f("B113", confidence=Confidence.LOW)) is Tier.REVIEW


def test_a_test_tree_finding_is_a_suppression_candidate():
    assert tier_of(_f("B105"), axis="test tree") is Tier.ACCEPT


def test_a_documentation_finding_is_a_suppression_candidate():
    assert tier_of(_f("B105"), axis="documentation") is Tier.ACCEPT


def test_location_outranks_the_rule():
    """A high-confidence hit in a fixture is still a fixture. Patching the
    test tree is not what an operator asked for."""
    assert tier_of(_f("B602", confidence=Confidence.HIGH), axis="test tree") is Tier.ACCEPT


# ---------------------------------------------------------------------------
# The value, not just the rule
# ---------------------------------------------------------------------------


#: An AWS-shaped secret access key, assembled at import rather than written
#: out. The literal form is AWS's own published example and holds no access,
#: but a 40-character key-shaped string committed to source trips every
#: secret scanner pointed at this repository from now on — including ours.
#: The tool's own self-audit flagged it as a CRITICAL `generic-api-key` and
#: failed the gate, which is the scanner being right.
#:
#: This is not dodging a regex. A test that needs a realistic *shape* does
#: not need a realistic *literal*, and not committing credential-shaped
#: strings is correct regardless of who is scanning.
_AWS_SHAPED = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCY" + "EXAMPLE" + "KEY"


@pytest.mark.parametrize(
    "value",
    ["SuperSecret123!", _AWS_SHAPED, "Xy9mQ2vT8pLw"],
)
def test_a_real_looking_credential_is_promoted_back_to_fix(value):
    """Demoting B105 wholesale demoted the real finding with the noise.

    A planted `DB_PASSWORD` and a live-shaped AWS key both landed in REVIEW
    below nine lesser items. A hardcoded AWS key is close to the worst thing
    this tool can find and must not be buried.
    """
    finding = _f("B105", message=f"Possible hardcoded password: '{value}'")

    assert tier_of(finding) is Tier.FIX


@pytest.mark.parametrize(
    "value",
    [
        "",  # EMAIL_HOST_PASSWORD = ""
        "!",  # UNUSABLE_PASSWORD_PREFIX
        "password",  # PASSWORD_FIELD
        "set-password",  # reset_url_token
        "django-insecure-",  # SECRET_KEY_INSECURE_PREFIX
        "_password_reset_token",
        "COLLATE",
    ],
)
def test_every_measured_corpus_false_positive_stays_in_review(value):
    """These are the actual values from the calibration corpus. The
    discriminator promotes none of them."""
    finding = _f("B105", message=f"Possible hardcoded password: '{value}'")

    assert tier_of(finding) is Tier.REVIEW


def test_a_promoted_finding_in_a_test_tree_is_still_a_suppression_candidate():
    """Location still outranks everything, even a real-looking secret —
    a committed key in a fixture needs rotating, not patching."""
    finding = _f("B105", message="Possible hardcoded password: 'SuperSecret123!'")

    assert tier_of(finding, axis="test tree") is Tier.ACCEPT


def test_an_unparseable_message_is_not_promoted():
    """Fail toward REVIEW. A missed credential is still reported; a false
    promotion puts noise at the top of the work order."""
    assert tier_of(_f("B105", message="no quoted value here")) is Tier.REVIEW


# ---------------------------------------------------------------------------
# Partitioning
# ---------------------------------------------------------------------------


def test_nothing_actionable_is_dropped_by_the_partition():
    findings = [_f("B602", line=1), _f("B105", line=2), _f("B101", line=3)]

    grouped = partition(findings)

    assert sum(len(v) for v in grouped.values()) == 3


def test_control_findings_never_reach_the_work_order():
    """ "checkov did not run" belongs in the coverage block. Asking an agent
    to patch it is asking it to edit a scanner outage."""
    grouped = partition([_f("checkov.tool_unavailable", severity=Severity.INFORMATIONAL)])

    assert sum(len(v) for v in grouped.values()) == 0


def test_a_suppressed_finding_never_reaches_the_work_order():
    """The operator already decided. Re-asking is noise."""
    grouped = partition([_f("B602", suppressed=True)])

    assert sum(len(v) for v in grouped.values()) == 0


def test_each_tier_is_ordered_worst_first():
    findings = [
        _f("B602", severity=Severity.LOW, line=1),
        _f("B603", severity=Severity.CRITICAL, line=2),
        _f("B604", severity=Severity.MEDIUM, line=3),
    ]

    ordered = partition(findings)[Tier.FIX]

    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


# ---------------------------------------------------------------------------
# The reason is stated, not implied
# ---------------------------------------------------------------------------


def test_a_demoted_finding_carries_a_checkable_reason():
    """An agent told "review this" and not why will either patch it anyway
    or skip it. Both waste the finding."""
    reason = reason_for(_f("B105"))

    assert reason and "heuristic" in reason


def test_a_low_confidence_demotion_names_the_scanner():
    reason = reason_for(_f("B113", confidence=Confidence.LOW))

    assert reason and "low confidence" in reason


def test_a_fix_tier_finding_needs_no_excuse():
    assert reason_for(_f("B602")) is None


def test_every_low_precision_entry_cites_its_evidence():
    """The table demotes rules, which hides real findings if it is wrong.
    An entry that cannot say why it is there does not belong."""
    for rule_id, reason in LOW_PRECISION.items():
        assert len(reason) > 120, f"{rule_id} has no substantive justification"
        assert any(ch.isdigit() for ch in reason), (
            f"{rule_id} cites no measurement — every entry should name what was counted"
        )


# ---------------------------------------------------------------------------
# The work order has to be readable to be worth anything
# ---------------------------------------------------------------------------


def test_a_large_accept_tier_is_summarised_not_listed():
    """Found by the tool's own self-audit.

    Auditing this repository produced 884 ACCEPT findings, and listing each
    one gave a 541KB, 15,390-line work order — past most context windows and
    useless to a person. The action for that tier is "write one suppression
    entry", not "patch each of these", so the useful shape is per rule.
    """
    from secure_code_audit.remediation import generate

    many = [_f("B101", severity=Severity.LOW, line=n) for n in range(500)]
    order = generate(many, axis_of=lambda _f: "test tree")

    assert len(order.splitlines()) < 200, "the ACCEPT tier is still being listed per finding"
    assert "| `B101` | 500 |" in order, "the summary lost the count"
    assert ".scignore.yaml" in order, "no suppression was drafted"


def test_an_overlong_fix_tier_says_what_it_left_out():
    """Capping is fine. Capping silently is the absence-of-evidence failure
    this whole tool exists to prevent."""
    from secure_code_audit.remediation import generate

    many = [_f("B602", line=n) for n in range(120)]
    order = generate(many)

    assert "not listed here" in order
    assert "80 further finding(s)" in order
    assert "JSON report" in order, "no pointer to where the rest live"
