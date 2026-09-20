"""A declared capability's findings are not nominated for patching (D28).

D24 lets a project declare what it is. A finding whose rule *is* that
capability being exercised is routed to a `declared:` axis: counted,
listed in the report, and off the code-condition score.

The declaration reached the scorer and the renderer and never reached
triage. So one run of this tool said both of these things:

    security pillar:     5.0 healthy — "findings: no findings"
    security work order: 68 to fix

The same 68. Every one of them `B404`/`B603`/`B607` — `subprocess`
imports and calls in a tool whose entire purpose is running other
programs — plus the XML and URL findings the project had also declared.

Two costs, and the second is the serious one. A reader of the HTML report
sees a green pillar beside "68 to fix". And an agent handed that work
order starts rewriting the architecture the operator explicitly declared,
under a §FIX heading that says "patch these".

`_ACCEPT_AXES` was a hardcoded pair written before declared axes existed.
The fix is at the axis, not a third literal: every `declared: ` axis is a
suppression candidate, for the same reason the test tree is — where a
finding lives outweighs which rule found it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import remediation, triage
from secure_code_audit.capabilities import AXIS_PREFIX
from secure_code_audit.findings import Category, Confidence, Finding, Severity


def _finding(rule_id: str = "B404", path: str = "src/runner.py") -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=f"fp:{rule_id}:{path}",
        canonical_cwe="CWE-78",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path=Path(path),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="Consider possible security implications of the subprocess module.",
    )


@pytest.mark.parametrize(
    "capability",
    [
        "spawns_processes",
        "parses_untrusted_xml",
        "fetches_remote_urls",
        "uses_nondeterministic_randomness",
    ],
)
def test_every_declared_axis_is_a_suppression_candidate(capability) -> None:
    """Not just the one that was noticed. Any declaration, any capability."""
    axis = AXIS_PREFIX + capability

    assert triage.tier_of(_finding(), axis) is triage.Tier.ACCEPT


def test_the_same_finding_on_the_primary_axis_is_still_a_patch_target() -> None:
    """The declaration is what changes the tier, not the rule.

    An undeclared project gets the same finding in §FIX, which is correct:
    it has not said this is what it is.
    """
    assert triage.tier_of(_finding(), "primary") is triage.Tier.FIX


def test_a_declared_finding_does_not_reach_the_fix_tier(root: Path | None = None) -> None:
    """Through `partition`, which is what the work order actually calls."""
    tiers = triage.partition([_finding()], lambda _f: AXIS_PREFIX + "spawns_processes")

    assert tiers[triage.Tier.FIX] == []
    assert len(tiers[triage.Tier.ACCEPT]) == 1


def test_the_work_order_does_not_nominate_declared_findings() -> None:
    """End of the chain: the artifact an agent is handed.

    The §FIX heading says "patch these". A declared finding under it is an
    instruction to undo the architecture the operator declared.
    """
    data = remediation.as_data(
        [_finding(), _finding("B603"), _finding("B607")],
        axis_of=lambda _f: AXIS_PREFIX + "spawns_processes",
    )

    assert data["counts"]["fix"] == 0
    assert data["fix"]["shown"] == []
    assert data["counts"]["accept"] == 3


def test_the_pillar_and_the_work_order_agree() -> None:
    """The contradiction, asserted as one property.

    Nothing the scorer treats as declared architecture may appear in the
    tier that asks for a patch.
    """
    findings = [_finding(), _finding("B603"), _finding("B310")]
    axis_of = lambda _f: AXIS_PREFIX + "spawns_processes"  # noqa: E731

    tiers = triage.partition(findings, axis_of)
    scored = [f for f in findings if axis_of(f) == "primary"]

    assert not scored, "fixture no longer declares every finding"
    assert not tiers[triage.Tier.FIX], (
        "a finding the scorer routed off the code condition was nominated for patching"
    )


def test_the_named_axes_still_accept() -> None:
    """The pair that already worked must keep working."""
    assert triage.tier_of(_finding(), "test tree") is triage.Tier.ACCEPT
    assert triage.tier_of(_finding(), "documentation") is triage.Tier.ACCEPT
