"""A work order is a prompt, not a backlog.

Marshall, 2026-09-11: *"make sure you never create 15,000 line work order
prompts. that is retarded. prompts should be paragraph or two sized within
reason, not a fucking entire program."* The rule predates this file — it is
in `RULES.md` and names `--prompt-output` explicitly — and this repository
was not honouring it.

The history is a lesson in fixing the number instead of the principle:

| version | Django | PyGoat |
| --- | ---: | ---: |
| list everything | 15,390 | — |
| cap 40 per tier | 1,954 | 1,602 |
| cap 12, compressed | **254** | **229** |

Capping at 40 fixed the 15k and left a work order that was still a program.
The bulk was never where it looked: Django's twelve §FIX blocks carried
**212 lines inside code fences**, because scanners return whole-function
context and nothing trimmed it.

Ordinary repositories now land at 85–145 lines. The caps only bite on
pathological inputs, which is what a cap is for.

**Length is not thoroughness.** Nothing is dropped silently — every
truncation is stated and the full backlog is in the report, which is a file
someone scrolls rather than a payload someone pastes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import remediation
from secure_code_audit.findings import Category, Confidence, Finding, Severity

#: A work order must fit on a page. Generous against the measured worst case
#: (254) so ordinary drift does not fail the build, tight enough that
#: returning to a backfilled backlog does.
MAX_LINES = 320

#: The payload an agent actually holds.
MAX_WORDS = 2500


def _finding(n: int, *, severity: Severity = Severity.HIGH, axis_file: str = "src/app.py"):
    return Finding(
        rule_id=f"R{n:03d}",
        scanner="fixture",
        fingerprint=f"fp{n}",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3.5",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path(axis_file),
        line_start=n,
        line_end=n,
        # Whole-function context, which is what real scanners return and what
        # went unmeasured until it was 212 lines of one work order.
        code_snippet="\n".join(f"    line {i} of context" for i in range(40)),
        message="m" * 300,
        fix_hint="f" * 200,
    )


def _order(count: int) -> str:
    findings = [_finding(i) for i in range(count)]
    return remediation.generate(findings, root=Path("/repo"))


@pytest.mark.parametrize("count", [1, 12, 50, 500, 5000])
def test_a_work_order_fits_on_a_page(count: int):
    """Including at 5,000 findings, which is the shape that produced 15,390
    lines."""
    order = _order(count)

    assert len(order.split("\n")) <= MAX_LINES, (
        f"{count} findings produced {len(order.split(chr(10)))} lines; "
        f"a work order is a prompt, not a backlog"
    )


@pytest.mark.parametrize("count", [12, 500, 5000])
def test_a_work_order_stays_a_payload_an_agent_can_hold(count: int):
    order = _order(count)

    assert len(order.split()) <= MAX_WORDS


def test_growth_is_bounded_not_linear():
    """Forty times the findings must not be forty times the prompt.

    This is the property, and the count caps are only one way to hold it. A
    future change that lifts a cap will fail here before it reaches anyone.
    """
    small = len(_order(12).split("\n"))
    huge = len(_order(5000).split("\n"))

    assert huge <= small * 1.5, f"12 findings: {small} lines, 5000: {huge}"


# ---------------------------------------------------------------------------
# Nothing is dropped silently
# ---------------------------------------------------------------------------


def test_truncation_is_always_stated():
    order = _order(500)

    assert "more in" in order, "findings were omitted without saying so"
    assert "in the JSON report" in order


def test_the_quoted_snippet_is_trimmed_and_says_so():
    """The single biggest contributor to length, and the least visible."""
    order = _order(3)

    assert "more line(s) — open the file" in order
    fenced = order.count("line 39 of context")
    assert fenced == 0, "the full 40-line context reached the prompt"


def test_every_constraint_survives_the_compression():
    """The ten constraints are the product. Brevity may not cost one.

    They were compressed from thirty lines to ten, and the risk of that is
    dropping one while it reads fine.
    """
    order = _order(1)
    for marker in (
        "Fix only the findings listed",
        "crypto algorithms",
        "auth flows",
        "weaken validation",
        "security tests",
        "nosec",
        "Do not add dependencies",
        "Preserve behaviour",
        "FAILS before and PASSES after",
        "Keep the patch small",
    ):
        assert marker in order, f"constraint lost in compression: {marker!r}"


def test_the_bound_is_not_vacuous():
    """A generator that returned nothing would satisfy every assertion above."""
    order = _order(12)

    assert len(order.split("\n")) > 40, "the work order is suspiciously empty"
    assert "§FIX" in order
