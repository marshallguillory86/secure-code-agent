"""Which findings are worth an agent's attention, and in what order.

The work order is the first-class output — the thing that makes the code
better. A flat list undermines it: a `shell=True` command injection and a
`PASSWORD_FIELD = "password"` name-match arrive with identical billing, so
the agent spends its care on noise and the real defect scrolls past.

**Low precision demotes a finding to a different tier. It never deletes
one.** Bandit's `B105` scored zero useful hits out of twenty-two across the
calibration corpus and still caught the planted `DB_PASSWORD =
"SuperSecret123!"` in a synthetic vulnerable repository. A rule like that is
worth keeping and worth labelling; it is not worth presenting as a confirmed
defect.

Three tiers, and the work order gives each its own instructions:

  FIX     — act on it. The scanner is confident and the rule has not been
            measured producing noise.
  REVIEW  — look at it, decide, then act. Either the scanner said it was
            guessing, or the rule is on the measured list below.
  ACCEPT  — a finding in the test tree or the documentation. Almost always
            deliberate; the useful output is a drafted suppression, not a
            patch.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable

from secure_code_audit.findings import Confidence, Finding, Severity


class Tier(enum.Enum):
    FIX = "fix"
    REVIEW = "review"
    ACCEPT = "accept"


#: Rules measured producing findings that are not defects, with the evidence.
#:
#: This table is short on purpose. A rule belongs here only after its output
#: has actually been read — demoting a rule on a hunch hides real defects,
#: which is the failure mode that matters more than noise.
LOW_PRECISION: dict[str, str] = {
    "B105": (
        "Name heuristic, not a value check: it fires when an identifier "
        "looks credential-ish. Across the calibration corpus all 22 scored "
        'hits were non-credentials — `EMAIL_HOST_PASSWORD = ""` and '
        '`SECRET_KEY = ""` (empty defaults), `PASSWORD_FIELD = "password"` '
        'and `reset_url_token = "set-password"` (field names). The same '
        "rule does catch a real hardcoded credential, so it is demoted, not "
        "dropped."
    ),
    "B106": (
        "Same heuristic as B105 applied to keyword arguments. Grouped with "
        "it rather than measured separately: all 387 corpus hits were in "
        "test trees, so the primary-tree precision is unmeasured and "
        "asserting it would be a guess."
    ),
    "B101": (
        "`assert` is stripped under `python -O`, which is a robustness "
        "concern rather than an exploitable weakness — Bandit files it "
        "under CWE-703, which belongs to no OWASP Top 10 category. It is "
        "the single most voluminous rule in the corpus at 7,886 hits, and "
        "the 172 in primary trees are internal invariant checks such as "
        "`assert algorithm == self.algorithm` inside Django's password "
        "hashers."
    ),
}

#: Axes whose findings are suppression candidates rather than patch targets.
_ACCEPT_AXES = frozenset({"test tree", "documentation"})


#: Bandit quotes the offending value: `Possible hardcoded password: 'x'`.
_QUOTED_VALUE = re.compile(r"password: '(.*)'\s*$")


def _looks_like_a_credential(message: str) -> bool:
    """Does the matched *value* look like a secret, rather than a name?

    Demoting `B105` wholesale demoted the real finding with the noise: a
    planted `DB_PASSWORD = "SuperSecret123!"` and a live-shaped AWS key both
    landed in REVIEW, below nine lesser items. A hardcoded AWS key is close
    to the worst thing this tool can find and it must not be buried.

    The rule fires on the identifier; this reads the value it fired on.
    Length at least twelve, containing both a digit and an uppercase letter
    — deliberately dull, and checked rather than assumed. Against all 22
    `B105`/`B106` values in the calibration corpus it promotes **none**:
    `""`, `"!"`, `"password"`, `"set-password"`, `"django-insecure-"`,
    `"_password_reset_token"` and `"COLLATE"` all stay in REVIEW. It
    promotes both planted credentials.

    A missed real credential still appears in REVIEW, which is the safe
    direction for the error to fall.
    """
    match = _QUOTED_VALUE.search(message)
    if not match:
        return False
    value = match.group(1)
    return len(value) >= 12 and any(c.isdigit() for c in value) and any(c.isupper() for c in value)


def tier_of(finding: Finding, axis: str = "primary") -> Tier:
    """Classify one finding.

    Order matters. Where a finding *lives* outweighs what rule found it: a
    genuine hardcoded key in a test fixture is still deliberate, and a
    high-confidence rule firing there does not make it a patch target.
    """
    if axis in _ACCEPT_AXES:
        return Tier.ACCEPT
    if finding.rule_id in LOW_PRECISION:
        # Unless the value itself gives it away.
        if _looks_like_a_credential(finding.message):
            return Tier.FIX
        return Tier.REVIEW
    if finding.confidence is Confidence.LOW:
        return Tier.REVIEW
    return Tier.FIX


def reason_for(finding: Finding) -> str | None:
    """Why a finding was demoted, in words the reader can check."""
    measured = LOW_PRECISION.get(finding.rule_id)
    if measured:
        return measured
    if finding.confidence is Confidence.LOW:
        return (
            f"{finding.scanner} reported this at low confidence — it is "
            f"flagging a pattern it is not sure about."
        )
    return None


def partition(
    findings: Iterable[Finding], axis_of=lambda _f: "primary"
) -> dict[Tier, list[Finding]]:
    """Group actionable findings by tier, worst-first within each.

    Informational findings are dropped here rather than tiered: they are
    control findings — "checkov did not run" — and belong in the coverage
    block, not in a work order that asks an agent to change code.
    """
    out: dict[Tier, list[Finding]] = {tier: [] for tier in Tier}
    for finding in findings:
        if finding.suppressed or finding.severity is Severity.INFORMATIONAL:
            continue
        out[tier_of(finding, axis_of(finding))].append(finding)
    for group in out.values():
        group.sort(key=lambda f: (-f.severity.rank, f.file_path.as_posix(), f.line_start))
    return out
