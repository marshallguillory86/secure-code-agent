"""Remediation prompt generator — the differentiator.

Produces an LLM-ready prompt scoped to the actual findings with explicit
guardrails against the documented failure modes for AI security fixes.

See docs/remediation.md for the full template + rationale.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from secure_code_audit import triage
from secure_code_audit.findings import Finding
from secure_code_audit.standards import cwe_url, owasp_label

_HARD_CONSTRAINTS = """\
## Hard constraints (MUST NOT violate)

1. Fix only the findings listed in §FINDINGS. Do not touch unrelated
   code, files, or modules.
2. Do not change cryptographic algorithms, key derivation, IV/nonce
   handling, padding modes, or random sources unless a finding in
   §FINDINGS explicitly names them as the defect.
3. Do not change authentication flows, session handling, token
   lifetime, cookie attributes, or authorization gates unless a
   finding in §FINDINGS explicitly names them.
4. Do not weaken input validation, output encoding, sanitization,
   bounds checks, regex strictness, or rate limits to make existing
   tests pass.
5. Do not disable, delete, or skip security tests. Do not remove
   `@_limiter.limit`, `@require_auth`, `@require_csrf`, or similar
   decorators.
6. Do not silence linter warnings via `# nosec`, `# noqa`, `# type:
   ignore`, `eslint-disable`, `sonar-disable`, or equivalent.
7. Do not introduce new third-party dependencies. Prefer stdlib or
   already-vendored libraries. If a new dependency is necessary,
   stop and ask the operator first.
8. Preserve behavior. Same inputs must produce the same outputs
   unless a finding explicitly proves the current behavior is
   unsafe (in which case, name the input/output pair that changes
   in the patch description).
9. Add a focused test that exercises the specific security boundary
   you fixed. The test must FAIL on the pre-fix code and PASS on the
   post-fix code. No "TODO: add test later".
10. Keep the patch small. If you find yourself rewriting a function
    rather than patching it, stop and report the structural issue
    to the operator instead.
"""


_PATCH_PROTOCOL = """\
## Patch protocol

For each finding:

  1. Quote the specific lines you will change (file:line_start-line_end).
  2. State the minimum change that resolves the finding.
  3. State the test you will add.
  4. Apply the change.
  5. Run the test. Confirm it fails on the pre-fix code (via git stash
     or equivalent) and passes after.
  6. Re-run the audit (the operator's CI will do this — you don't need
     to invoke secure-code-agent yourself).

## Reporting

When done, emit a single summary block per finding:

  · Finding id:
  · Files changed (file:line ranges):
  · Test added (file:line range):
  · Behavior change (yes/no — if yes, name input → old output / new output):
  · Standards satisfied:

If you discover the finding is a false positive, do NOT apply a fix.
Instead, emit a suppression candidate for `.scignore.yaml` with the
justification and a proposed `expires` date (max 90 days). Operator
will review.
"""


def generate(
    findings: Iterable[Finding],
    root: Path | None = None,
    axis_of=lambda _f: "primary",
) -> str:
    """Build the work order. The operator hands this to their agent.

    Grouped into tiers rather than listed flat. A flat list gave a
    `shell=True` command injection and a `PASSWORD_FIELD = "password"`
    name-match the same billing, so an agent working top-to-bottom spent its
    care on noise. See `triage.py` for what lands where and why.
    """
    tiers = triage.partition(findings, axis_of)
    if not any(tiers.values()):
        return (
            "# Security remediation — no actionable findings\n\n"
            "secure-code-agent did not surface any actionable security findings "
            "for this run. Nothing to fix.\n"
        )

    fix = tiers[triage.Tier.FIX]
    review = tiers[triage.Tier.REVIEW]
    accept = tiers[triage.Tier.ACCEPT]

    parts: list[str] = []
    parts.append("# Security work order\n")
    parts.append(
        f"**{len(fix)} to fix · {len(review)} to review · "
        f"{len(accept)} suppression candidates.**\n\n"
        "Work the tiers in order. Everything in §FIX is a defect the scanner "
        "is confident about; everything in §REVIEW needs your judgement "
        "before you touch it, and the reason is stated per finding. This is a "
        "constrained task, not a refactor.\n"
    )
    parts.append(_HARD_CONSTRAINTS)
    parts.append(_PATCH_PROTOCOL)
    parts.append("## Standards context\n")
    parts.append(
        "Each finding below carries its CWE id, OWASP Top 10 bucket, OWASP\n"
        "ASVS section, and NIST SSDF practice. Read the linked standards\n"
        "entries before editing — they are the authoritative description\n"
        "of the weakness.\n"
    )

    n = 0
    if fix:
        parts.append("## §FIX — patch these\n")
        for f in fix:
            n += 1
            parts.append(_finding_block(n, f, root))

    if review:
        parts.append("## §REVIEW — confirm before changing\n")
        parts.append(
            "These come from rules measured producing findings that are not\n"
            "defects, or from a scanner reporting low confidence. **Do not\n"
            "patch one without first checking it is real.** If it is, fix it\n"
            "under the same constraints as §FIX. If it is not, emit a\n"
            "suppression candidate with the justification — that is a\n"
            "successful outcome for this tier, not a failure.\n"
        )
        for f in review:
            n += 1
            parts.append(_finding_block(n, f, root, note=triage.reason_for(f)))

    if accept:
        parts.append("## §ACCEPT — test tree and documentation\n")
        parts.append(
            "Findings outside the shipped source. A credential in a test\n"
            "fixture or a tutorial is usually deliberate, and these do not\n"
            "grade the code condition — but they are still reported, and one\n"
            "of them may be a real key committed to the wrong place.\n\n"
            "**Do not patch these.** For each, decide: a genuine secret to\n"
            "rotate and remove, or a fixture to record in `.scignore.yaml`\n"
            "with a reason and an expiry. Propose, do not apply.\n"
        )
        for f in accept:
            n += 1
            parts.append(_finding_block(n, f, root))

    parts.append(_footer())
    return "\n".join(parts)


def _finding_block(n: int, f: Finding, root: Path | None = None, note: str | None = None) -> str:
    lines: list[str] = []
    lines.append(f"### Finding {n}: `{f.rule_id}` — {f.short_desc or f.message[:120]}")
    lines.append("")
    lines.append(f"- **Severity:** {f.severity.value} ({f.confidence.value} confidence)")
    if f.canonical_cwe:
        top25 = " (MITRE Top 25)" if f.cwe_top25 else ""
        lines.append(f"- **CWE:** [{f.canonical_cwe}]({cwe_url(f.canonical_cwe)}){top25}")
    if f.owasp_top10:
        lines.append(f"- **OWASP Top 10:** {owasp_label(f.owasp_top10)}")
    if f.asvs_section:
        lines.append(f"- **OWASP ASVS:** `{f.asvs_section}`")
    if f.nist_ssdf:
        lines.append(f"- **NIST SSDF:** `{f.nist_ssdf}`")
    lines.append(f"- **Scanner:** `{f.scanner}`")
    lines.append(f"- **Category:** `{f.category.value}`")
    lines.append("")
    lines.append(
        f"**Location:** `{_display_path(f.file_path, root)}:{f.line_start}"
        + (f"-{f.line_end}" if f.line_end and f.line_end != f.line_start else "")
        + "`"
    )
    if f.code_snippet:
        lines.append("")
        lines.append("```")
        lines.append(f.code_snippet.rstrip())
        lines.append("```")
    lines.append("")
    lines.append(f"**Why this matters:** {f.message}")
    if note:
        lines.append("")
        lines.append(f"**Why this needs checking first:** {note}")
    if f.fix_hint:
        lines.append("")
        lines.append(f"**Suggested approach:** {f.fix_hint}")
    lines.append("")
    return "\n".join(lines)


def _footer() -> str:
    return (
        "---\n\n"
        "End of findings. Apply the patch protocol above per finding. "
        "Report each one in the summary block format.\n"
    )


def _display_path(path: Path, root: Path | None) -> str:
    """Repository-relative, because a work order gets pasted somewhere else.

    Finding paths are absolute by design — every consumer that asks "where
    is this?" needs them anchored to the audited tree. But an absolute path
    is the wrong thing to hand a person or an agent: it names one machine's
    checkout, and `/private/tmp/.../scratchpad/wo/src/app.py:13` is not a
    location anyone can act on.
    """
    if root is None or not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        # Outside the tree — an imported SARIF from another machine. Leave
        # it absolute rather than inventing a relative path that is wrong.
        return path.as_posix()


def write(
    findings: Iterable[Finding],
    path: Path,
    root: Path | None = None,
    axis_of=lambda _f: "primary",
) -> None:
    path.write_text(generate(findings, root, axis_of), encoding="utf-8")
