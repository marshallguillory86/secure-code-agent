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

#: The ten constraints, one line each.
#:
#: They are the product — the reviewer's word for them was "the leash" — and
#: not one is dropped here. What is dropped is the wrapping: thirty lines of
#: text carrying ten instructions. An instruction an agent has to wade to is
#: an instruction it is likelier to skip, so brevity is on the side of
#: compliance rather than against it.
_HARD_CONSTRAINTS = """\
## Hard constraints — MUST NOT violate

1. Fix only the findings listed. Touch nothing else.
2. Do not change crypto algorithms, key derivation, IV/nonce, padding or random sources unless a finding names them.
3. Do not change auth flows, sessions, token lifetime, cookie attributes or authorization gates unless a finding names them.
4. Do not weaken validation, encoding, sanitization, bounds checks, regex strictness or rate limits to make tests pass.
5. Do not disable, delete or skip security tests, or remove `@require_auth`-style decorators.
6. Do not silence warnings: no `# nosec`, `# noqa`, `# type: ignore`, `eslint-disable` or equivalent.
7. Do not add dependencies. If one is genuinely required, stop and ask.
8. Preserve behaviour. If a finding proves current behaviour unsafe, name the input → old/new output.
9. Add one focused test per fix that FAILS before and PASSES after. No "TODO: add test later".
10. Keep the patch small. If you are rewriting a function rather than patching it, stop and report why.
"""


_PATCH_PROTOCOL = """\
## Protocol

Per finding: quote the lines you will change, state the minimum change and
the test you will add, apply it, then confirm the test fails on the pre-fix
code and passes after. Do not re-run this tool; CI will.

Report per finding: id · files changed (`file:line`) · test added · behaviour
change (yes/no, with input → old/new) · standards satisfied.

A false positive is a successful outcome: do not patch it. Emit a
`.scignore.yaml` suppression candidate with the justification and a proposed
`expires` date (90 days maximum) for the operator to review.
"""


#: Findings given a full patch block. A work order is a prompt, not a backlog.
#:
#: Truncation is always stated, never silent. The first version of this file
#: listed every finding and produced a 541KB, 15,390-line prompt from this
#: repository's own audit — one no agent could act on and most could not
#: read. Capping at 40 per tier fixed that number and not the principle:
#: Django still produced 1,954 lines and PyGoat 1,602.
#:
#: This was 40 **per tier**, which produced 1,954 lines on Django and 1,602 on
#: PyGoat — eighty blocks of roughly twenty-three lines each. That is a
#: program, not something a person pastes into an agent, and it is the
#: sprawling unreviewable change the bounded prompt exists to prevent,
#: arriving one step earlier.
#:
#: Twelve is a batch an agent can hold and an operator can verify with
#: `--verify-against` before taking the next one. The remainder is not lost:
#: it is counted, and the full backlog is in the report, which is a file
#: someone scrolls rather than a payload someone pastes.
_MAX_BLOCKS = 12

#: §REVIEW is judgement, not patching, so it gets one line per finding rather
#: than a patch block. Listing forty of them in full was 881 lines of Django's
#: work order describing work the agent is explicitly told not to do yet.
_MAX_REVIEW_LINES = 12

#: Lines of code quoted per finding.
#:
#: The single biggest contributor to length, and invisible until measured:
#: Django's twelve §FIX blocks carried **212 lines inside code fences**,
#: roughly eighteen each, because scanners return whole-function context. A
#: work order needs enough to locate the defect, not to reproduce the
#: function — the agent has the file.
_MAX_SNIPPET_LINES = 3

#: Rules listed in the §ACCEPT table before it is summarised. The tier is a
#: decision per rule, and twenty-eight rows is a backlog again.
_MAX_ACCEPT_ROWS = 8


def _snippet(text: str) -> list[str]:
    lines = [line for line in text.rstrip().split("\n") if line.strip()]
    if len(lines) <= _MAX_SNIPPET_LINES:
        return lines
    kept = lines[:_MAX_SNIPPET_LINES]
    kept.append(f"… {len(lines) - _MAX_SNIPPET_LINES} more line(s) — open the file")
    return kept


def _overflow(remaining: int, section: str) -> str:
    """Say what was left out. Never drop findings silently."""
    return (
        f"> **{remaining} more in {section}.** Fix this batch, re-run, and the "
        f"next order carries the rest. All of them are in the JSON report.\n"
    )


def _accept_summary(findings: list[Finding], root: Path | None) -> str:
    """Group the side-axis findings instead of listing them.

    The action for this tier is "write one suppression entry", not "patch
    each of these", so the useful shape is per rule with a drafted entry —
    not 884 individual blocks.
    """
    lines: list[str] = [
        "Findings outside the shipped source. A credential in a test fixture",
        "or a tutorial is usually deliberate, and these do not grade the code",
        "condition — but they are reported, because one of them may be a real",
        "key committed to the wrong place.",
        "",
        "**Do not patch these.** Decide per group: a genuine secret to rotate",
        "and remove, or a fixture to record in `.scignore.yaml` with a reason",
        "and an expiry. Propose, do not apply.",
        "",
        "Grouped by rule, because the decision is per rule and not per line.",
        "",
        "| rule | count | worst | example |",
        "| --- | ---: | --- | --- |",
    ]
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    ranked = sorted(
        by_rule.items(), key=lambda kv: (-max(f.severity.rank for f in kv[1]), -len(kv[1]))
    )
    for rule_id, group in ranked[:_MAX_ACCEPT_ROWS]:
        worst = max(group, key=lambda f: f.severity.rank)
        example = _display_path(worst.file_path, root)
        lines.append(
            f"| `{rule_id}` | {len(group)} | {worst.severity.value} | "
            f"`{example}:{worst.line_start}` |"
        )
    if len(ranked) > _MAX_ACCEPT_ROWS:
        hidden = ranked[_MAX_ACCEPT_ROWS:]
        lines.append(
            f"| _{len(hidden)} more rule(s)_ | {sum(len(g) for _, g in hidden)} | | "
            f"_see the report_ |"
        )
    first = max(findings, key=lambda f: f.severity.rank)
    lines.extend(
        [
            "",
            "A suppression covering one of these groups looks like:",
            "",
            "```yaml",
            f"- rule_id: {first.rule_id}",
            '  paths: ["*/tests/*"]',
            '  reason: "state why this is deliberate, and what you checked"',
            '  expires: "YYYY-MM-DD"',
            "```",
            "",
        ]
    )
    return "\n".join(lines)


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
    # The standards-context section was four lines saying that each finding
    # carries its standards. Each finding carries its standards; saying so
    # is not context.

    n = 0
    if fix:
        parts.append("## §FIX — patch these\n")
        for f in fix[:_MAX_BLOCKS]:
            n += 1
            parts.append(_finding_block(n, f, root))
        if len(fix) > _MAX_BLOCKS:
            parts.append(_overflow(len(fix) - _MAX_BLOCKS, "§FIX"))

    if review:
        parts.append("## §REVIEW — confirm before changing\n")
        parts.append(
            "Low-precision rules or low scanner confidence. **Check each is "
            "real before patching it.** If it is, fix it under the §FIX "
            "constraints. If it is not, emit a suppression candidate with the "
            "justification — that is a successful outcome for this tier.\n"
        )
        listed = review[:_MAX_REVIEW_LINES]
        parts.append(
            "\n".join(
                _review_line(i, f, root, triage.reason_for(f)) for i, f in enumerate(listed, 1)
            )
            + "\n"
        )
        if len(review) > _MAX_REVIEW_LINES:
            parts.append(_overflow(len(review) - _MAX_REVIEW_LINES, "§REVIEW"))

    if accept:
        parts.append("## §ACCEPT — test tree and documentation\n")
        parts.append(_accept_summary(accept, root))

    parts.append(_footer())
    return "\n".join(parts)


def _location(f: Finding, root: Path | None) -> str:
    span = f"-{f.line_end}" if f.line_end and f.line_end != f.line_start else ""
    return f"{_display_path(f.file_path, root)}:{f.line_start}{span}"


def _standards(f: Finding) -> str:
    """One trailing line, not eight bullets.

    Severity, CWE, OWASP, ASVS, SSDF, scanner and category were each their
    own bullet — a reference card per finding, which is report material. An
    agent patching a line needs what it is, where it is, and what to do; the
    standards line stays because it is the citation that makes a finding
    checkable, compressed to the width it deserves.
    """
    bits: list[str] = []
    if f.canonical_cwe:
        top25 = " (Top 25)" if f.cwe_top25 else ""
        bits.append(f"[{f.canonical_cwe}]({cwe_url(f.canonical_cwe)}){top25}")
    if f.owasp_top10:
        bits.append(owasp_label(f.owasp_top10))
    if f.asvs_section:
        bits.append(f"ASVS `{f.asvs_section}`")
    if f.nist_ssdf:
        # Dropped in the first compression pass and restored: it costs nothing
        # on a line that already exists, and this tool claims an SSDF mapping.
        # Brevity may remove wrapping, not claims.
        bits.append(f"SSDF `{f.nist_ssdf}`")
    bits.append(f"{f.severity.value}/{f.confidence.value} via `{f.scanner}`")
    return " · ".join(bits)


def _finding_block(n: int, f: Finding, root: Path | None = None, note: str | None = None) -> str:
    # Location rides the heading. It was its own line with a blank either
    # side — three lines to say where, twelve times over.
    heading = f"### {n}. `{f.rule_id}` — {f.short_desc or f.message[:90]}"
    lines = [heading, "", f"`{_location(f, root)}`"]
    if f.code_snippet:
        lines += ["", "```", *_snippet(f.code_snippet), "```"]
    lines.append("")
    if note:
        lines += [f"**Check first:** {note}", ""]
    lines.append(f.fix_hint or f.message)
    lines += [_standards(f), ""]
    return "\n".join(lines)


def _review_line(n: int, f: Finding, root: Path | None, note: str | None) -> str:
    """One line. §REVIEW is judgement, not a patch instruction."""
    reason = f" — {note}" if note else ""
    return f"{n}. `{_location(f, root)}` · `{f.rule_id}` {f.short_desc or ''}{reason}".rstrip()


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
