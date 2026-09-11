"""Renderers — markdown report, canonical JSON, PR-comment summary."""

from __future__ import annotations

import datetime
import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from secure_code_audit import __version__
from secure_code_audit.findings import Finding, Severity
from secure_code_audit.scanner_status import CoverageReport
from secure_code_audit.scanners import floor
from secure_code_audit.scoring import AxisReport, GateResult, ScoreReport, Verdict
from secure_code_audit.standards import cwe_url, owasp_label

# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def to_json(
    findings: Iterable[Finding],
    score: ScoreReport,
    gate: GateResult,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
    axes: Iterable[AxisReport] = (),
) -> dict:
    findings = list(findings)
    return {
        "version": __version__,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": {
            "overall": score.overall,
            "letter": score.letter,
            "verified_grade": verdict.verified_grade if verdict else None,
            "evidence_status": verdict.evidence_status if verdict else "incomplete",
            "evidence_reasons": list(verdict.reasons) if verdict else [],
            "coverage_complete": coverage is None or coverage.status.value == "complete",
            "loc_scanned": score.loc_scanned,
            "worst_category": score.worst_category.value if score.worst_category else None,
            # null where nothing could measure the category — never a default
            "per_category": {
                c.value: (round(v, 2) if v is not None else None)
                for c, v in score.per_category.items()
            },
            "per_category_count": {c.value: n for c, n in score.per_category_count.items()},
            "per_severity_count": {s.value: n for s, n in score.per_severity_count.items()},
        },
        "gate": {
            "passed": gate.passed,
            "reasons": list(gate.reasons),
            "tripped": list(gate.tripped),
        },
        "coverage": _coverage_to_dict(coverage),
        "reported_not_scored": _axes_to_dict(axes),
        # Every finding, tagged with the axis it belongs to. `findings` stays
        # the complete list so nothing is hidden from a consumer that reads
        # only this key, and `axis` says which of them the score counted.
        #
        # Without the tag this array mixed scored and unscored findings while
        # the axis blocks repeated the unscored ones, so a consumer summing
        # both double-counted — and the calibration harness did exactly that,
        # reporting a median over dependency findings the product does not
        # score.
        "findings": [_finding_to_dict(f, axis_of(f, axes)) for f in findings],
    }


def _axis_key_of(finding: Finding) -> tuple:
    return (finding.fingerprint, str(finding.file_path), finding.line_start, finding.rule_id)


def axis_of(finding: Finding, axes: Iterable[AxisReport]) -> str:
    """Which axis a finding was reported on. "primary" means it was scored."""
    key = _axis_key_of(finding)
    for axis in axes or ():
        if any(_axis_key_of(other) == key for other in axis.findings):
            return axis.name
    return "primary"


def _finding_to_dict(f: Finding, axis: str = "primary") -> dict:
    return {
        # "primary" was scored; anything else was reported beside the score.
        "axis": axis,
        "scored": axis == "primary",
        "rule_id": f.rule_id,
        "scanner": f.scanner,
        "fingerprint": f.fingerprint,
        "canonical_cwe": f.canonical_cwe,
        "owasp_top10": f.owasp_top10,
        "asvs_section": f.asvs_section,
        "nist_ssdf": f.nist_ssdf,
        "category": f.category.value,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "cwe_top25": f.cwe_top25,
        # Other checks that reported this same weakness at this same line.
        # Corroboration is reported rather than dropped: two independent
        # scanners agreeing is stronger evidence than one, and an operator
        # deciding what to fix first should be able to see it.
        "corroborated_by": list(f.corroborated_by),
        "file_path": f.file_path.as_posix(),
        "line_start": f.line_start,
        "line_end": f.line_end,
        "code_snippet": f.code_snippet,
        "message": f.message,
        "short_desc": f.short_desc,
        "fix_hint": f.fix_hint,
        "suppressed": f.suppressed,
        "suppression_note": f.suppression_note,
        "is_new": f.is_new,
    }


def _coverage_to_dict(coverage: CoverageReport | None) -> dict | None:
    if coverage is None:
        return None
    return {
        "status": coverage.status.value,
        "required": list(coverage.required),
        "unverified": list(coverage.unverified),
        "failures": list(coverage.failures),
        "scanners": [
            {
                "name": execution.name,
                "outcome": execution.outcome.value,
                "command": list(execution.command),
                "version": execution.version,
                "finding_count": execution.finding_count,
                "reason": execution.reason,
                "scope": execution.scope,
            }
            for execution in coverage.executions
        ],
    }


def _axes_to_dict(axes: Iterable[AxisReport]) -> dict:
    """Axes reported beside the score, never folded into it.

    Findings are carried in full. Filing them under their own key is the
    opposite of hiding them: before this, seven thousand `assert` statements in
    a test suite outweighed everything a reader actually needed to see, and a
    library's dev-dependency CVEs sank its code-condition grade.
    """
    return {
        _axis_key(axis.name): {
            "name": axis.name,
            "loc": axis.loc,
            "count": axis.count,
            "scored": False,
            "gated": axis.name == "dependencies",
            "note": _AXIS_NOTES.get(axis.name, ""),
            "per_severity_count": {s.value: n for s, n in axis.per_severity_count.items()},
            "per_category_count": {c.value: n for c, n in axis.per_category_count.items()},
            # Not repeated here: every one of these appears in the top-level
            # `findings` array tagged with this axis name. Duplicating them
            # invited a consumer to count them twice.
        }
        for axis in axes
    }


def _axis_key(name: str) -> str:
    return name.replace(" ", "_")


#: Why each axis sits outside the score. Stated in the artifact rather than
#: only in the docs, because the reader who most needs it is the one looking at
#: a number they did not expect.
_AXIS_NOTES = {
    "test tree": (
        "Reported, not scored. A project graded on its test fixtures is graded "
        "on the wrong thing. Secrets found here are still gated when the "
        "configuration names the category, because nothing static separates a "
        "live credential from a test certificate."
    ),
    "documentation": (
        "Reported, not scored. Prose is not the shipped source, and a "
        "credential in a tutorial is an illustration. Gated on the same terms "
        "as the test tree."
    ),
    "dependencies": (
        "Reported and gated, but not scored as code condition. A CVE in a "
        "pinned dependency is fixed with a version bump; an injection flaw is "
        "fixed with a rewrite. Gates still apply, so a critical runtime CVE "
        "still fails a build."
    ),
}


def write_json(
    findings: Iterable[Finding],
    score: ScoreReport,
    gate: GateResult,
    path: Path,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
    axes: Iterable[AxisReport] = (),
) -> None:
    path.write_text(
        json.dumps(to_json(findings, score, gate, coverage, verdict, axes), indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def write_markdown(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    path: Path,
    scanners_run: list[str],
    scanners_unavailable: list[str],
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
    axes: Iterable[AxisReport] = (),
) -> None:
    path.write_text(
        _markdown(
            findings, score, gate, scanners_run, scanners_unavailable, coverage, verdict, axes
        ),
        encoding="utf-8",
    )


def _markdown(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    scanners_run: list[str],
    scanners_unavailable: list[str],
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
    axes: Iterable[AxisReport] = (),
) -> str:
    lines: list[str] = []
    lines.append("# secure-code-agent report\n")
    lines.append(
        f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ·  "
        f"agent v{__version__}\n"
    )

    lines.append(_summary_section(score, gate, coverage, verdict))
    lines.append(_categories_table(score))
    lines.append(_severity_table(score))
    for axis in axes or ():
        lines.append(_axis_section(axis))
    lines.append(_scanners_section(scanners_run, scanners_unavailable, coverage))
    lines.append(_findings_sections(findings))
    return "\n".join(lines)


def _summary_section(
    score: ScoreReport,
    gate: GateResult,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
) -> str:
    """The human-facing summary. It reads the verdict; it does not re-decide it.

    This section used to caveat the score on `coverage.status != complete`,
    which is a *different* and weaker condition than the one `Verdict` applies.
    A run with no `gates.require_scanners` declared has complete coverage of
    whatever happened to be selected, so the JSON reported
    `verified_grade: null` while this section printed a bare **A+** — the same
    run, two answers, and the unqualified one in the artifact a person actually
    reads. That is the P3 failure this project exists to prevent, surviving in
    the renderer where it does the most damage.
    """
    status = "✅ PASS" if gate.passed else "❌ FAIL"
    out = ["## Summary", ""]
    if coverage is not None:
        out.append(f"- **Scanner coverage:** {coverage.status.value.upper()}")
    # No verdict means nobody decided this run could claim a grade, so it
    # cannot. Falling back to a locally-invented condition here is what put a
    # second decision rule in the codebase in the first place.
    if verdict is None or not verdict.is_verified:
        if score.overall is None:
            out.append(
                "- **No score:** nothing measurable was scanned. This is not a "
                "clean result; it is the absence of one."
            )
        else:
            out.append(
                f"- **Finding score (not a verified grade):** {score.overall:.2f} / 5.00 — "
                f"**{score.letter}**"
            )
        for reason in verdict.reasons if verdict else ():
            out.append(f"    - {reason}")
    else:
        out.append(f"- **Verified grade:** {score.overall:.2f} / 5.00 — **{score.letter}**")
    out.append(f"- **Gate:** {status}")
    if not gate.passed:
        out.append("- **Tripped gates:**")
        for reason, key in zip(gate.reasons, gate.tripped, strict=True):
            out.append(f"    - `{key}` — {reason}")
    out.append(f"- **LOC scanned:** {score.loc_scanned:,}")
    if score.worst_category is not None:
        out.append(f"- **Worst category:** `{score.worst_category.value}`")
    out.append("")
    return "\n".join(out)


def _axis_section(report: AxisReport | None) -> str:
    """One axis, beside the score rather than inside it.

    Shown even when empty, because "we looked and found nothing" and "we never
    looked" are different statements and a reader cannot tell them apart from a
    missing section.
    """
    if report is None:
        return ""
    title = report.name[:1].upper() + report.name[1:]
    out = [f"## {title}", ""]
    if report.loc is not None:
        out.append(f"- **Lines:** {report.loc:,}")
    gated = report.name == "dependencies"
    out.append(
        f"- **Findings:** {report.count} — reported"
        + (" and gated, " if gated else ", ")
        + "not scored"
    )
    if report.per_severity_count:
        by_severity = ", ".join(
            f"{severity.value}: {count}"
            for severity, count in sorted(
                report.per_severity_count.items(), key=lambda kv: -kv[0].rank
            )
        )
        out.append(f"- **By severity:** {by_severity}")
    note = _AXIS_NOTES.get(report.name)
    if note:
        out.append(f"- {note}")
    out.append("")
    return "\n".join(out)


def _categories_table(score: ScoreReport) -> str:
    out = ["## Categories", "", "| Category | Grade | Score | Findings |", "|---|---|---:|---:|"]
    for cat_name, grade_letter, grade_score, count in score.as_table():
        # An unmeasured category shows a dash, not a number. Printing 5.00
        # for a category no scanner could read is the defect this whole
        # column exists to stop reporting.
        shown = f"{grade_score:.2f}" if grade_score is not None else "—"
        out.append(f"| `{cat_name}` | **{grade_letter}** | {shown} | {count} |")
    out.append("")
    return "\n".join(out)


def _severity_table(score: ScoreReport) -> str:
    out = ["## Severity breakdown", "", "| Severity | Count |", "|---|---:|"]
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ):
        out.append(f"| **{sev.value}** | {score.per_severity_count.get(sev, 0)} |")
    out.append("")
    return "\n".join(out)


def _scanners_section(
    scanners_run: list[str],
    scanners_unavailable: list[str],
    coverage: CoverageReport | None = None,
) -> str:
    out = ["## Scanners", ""]
    if coverage is not None:
        out.append(f"- Coverage: **{coverage.status.value.upper()}**")
        if coverage.required:
            out.append(f"- Required: {', '.join(coverage.required)}")
        if coverage.unverified:
            out.append(
                f"- Unverified (imported artifact, execution not observed): "
                f"{', '.join(coverage.unverified)}"
            )
    out.append(f"- Run: {', '.join(scanners_run) if scanners_run else '_none_'}")
    if floor.REPOSITORY_CADENCE_NAMES:
        out.append(
            f"- Deferred (repository cadence, supplied by SARIF import): "
            f"{', '.join(floor.REPOSITORY_CADENCE_NAMES)}"
        )
    if scanners_unavailable:
        out.append(f"- Skipped (binary not on PATH): {', '.join(scanners_unavailable)}")
    if coverage is not None and coverage.executions:
        out.extend(
            [
                "",
                "| Scanner | Outcome | Version | Command | Scope |",
                "|---|---|---|---|---|",
            ]
        )
        for execution in coverage.executions:
            command = " ".join(execution.command) or "—"
            out.append(
                f"| `{execution.name}` | `{execution.outcome.value}` | "
                f"{execution.version or '—'} | `{command}` | {execution.scope or '—'} |"
            )
    out.append("")
    return "\n".join(out)


def _findings_sections(findings: list[Finding]) -> str:
    if not findings:
        return "## Findings\n\n_None._\n"

    # Sort: severity desc, then category, then file
    severity_order = list(Severity)
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            0 if f.is_new else 1,
            f.category.value,
            f.file_path.as_posix(),
            f.line_start,
        ),
    )

    by_sev: dict[Severity, list[Finding]] = defaultdict(list)
    for f in sorted_findings:
        if f.suppressed:
            continue
        by_sev[f.severity].append(f)

    out = ["## Findings", ""]
    for sev in severity_order:
        bucket = by_sev.get(sev) or []
        if not bucket:
            continue
        out.append(f"### {sev.value.title()}")
        out.append("")
        for f in bucket:
            out.extend(_one_finding_md(f))
            out.append("")

    suppressed = [f for f in findings if f.suppressed]
    if suppressed:
        out.append("---")
        out.append("")
        out.append("## Acknowledged (suppressed)")
        out.append("")
        for f in suppressed:
            out.append(
                f"- `{f.rule_id}` — `{f.file_path.as_posix()}:{f.line_start}` — "
                f"{f.suppression_note or 'no note'}"
            )
        out.append("")
    return "\n".join(out)


def _one_finding_md(f: Finding) -> list[str]:
    out: list[str] = []
    new_marker = " 🆕" if f.is_new else ""
    out.append(f"#### `{f.rule_id}` — {f.short_desc or f.message[:120]}{new_marker}")
    out.append("")
    out.append(f"- **Severity:** {f.severity.value} ({f.confidence.value} confidence)")
    out.append(f"- **Category:** `{f.category.value}`")
    out.append(f"- **Scanner:** `{f.scanner}`")
    if f.canonical_cwe:
        cwe_marker = " (Top 25)" if f.cwe_top25 else ""
        out.append(f"- **CWE:** [{f.canonical_cwe}]({cwe_url(f.canonical_cwe)}){cwe_marker}")
    if f.owasp_top10:
        out.append(f"- **OWASP Top 10:** {owasp_label(f.owasp_top10)}")
    if f.asvs_section:
        out.append(f"- **OWASP ASVS:** `{f.asvs_section}`")
    if f.nist_ssdf:
        out.append(f"- **NIST SSDF:** `{f.nist_ssdf}`")
    out.append(
        f"- **Location:** `{f.file_path.as_posix()}:{f.line_start}"
        + (f"-{f.line_end}" if f.line_end and f.line_end != f.line_start else "")
        + "`"
    )
    if f.code_snippet:
        out.append("")
        out.append("```")
        out.append(f.code_snippet.rstrip())
        out.append("```")
    if f.fix_hint:
        out.append("")
        out.append(f"> 💡 **Fix:** {f.fix_hint}")
    return out


# ---------------------------------------------------------------------------
# PR comment (short, scannable)
# ---------------------------------------------------------------------------


def write_pr_comment(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    path: Path,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
) -> None:
    path.write_text(_pr_comment(findings, score, gate, coverage, verdict), encoding="utf-8")


def _pr_comment(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
) -> str:
    status = "✅" if gate.passed else "❌"
    n_crit = score.per_severity_count.get(Severity.CRITICAL, 0)
    n_high = score.per_severity_count.get(Severity.HIGH, 0)
    n_new = sum(1 for f in findings if f.is_new and not f.suppressed)

    # Same single source as every other output, and the same conservative
    # default. A PR comment is the most widely read artifact this tool produces
    # and the least likely to be cross-checked against the JSON, so it must
    # never caveat on its own terms.
    unverified = verdict is None or not verdict.is_verified
    score_label = "finding score, not a verified grade" if unverified else "verified grade"
    headline = (
        "no score — nothing measurable was scanned"
        if score.overall is None
        else f"{score_label} **{score.letter}** ({score.overall:.2f}/5.00)"
    )
    out = [
        f"### secure-code-agent {status} — {headline}",
        "",
        f"- Critical: **{n_crit}** · High: **{n_high}** · New since baseline: **{n_new}**",
        f"- Worst category: `{score.worst_category.value if score.worst_category else '_none_'}`",
    ]
    if coverage is not None:
        out.append(f"- Scanner coverage: **{coverage.status.value.upper()}**")
    if not gate.passed:
        out.append("- Tripped gates:")
        for r in gate.reasons:
            out.append(f"    - {r}")
    out.append("")
    out.append("_Full report uploaded as artifact._")
    return "\n".join(out)
