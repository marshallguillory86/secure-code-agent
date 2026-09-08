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
from secure_code_audit.scoring import GateResult, ScoreReport, Verdict
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
            "per_category": {c.value: round(v, 2) for c, v in score.per_category.items()},
            "per_category_count": {c.value: n for c, n in score.per_category_count.items()},
            "per_severity_count": {s.value: n for s, n in score.per_severity_count.items()},
        },
        "gate": {
            "passed": gate.passed,
            "reasons": list(gate.reasons),
            "tripped": list(gate.tripped),
        },
        "coverage": _coverage_to_dict(coverage),
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
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


def write_json(
    findings: Iterable[Finding],
    score: ScoreReport,
    gate: GateResult,
    path: Path,
    coverage: CoverageReport | None = None,
    verdict: Verdict | None = None,
) -> None:
    path.write_text(
        json.dumps(to_json(findings, score, gate, coverage, verdict), indent=2), encoding="utf-8"
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
) -> None:
    path.write_text(
        _markdown(findings, score, gate, scanners_run, scanners_unavailable, coverage),
        encoding="utf-8",
    )


def _markdown(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    scanners_run: list[str],
    scanners_unavailable: list[str],
    coverage: CoverageReport | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# secure-code-agent report\n")
    lines.append(
        f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ·  "
        f"agent v{__version__}\n"
    )

    lines.append(_summary_section(score, gate, coverage))
    lines.append(_categories_table(score))
    lines.append(_severity_table(score))
    lines.append(_scanners_section(scanners_run, scanners_unavailable, coverage))
    lines.append(_findings_sections(findings))
    return "\n".join(lines)


def _summary_section(
    score: ScoreReport, gate: GateResult, coverage: CoverageReport | None = None
) -> str:
    status = "✅ PASS" if gate.passed else "❌ FAIL"
    out = ["## Summary", ""]
    if coverage is not None:
        out.append(f"- **Scanner coverage:** {coverage.status.value.upper()}")
    if coverage is not None and coverage.status.value != "complete":
        out.append(
            f"- **Finding score (coverage incomplete):** {score.overall:.2f} / 5.00 — "
            f"**{score.letter}**"
        )
    else:
        out.append(f"- **Score:** {score.overall:.2f} / 5.00 — **{score.letter}**")
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


def _categories_table(score: ScoreReport) -> str:
    out = ["## Categories", "", "| Category | Grade | Score | Findings |", "|---|---|---:|---:|"]
    for cat_name, grade_letter, grade_score, count in score.as_table():
        out.append(f"| `{cat_name}` | **{grade_letter}** | {grade_score:.2f} | {count} |")
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
) -> None:
    path.write_text(_pr_comment(findings, score, gate, coverage), encoding="utf-8")


def _pr_comment(
    findings: list[Finding],
    score: ScoreReport,
    gate: GateResult,
    coverage: CoverageReport | None = None,
) -> str:
    status = "✅" if gate.passed else "❌"
    n_crit = score.per_severity_count.get(Severity.CRITICAL, 0)
    n_high = score.per_severity_count.get(Severity.HIGH, 0)
    n_new = sum(1 for f in findings if f.is_new and not f.suppressed)

    incomplete = coverage is not None and coverage.status.value != "complete"
    score_label = "finding score; coverage incomplete" if incomplete else "score"
    out = [
        f"### secure-code-agent {status} — {score_label} **{score.letter}** "
        f"({score.overall:.2f}/5.00)",
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
