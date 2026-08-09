"""CLI entrypoint — `secure-code-agent` and `secure-code-audit`.

Wires together: config load → scanner runs → suppressions → baseline diff →
scoring → gate evaluation → render outputs.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from secure_code_audit import (
    __version__,
    instructions,
    remediation,
    renderers,
    sarif,
    scanners,
    suppressions,
)
from secure_code_audit import baseline as baseline_mod
from secure_code_audit import config as config_mod
from secure_code_audit.findings import Category, Finding, Severity
from secure_code_audit.git_tools import find_repo_root, loc_under
from secure_code_audit.scanner_status import classify_execution, evaluate_coverage
from secure_code_audit.scoring import evaluate_gates
from secure_code_audit.scoring import score as score_findings


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-code-agent",
        description="Deterministic security gate + bounded AI remediation prompts.",
    )
    p.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="One scan root. Defaults to the current directory.",
    )
    p.add_argument(
        "--config",
        default="secure-code-agent.json",
        help="Path to config (default: secure-code-agent.json).",
    )

    p.add_argument("--output", help="Markdown report output path.")
    p.add_argument("--json-output", help="Canonical JSON output path.")
    p.add_argument("--sarif-output", help="SARIF 2.1.0 output path.")
    p.add_argument("--comment-output", help="PR-comment markdown output path.")
    p.add_argument("--prompt-output", help="Remediation prompt output path.")
    p.add_argument("--baseline", help="Baseline file path (read).")
    p.add_argument(
        "--bump-baseline", action="store_true", help="Rewrite the baseline from current findings."
    )

    p.add_argument("--fail-on-gate", action="store_true", help="Exit nonzero if any gate trips.")
    p.add_argument(
        "--fail-on-new", action="store_true", help="Exit nonzero on findings not in baseline."
    )

    p.add_argument("--changed-only", help="Audit only files changed since REF (e.g. main...HEAD).")
    p.add_argument("--skip-scanners", help="Comma-separated scanner names to skip.")
    p.add_argument("--only-scanners", help="Comma-separated scanner names — only these run.")
    p.add_argument(
        "--severity-threshold",
        default="informational",
        choices=[s.value for s in Severity],
        help="Filter findings below this severity.",
    )

    p.add_argument(
        "--sarif-import",
        action="append",
        default=[],
        help="Path to an external SARIF file to ingest. May be passed multiple times.",
    )

    p.add_argument(
        "--init-agent-standards",
        action="store_true",
        help="Emit per-agent standards files instead of running an audit.",
    )
    p.add_argument(
        "--target",
        action="append",
        default=[],
        help="Target for --init-agent-standards (codex, claude-code, cursor, copilot, windsurf, generic).",
    )
    p.add_argument(
        "--instructions-output-dir",
        default=".",
        help="Output directory for --init-agent-standards.",
    )

    p.add_argument(
        "--json",
        action="store_true",
        help="Print canonical JSON to stdout (suppresses other terminal output).",
    )
    p.add_argument("--version", action="version", version=f"secure-code-agent {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.init_agent_standards:
        return _do_init_standards(args)

    try:
        return _do_audit(args)
    except ValueError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2


def _do_init_standards(args: argparse.Namespace) -> int:
    targets = args.target or instructions.known_targets()
    out_dir = Path(args.instructions_output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for t in targets:
        path = instructions.write_for_target(t, out_dir)
        print(f"wrote {path}")
    return 0


def _do_audit(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    _validate_scanner_config(cfg)
    if args.changed_only:
        raise ValueError(
            "--changed-only is not implemented safely; refusing to claim a scoped audit"
        )
    if len(args.paths) > 1:
        raise ValueError("multiple scan roots are not supported; provide one repository root")
    target = Path(args.paths[0]).resolve()
    root = find_repo_root(target)

    # ----- scanners -----
    skip = set(filter(None, (args.skip_scanners or "").split(",")))
    only = set(filter(None, (args.only_scanners or "").split(",")))
    all_findings: list[Finding] = []
    ran: list[str] = []
    unavailable: list[str] = []
    executions = []

    for name, klass in scanners.SCANNERS.items():
        if only and name not in only:
            continue
        if name in skip:
            continue
        sc_cfg = cfg.scanners.get(name) or config_mod.ScannerConfig()
        if not sc_cfg.enabled:
            continue
        scanner = klass()
        scanner.configure(target, cfg)
        if not scanner.is_available():
            unavailable.append(name)
            scanner_findings = scanner.run(target, cfg)
            all_findings.extend(scanner_findings)
            executions.append(classify_execution(name, scanner_findings))
            continue
        version = scanner.binary_version()
        scanner_findings = scanner.run(target, cfg)
        all_findings.extend(scanner_findings)
        execution = classify_execution(
            name,
            scanner_findings,
            command=scanner.command,
            version=version,
        )
        executions.append(execution)
        if execution.outcome.value == "completed":
            ran.append(name)

    # ----- SARIF imports -----
    for sarif_path_str in args.sarif_import:
        all_findings.extend(sarif.ingest(Path(sarif_path_str)))

    # ----- overrides from config -----
    all_findings = _apply_overrides(all_findings, cfg)

    # ----- suppressions -----
    suppression_path = _under_root(root, cfg.suppressions_file)
    sup_rules, sup_errors = suppressions.load(suppression_path)
    if sup_errors:
        for err in sup_errors:
            sys.stderr.write(f"WARN: {err}\n")
    all_findings = suppressions.apply(all_findings, sup_rules)
    all_findings.extend(suppressions.expired_findings(sup_rules, suppression_path))

    # ----- severity threshold filter -----
    threshold = Severity.from_string(args.severity_threshold)
    all_findings = [f for f in all_findings if f.severity.rank >= threshold.rank]

    # ----- baseline -----
    baseline_path = _under_root(root, args.baseline or cfg.outputs["baseline_path"])
    baseline = baseline_mod.load(baseline_path)
    all_findings = baseline_mod.mark_new(all_findings, baseline)

    # ----- scoring -----
    if cfg.loc_for_scoring:
        loc = int(cfg.loc_for_scoring.get("value", 0))
    else:
        loc = loc_under(target, cfg.include_extensions, cfg.exclude_patterns)
    score = score_findings(all_findings, loc)
    coverage = evaluate_coverage(executions, cfg.gates.get("require_scanners", []))
    gate = evaluate_gates(all_findings, score, cfg.gates, coverage)

    # ----- write outputs -----
    paths = _resolve_outputs(args, cfg, root)

    if paths.markdown is not None:
        renderers.write_markdown(
            all_findings, score, gate, paths.markdown, ran, unavailable, coverage
        )
    if paths.json_out is not None:
        renderers.write_json(all_findings, score, gate, paths.json_out, coverage)
    if paths.sarif is not None:
        sarif.write(all_findings, paths.sarif)
    if paths.comment is not None:
        renderers.write_pr_comment(all_findings, score, gate, paths.comment, coverage)
    if paths.prompt is not None:
        remediation.write(all_findings, paths.prompt)
    if args.bump_baseline:
        baseline_mod.write(baseline_path, all_findings, baseline)

    # ----- terminal output -----
    if args.json:
        sys.stdout.write(
            json.dumps(renderers.to_json(all_findings, score, gate, coverage), indent=2)
        )
        sys.stdout.write("\n")
    else:
        _print_summary(score, gate, ran, unavailable, coverage, paths)

    # ----- exit code -----
    if args.fail_on_gate and not gate.passed:
        return 1
    if args.fail_on_new and any(
        f.is_new and not f.suppressed and f.severity is not Severity.INFORMATIONAL
        for f in all_findings
    ):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _apply_overrides(findings: list[Finding], cfg: config_mod.Config) -> list[Finding]:
    """Apply config-level severity_overrides + category_overrides."""
    if not cfg.severity_overrides and not cfg.category_overrides:
        return findings
    out: list[Finding] = []
    for f in findings:
        new_severity = f.severity
        if f.rule_id in cfg.severity_overrides:
            new_severity = Severity.from_string(cfg.severity_overrides[f.rule_id])
        new_category = f.category
        if f.rule_id in cfg.category_overrides:
            with contextlib.suppress(ValueError):
                new_category = Category(cfg.category_overrides[f.rule_id])
        out.append(replace(f, severity=new_severity, category=new_category))
    return out


@dataclass(frozen=True)
class _OutputPaths:
    markdown: Path | None
    json_out: Path | None
    sarif: Path | None
    comment: Path | None
    prompt: Path | None


def _resolve_outputs(args: argparse.Namespace, cfg: config_mod.Config, root: Path) -> _OutputPaths:
    """CLI flags override config defaults. A flag value of None means
    'don't emit this format' — by default we emit Markdown only, and
    other outputs are opt-in via CLI flag or explicit config."""

    def _p(flag_value, default_key) -> Path | None:
        if flag_value is not None:
            return (root / flag_value).resolve()
        return None

    return _OutputPaths(
        markdown=_p(args.output or cfg.outputs.get("markdown_path"), "markdown_path"),
        json_out=_p(args.json_output, "json_path"),
        sarif=_p(args.sarif_output, "sarif_path"),
        comment=_p(args.comment_output, "comment_path"),
        prompt=_p(args.prompt_output, "prompt_path"),
    )


def _under_root(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _print_summary(score, gate, ran, unavailable, coverage, paths) -> None:
    status = "PASS" if gate.passed else "FAIL"
    print(f"secure-code-agent  ·  score {score.overall:.2f} ({score.letter})  ·  gate {status}")
    print(f"  scanned LOC: {score.loc_scanned:,}")
    print(f"  scanners run: {', '.join(ran) if ran else '(none)'}")
    print(f"  coverage: {coverage.status.value.upper()}")
    if unavailable:
        print(f"  unavailable: {', '.join(unavailable)}")
    if not gate.passed:
        for reason in gate.reasons:
            print(f"  ✗ {reason}")
    written = [
        str(p)
        for p in (paths.markdown, paths.json_out, paths.sarif, paths.comment, paths.prompt)
        if p is not None
    ]
    if written:
        print(f"  wrote: {', '.join(written)}")


def _validate_scanner_config(cfg: config_mod.Config) -> None:
    known = set(scanners.SCANNERS)
    unknown = sorted(set(cfg.scanners) - known)
    if unknown:
        raise ValueError(f"unknown scanner configuration: {', '.join(unknown)}")
    required = set(cfg.gates.get("require_scanners", []))
    unknown_required = sorted(required - known)
    if unknown_required:
        raise ValueError(f"unknown required scanner: {', '.join(unknown_required)}")


if __name__ == "__main__":
    sys.exit(main())
