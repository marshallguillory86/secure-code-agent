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
from secure_code_audit import pillar as pillar_mod
from secure_code_audit import practice as practice_mod
from secure_code_audit.findings import Category, Finding, Severity
from secure_code_audit.git_tools import find_repo_root, is_excluded, is_test_path, loc_under
from secure_code_audit.scanner_status import (
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
    execution_from_result,
)
from secure_code_audit.scanners import floor
from secure_code_audit.scoring import (
    active_gates,
    evaluate_gates,
    partition_by_tree,
    split_side_axes,
    summarize_axis,
)
from secure_code_audit.scoring import score as score_findings
from secure_code_audit.scoring import verdict as build_verdict


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
        default=None,
        help="Path to config. If omitted, secure-code-agent.json is used when present.",
    )

    p.add_argument("--output", help="Markdown report output path.")
    p.add_argument("--json-output", help="Canonical JSON output path.")
    p.add_argument("--sarif-output", help="SARIF 2.1.0 output path.")
    p.add_argument("--comment-output", help="PR-comment markdown output path.")
    p.add_argument("--prompt-output", help="Remediation prompt output path.")
    p.add_argument(
        "--security-pillar",
        help=(
            "Write security-pillar.json for maintainability-agent to ingest "
            "via --security-pillar (D3). Carries practice level and code "
            "condition as two values that are never averaged."
        ),
    )
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
        metavar="[NAME=]PATH",
        help=(
            "External SARIF file to ingest; counts toward scanner coverage. "
            "Prefix with NAME= when the tool's SARIF driver name differs from "
            "its id in gates.require_scanners. May be passed multiple times."
        ),
    )

    p.add_argument(
        "--trust-target-config",
        action="store_true",
        help=(
            "Allow a config inside the audited tree to name executables from "
            "that tree. Only for repositories you own. CLI-only by design: a "
            "config file cannot grant itself this."
        ),
    )

    p.add_argument(
        "--preflight",
        action="store_true",
        help=(
            "Resolve enabled scanners and report availability without auditing. "
            "Exits nonzero if a required scanner cannot be resolved."
        ),
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
        return _do_preflight(args) if args.preflight else _do_audit(args)
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


def _do_preflight(args: argparse.Namespace) -> int:
    """Report which scanners resolve, without auditing anything.

    Resolution only. A scanner that resolves here can still time out or fail
    during a real audit, which is why coverage is evaluated per run and not
    cached from this command.
    """
    cfg, target, _ = _prepare_audit(args)
    inventory = _repository_inventory(target, cfg)
    required = {
        name
        for name in floor.expand_required(cfg.gates.get("require_scanners", []))
        if floor.applies_to_repository(name, *inventory)
    }
    selected = _selected_scanners(args, cfg)

    rows: list[dict] = []
    for name in selected:
        scanner = scanners.SCANNERS[name]()
        scanner.configure(target, cfg)
        available = scanner.is_available()
        rows.append(
            {
                "scanner": name,
                "required": name in required,
                "available": available,
                "command": " ".join(scanner.command) or None,
                "version": scanner.binary_version() if available else None,
                "remedy": None if available else scanner.unavailable_fix_hint(),
            }
        )

    unresolved = [row["scanner"] for row in rows if row["required"] and not row["available"]]
    unselected = sorted(required - set(selected))
    blocking = unresolved + unselected

    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "required": sorted(required),
                    "scanners": rows,
                    "required_unresolved": unresolved,
                    "required_not_selected": unselected,
                    "ready": not blocking,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        _print_preflight(rows, unselected, blocking)
    return 1 if blocking else 0


def _print_preflight(rows: list[dict], unselected: list[str], blocking: list[str]) -> None:
    print(f"secure-code-agent preflight  ·  {len(rows)} scanner(s) enabled")
    for row in rows:
        mark = "✓" if row["available"] else "✗"
        role = "required" if row["required"] else "optional"
        detail = row["version"] or row["command"] or "not resolved"
        print(f"  {mark} {row['scanner']:<14} {role:<8} {detail}")
        if row["remedy"]:
            print(f"      → {row['remedy']}")
    for name in unselected:
        print(f"  ✗ {name:<14} required  not enabled in this configuration")
    # Named, not omitted: a floor tool this run does not evaluate is a stated
    # scope decision, and silence would read as a pass.
    for name in floor.REPOSITORY_CADENCE_NAMES:
        print(f"  · {name:<14} deferred  repository cadence; supplied by SARIF import (D3)")
    if blocking:
        print(f"  required scanners unavailable: {', '.join(blocking)}")
    else:
        print("  all required scanners resolved")


def _do_audit(args: argparse.Namespace) -> int:
    cfg, target, root = _prepare_audit(args)
    _require_configured_gates(args, cfg)

    # ----- scanners -----
    scan = _run_scanners(args, cfg, target)
    all_findings = scan.findings
    ran, unavailable, executions = scan.ran, scan.unavailable, scan.executions

    # ----- SARIF imports -----
    # An imported SARIF is coverage: a scanner someone else ran on our behalf.
    imported, imported_executions = _ingest_sarif_imports(args.sarif_import)
    all_findings.extend(imported)
    executions.extend(imported_executions)

    # ----- scan scope, enforced once -----
    all_findings = _drop_excluded(all_findings, target, cfg)

    # ----- overrides from config -----
    all_findings = _apply_overrides(all_findings, cfg)

    # ----- suppressions -----
    suppression_path = _under_root(root, cfg.suppressions_file)
    sup_rules, sup_errors = suppressions.load(suppression_path)
    if sup_errors:
        # Fail closed. A suppression file that exists is an explicit
        # instruction; ignoring it silently changes which findings are
        # reported, and "my suppressions are working" then looks exactly
        # like "my suppressions were skipped". This bit in practice: a
        # missing PyYAML made an entire .scignore.yaml a no-op while the
        # run still exited 0 and reported the suppressed finding as live.
        #
        # Only reachable when the file is present, so repositories that
        # do not use suppressions are unaffected.
        for err in sup_errors:
            sys.stderr.write(f"ERROR: {err}\n")
        sys.stderr.write(
            f"ERROR: {suppression_path} exists but could not be applied; refusing to "
            "report results that silently ignore it.\n"
        )
        return 1
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
    # The test tree is reported, not scored. A project graded on its test
    # fixtures is graded on the wrong thing: across the calibration corpus,
    # including test directories moved the median normalized subtotal from
    # 4.36 to 50.15 and put ten of fourteen well-maintained projects at F.
    # Secrets are exempt and stay in the score — see ALWAYS_SCORED_CATEGORIES.
    root_for_tests = target if target.is_dir() else target.parent
    all_findings, test_findings = partition_by_tree(
        all_findings,
        lambda f: is_test_path(f.file_path, root_for_tests, cfg.test_patterns),
    )
    if cfg.loc_for_scoring:
        loc = int(cfg.loc_for_scoring.get("value", 0))
        test_loc = 0
    else:
        loc, test_loc = loc_under(
            target, cfg.include_extensions, cfg.exclude_patterns, cfg.test_patterns
        )
    # Dependencies come off the code-condition score and onto their own axis.
    # A CVE in a pinned dependency is fixed with a version bump; an injection
    # flaw is fixed with a rewrite. Averaging them produced the largest
    # remaining distortion in the corpus — median 15.36 against 7.32.
    #
    # The split is between *scoring* and *gating*, not between reported and
    # hidden: `gated_findings` keeps the dependency advisories, so a critical
    # runtime CVE still fails a build exactly as before.
    gated_findings = all_findings
    scored_findings, dependency_findings = split_side_axes(all_findings)
    score = score_findings(scored_findings, loc)
    test_tree = summarize_axis("test tree", test_findings, test_loc)
    dependencies = summarize_axis("dependencies", dependency_findings)
    axes = (test_tree, dependencies)
    # Naming an import on the command line asserts that it contributes coverage,
    # so a broken one fails the gate even if no config requires that scanner.
    # Requiring a tool that has nothing to look at would make every
    # single-language repository permanently incomplete, and an alarm that is
    # always on is not an alarm. Applicability is decided from what the tree
    # actually contains, before the requirement is asserted.
    inventory = _repository_inventory(target, cfg)
    required = [
        *(
            name
            for name in floor.expand_required(cfg.gates.get("require_scanners", []))
            if floor.applies_to_repository(name, *inventory)
        ),
        *(execution.name for execution in imported_executions),
    ]
    coverage = evaluate_coverage(executions, required)
    # Gates see the dependency advisories; the score does not.
    gate = evaluate_gates(gated_findings, score, cfg.gates, coverage)
    verdict = build_verdict(score, cfg.gates, coverage)

    # ----- write outputs -----
    paths = _resolve_outputs(args, cfg, root)
    # The pillar artifact is what maintainability-agent ingests (D3). Built
    # here rather than inside a renderer because it needs the practice level,
    # which is read from configuration and CI rather than from findings.
    security_pillar = pillar_mod.build(score, verdict, coverage, practice_mod.assess(target), axes)
    _write_outputs(
        paths,
        all_findings,
        score,
        gate,
        coverage,
        ran,
        unavailable,
        verdict,
        axes,
        security_pillar,
    )
    if args.bump_baseline:
        baseline_mod.write(baseline_path, all_findings, baseline)

    # ----- terminal output -----
    if args.json:
        sys.stdout.write(
            json.dumps(
                renderers.to_json(all_findings, score, gate, coverage, verdict, axes), indent=2
            )
        )
        sys.stdout.write("\n")
    else:
        _print_summary(verdict, score, gate, ran, unavailable, coverage, paths, axes)

    return _exit_code(args, gate, all_findings)


def _prepare_audit(
    args: argparse.Namespace,
) -> tuple[config_mod.Config, Path, Path]:
    """Load config and resolve the single scan root, or refuse."""
    if args.changed_only:
        raise ValueError(
            "--changed-only is not implemented safely; refusing to claim a scoped audit"
        )
    if len(args.paths) > 1:
        raise ValueError("multiple scan roots are not supported; provide one repository root")
    # The target is resolved first because the default config belongs to it.
    target = Path(args.paths[0]).resolve()
    cfg = config_mod.load(args.config, default_root=target)
    # Set from the command line only. Threading it through the loaded config
    # would let a repository-supplied file assert its own trustworthiness.
    cfg.trust_target_config = bool(getattr(args, "trust_target_config", False))
    _validate_scanner_config(cfg)
    return cfg, target, find_repo_root(target)


def _require_configured_gates(args: argparse.Namespace, cfg: config_mod.Config) -> None:
    """Refuse --fail-on-gate when no gate could ever fail.

    Without this, an audit that detects a HIGH finding, scores it 0.00/F, and
    reports it in full still exits 0, because every gate is absent and an
    absent gate does not trip. That is a green build with no security floor,
    and it is the shape a default Action adoption takes.
    """
    if not args.fail_on_gate or active_gates(cfg.gates):
        return
    raise ValueError(
        "--fail-on-gate was requested but no gate is configured, so no finding "
        "could ever fail the build. Configure at least one of "
        "gates.fail_on_severity, gates.fail_on_category, gates.fail_on_new, "
        "gates.min_score (above 0), gates.require_scanners, or "
        "gates.max_unsuppressed — see secure-code-agent.example.json. Drop "
        "--fail-on-gate to run an ungated, report-only audit."
    )


def _exit_code(args: argparse.Namespace, gate, findings: list[Finding]) -> int:
    if args.fail_on_gate and not gate.passed:
        return 1
    if args.fail_on_new and any(
        f.is_new and not f.suppressed and f.severity is not Severity.INFORMATIONAL for f in findings
    ):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _ScanResult:
    findings: list[Finding]
    ran: list[str]
    unavailable: list[str]
    executions: list[ScannerExecution]


def _repository_inventory(target: Path, cfg: config_mod.Config) -> tuple[set[str], set[str]]:
    """Extensions and notable filenames present in the tree, for applicability.

    Bounded by the same exclusions the scan uses, so a vendored manifest does
    not make a whole ecosystem look present.
    """
    from secure_code_audit.git_tools import is_excluded

    extensions: set[str] = set()
    filenames: set[str] = set()
    for path in target.rglob("*"):
        if not path.is_file() or is_excluded(path, target, cfg.exclude_patterns):
            continue
        extensions.add(path.suffix)
        filenames.add(path.name)
    return extensions, filenames


def _scanner_enabled(cfg: config_mod.Config, name: str) -> bool:
    """Whether this scanner runs, with the floor supplying the default.

    A configuration that says nothing about a scanner gets the project's
    declared opinion: floor tools run, opt-in tools do not. Previously every
    registered scanner defaulted to enabled, which quietly turned overlapping
    and copyleft tools on for operators who never chose them.
    """
    configured = cfg.scanners.get(name)
    # `cfg.scanners` only holds scanners the configuration actually named, so
    # presence here is the operator having an opinion.
    return configured.enabled if configured is not None else floor.default_enabled(name)


def _selected_scanners(args: argparse.Namespace, cfg: config_mod.Config) -> list[str]:
    """Names the operator actually asked for, in registry order."""
    skip = set(filter(None, (args.skip_scanners or "").split(",")))
    only = set(filter(None, (args.only_scanners or "").split(",")))
    return [
        name
        for name in scanners.SCANNERS
        if not (only and name not in only) and name not in skip and _scanner_enabled(cfg, name)
    ]


def _drop_excluded(findings: list[Finding], target: Path, cfg: config_mod.Config) -> list[Finding]:
    """Enforce `paths.exclude_patterns` on findings, not just on file discovery.

    Five of fifteen adapters push the exclusion down to their tool; the rest
    have no flag for it, or read it from a config file in the audited tree that
    D1 forbids us honouring. So the setting was true for Bandit and a polite
    fiction for Checkov, RuboCop, Trivy, Semgrep and the others.

    That is worse than cosmetic, because `exclude_patterns` is *also* the
    denominator: `loc_under()` counts only non-excluded files while the
    findings counted against them came from everywhere. A repository excluding
    its vendored tree was scored on vendored findings over first-party lines —
    the numerator and denominator measuring different repositories.

    Pushing the exclusion into each adapter is still worth doing for speed and
    for smaller tool output. Correctness is enforced here, once, where every
    finding passes regardless of which adapter or SARIF import produced it.

    Control findings are exempt: they carry the scan root as their path, and
    dropping "bandit could not run" because the root matched a pattern would
    turn a failed scanner back into a silent one — the defect this whole
    project exists to prevent.
    """
    if not cfg.exclude_patterns:
        return findings

    root = target if target.is_dir() else target.parent
    kept: list[Finding] = []
    for finding in findings:
        path = finding.file_path
        is_control = path in (target, root)
        if not is_control and is_excluded(path, root, cfg.exclude_patterns):
            continue
        kept.append(finding)
    return kept


def _run_scanners(args: argparse.Namespace, cfg: config_mod.Config, target: Path) -> _ScanResult:
    result = _ScanResult(findings=[], ran=[], unavailable=[], executions=[])
    for name in _selected_scanners(args, cfg):
        scanner = scanners.SCANNERS[name]()
        scanner.configure(target, cfg)
        available = scanner.is_available()
        if not available:
            result.unavailable.append(name)
        version = scanner.binary_version() if available else None
        scan = scanner.scan(target, cfg)
        result.findings.extend(scan.findings)
        execution = execution_from_result(
            name,
            scan,
            command=scanner.command if available else (),
            version=version,
        )
        result.executions.append(execution)
        if execution.outcome is ScannerOutcome.COMPLETED:
            result.ran.append(name)
    return result


def _parse_sarif_import(spec: str) -> tuple[str | None, Path]:
    """Split an optional `NAME=` prefix off a --sarif-import value.

    Only a leading token with no path separator counts as a name, so ordinary
    paths that happen to contain '=' still resolve as paths.
    """
    name, separator, remainder = spec.partition("=")
    if separator and name and not any(sep in name for sep in ("/", "\\", ".")):
        return name, Path(remainder)
    return None, Path(spec)


def _ingest_sarif_imports(specs: list[str]) -> tuple[list[Finding], list[ScannerExecution]]:
    findings: list[Finding] = []
    executions: list[ScannerExecution] = []
    for spec in specs:
        name, sarif_path = _parse_sarif_import(spec)
        imported, imported_executions = sarif.ingest_with_coverage(
            sarif_path, override_scanner=name
        )
        findings.extend(imported)
        executions.extend(imported_executions)
    return findings, executions


def _write_outputs(
    paths, findings, score, gate, coverage, ran, unavailable, verdict, axes=(), pillar=None
) -> None:
    if paths.markdown is not None:
        renderers.write_markdown(
            findings, score, gate, paths.markdown, ran, unavailable, coverage, verdict, axes
        )
    if paths.json_out is not None:
        renderers.write_json(findings, score, gate, paths.json_out, coverage, verdict, axes)
    if paths.sarif is not None:
        sarif.write(findings, paths.sarif, coverage)
    if paths.comment is not None:
        renderers.write_pr_comment(findings, score, gate, paths.comment, coverage, verdict)
    if paths.prompt is not None:
        remediation.write(findings, paths.prompt)
    # The artifact maintainability-agent ingests (D3). Written last because it
    # is the only output that carries both axes plus the practice level.
    if paths.security_pillar is not None and pillar is not None:
        pillar_mod.write(pillar, paths.security_pillar)


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
    security_pillar: Path | None


def _resolve_outputs(args: argparse.Namespace, cfg: config_mod.Config, root: Path) -> _OutputPaths:
    """CLI flags override config defaults. A flag value of None means
    'don't emit this format' — by default we emit Markdown only, and
    other outputs are opt-in via CLI flag or explicit config."""

    def _p(flag_value) -> Path | None:
        if flag_value is not None:
            return (root / flag_value).resolve()
        return None

    return _OutputPaths(
        markdown=_p(args.output or cfg.outputs.get("markdown_path")),
        json_out=_p(args.json_output),
        sarif=_p(args.sarif_output),
        comment=_p(args.comment_output),
        prompt=_p(args.prompt_output),
        security_pillar=_p(args.security_pillar),
    )


def _under_root(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _print_summary(verdict, score, gate, ran, unavailable, coverage, paths, axes=()) -> None:
    status = "PASS" if gate.passed else "FAIL"
    print(f"secure-code-agent  ·  score {verdict.headline()}  ·  gate {status}")
    for reason in verdict.reasons:
        print(f"  ! grade withheld: {reason}")
    print(f"  scanned LOC: {score.loc_scanned:,}")
    for axis in axes or ():
        if axis.count or axis.loc:
            print(f"  {axis.headline()}")
    print(f"  scanners run: {', '.join(ran) if ran else '(none)'}")
    coverage_line = f"  coverage: {coverage.status.value.upper()}"
    if coverage.unverified:
        coverage_line += (
            f"  ({len(coverage.unverified)} unverified: {', '.join(coverage.unverified)})"
        )
    print(coverage_line)
    if unavailable:
        print(f"  unavailable: {', '.join(unavailable)}")
    if not gate.passed:
        for reason in gate.reasons:
            print(f"  ✗ {reason}")
    written = [
        str(p)
        for p in (
            paths.markdown,
            paths.json_out,
            paths.sarif,
            paths.comment,
            paths.prompt,
            paths.security_pillar,
        )
        if p is not None
    ]
    if written:
        print(f"  wrote: {', '.join(written)}")


def _validate_scanner_config(cfg: config_mod.Config) -> None:
    known = set(scanners.SCANNERS)
    unknown = sorted(set(cfg.scanners) - known)
    if unknown:
        raise ValueError(f"unknown scanner configuration: {', '.join(unknown)}")
    # Expand the `floor` token before validating, so requiring the declared
    # minimum does not read as a typo'd scanner name.
    required = set(floor.expand_required(cfg.gates.get("require_scanners", [])))
    unknown_required = sorted(required - known)
    if unknown_required:
        raise ValueError(f"unknown required scanner: {', '.join(unknown_required)}")


if __name__ == "__main__":
    sys.exit(main())
