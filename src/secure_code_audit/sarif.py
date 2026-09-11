"""SARIF 2.1.0 emit + ingest.

Spec: https://www.oasis-open.org/standard/sarif-v2-1-0/
SARIF JSON schema (OASIS canonical; the oasis-tcs raw URL 404s): https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from secure_code_audit import __version__
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import (
    CoverageReport,
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
)
from secure_code_audit.standards import cwe_url

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}


def emit(
    findings: Iterable[Finding],
    coverage: CoverageReport | None = None,
    axis_of=lambda _f: "primary",
) -> dict:
    """Build a SARIF 2.1.0 document from canonical findings."""
    findings = list(findings)

    # Build the rules array per-canonical-rule (rule_id is local; dedupe).
    rule_meta: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = f.rule_id
        if rid not in rule_meta:
            rule_meta[rid] = _rule(f)
        results.append(_result(f, axis_of(f)))

    run = {
        "tool": {
            "driver": {
                "name": "secure-code-agent",
                "informationUri": "https://github.com/marshallguillory86/secure-code-agent",
                "version": __version__,
                "rules": list(rule_meta.values()),
            }
        },
        "results": results,
    }
    if coverage is not None:
        run["invocations"] = [_invocation(coverage)]

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def _invocation(coverage: CoverageReport) -> dict:
    invocation = {
        "executionSuccessful": coverage.status is CoverageStatus.COMPLETE,
        "properties": {
            "coverageStatus": coverage.status.value,
            "requiredScanners": list(coverage.required),
            "unverifiedScanners": list(coverage.unverified),
            "scannerExecutions": [
                {
                    "name": execution.name,
                    "outcome": execution.outcome.value,
                    "scope": execution.scope,
                }
                for execution in coverage.executions
            ],
        },
    }
    if coverage.failures:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {"text": failure},
                "descriptor": {"id": "scanner-coverage"},
            }
            for failure in coverage.failures
        ]
    return invocation


def _rule(f: Finding) -> dict:
    rule: dict = {
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": {"text": f.short_desc or f.message[:120]},
        "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
        "properties": {
            "category": f.category.value,
            "scanner": f.scanner,
            "owasp_top10": f.owasp_top10,
            "asvs": f.asvs_section,
            "nist_ssdf": f.nist_ssdf,
            "cwe_top25": f.cwe_top25,
        },
    }
    if f.canonical_cwe:
        rule["properties"]["cwe"] = [f.canonical_cwe]
        rule["helpUri"] = cwe_url(f.canonical_cwe)
    return rule


#: Axes whose findings are reported but are not defects to raise an alert
#: for. Same set the work order files under §ACCEPT.
_SIDE_AXES = frozenset({"test tree", "documentation"})


def _suppressions(f: Finding, axis: str) -> list[dict] | None:
    """The SARIF-standard suppression array, or None to raise an alert.

    SARIF is consumed by code-scanning platforms that turn each result into
    an alert, and `suppressions` is the field they honour. We were writing
    `properties.suppressed` instead — a field of our own invention that no
    consumer reads — so two kinds of finding raised alerts they should not:

    * findings the operator had explicitly suppressed in `.scignore.yaml`,
      with a reason and an expiry, which is as clear a "do not alert me
      about this" as exists;
    * and every test-tree and documentation finding, which the product
      itself reports as "not scored" and the work order files under §ACCEPT
      with "do not patch these".

    Auditing `maintainability-agent` produced 4,929 SARIF results of which
    **4,847 were test fixtures**. Uploaded to code scanning that is 4,847
    alerts for deliberately-vulnerable test data, burying the 82 findings in
    the shipped source.

    Suppressed, not omitted. The finding stays in the file with its
    location and justification, so nothing is hidden from a reader — it
    simply does not become someone's ticket.
    """
    if f.suppressed:
        return [
            {
                "kind": "external",
                "justification": f.suppression_note or "suppressed by operator configuration",
            }
        ]
    if axis in _SIDE_AXES:
        return [
            {
                "kind": "external",
                "justification": (
                    f"reported on the {axis} axis: outside the shipped source, "
                    f"not scored as code condition, and not a patch target"
                ),
            }
        ]
    return None


def _result(f: Finding, axis: str = "primary") -> dict:
    region: dict = {"startLine": max(1, f.line_start)}
    if f.line_end and f.line_end != f.line_start:
        region["endLine"] = f.line_end
    if f.code_snippet:
        region["snippet"] = {"text": f.code_snippet}

    result = {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f.message},
        "fingerprints": {"secure-code-agent/v1": f.fingerprint},
        "properties": {
            "confidence": f.confidence.value,
            "category": f.category.value,
            "is_new": f.is_new,
            "suppressed": f.suppressed,
            "axis": axis,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path.as_posix()},
                    "region": region,
                }
            }
        ],
    }
    suppressions = _suppressions(f, axis)
    if suppressions:
        result["suppressions"] = suppressions
    return result


def write(
    findings: Iterable[Finding],
    output: Path,
    coverage: CoverageReport | None = None,
    axis_of=lambda _f: "primary",
) -> None:
    output.write_text(json.dumps(emit(findings, coverage, axis_of), indent=2), encoding="utf-8")


# ----- ingest -------------------------------------------------------------

_SARIF_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}


def ingest(sarif_path: Path, default_scanner: str = "external_sarif") -> list[Finding]:
    """Parse an external SARIF file (CodeQL, Snyk, Trivy, etc.) into canonical
    Findings. We trust the SARIF's own rule metadata for severity + CWE;
    standards.lookup() may still enhance via the local map."""
    findings, _ = ingest_with_coverage(sarif_path, default_scanner)
    return findings


def ingest_with_coverage(
    sarif_path: Path,
    default_scanner: str = "external_sarif",
    override_scanner: str | None = None,
) -> tuple[list[Finding], list[ScannerExecution]]:
    """Ingest an external SARIF file and report what it covered.

    A scanner that runs in CI and hands us SARIF is as much a coverage
    participant as one we invoke ourselves, so imports produce executions that
    can satisfy `gates.require_scanners`. An unreadable, malformed, or empty
    import is a coverage failure, never a silently empty finding set.

    `override_scanner` names the run explicitly when a tool's SARIF driver name
    does not match the id used in configuration.
    """
    scope = f"sarif-import:{sarif_path.name}"
    fallback = override_scanner or default_scanner
    payload, error = _read_sarif(sarif_path)
    if error is None and not (payload.get("runs") or []):
        error = f"imported SARIF {sarif_path} declares no runs; nothing was covered"
    if error is not None:
        return (
            [_import_control_finding(sarif_path, fallback, error)],
            [
                ScannerExecution(
                    name=fallback,
                    outcome=ScannerOutcome.FAILED,
                    reason=error,
                    scope=scope,
                )
            ],
        )

    findings: list[Finding] = []
    executions: list[ScannerExecution] = []
    for index, run in enumerate(payload["runs"]):
        if not isinstance(run, dict):
            message = (
                f"imported SARIF {sarif_path} run #{index} is {type(run).__name__}, not an object"
            )
            findings.append(_import_control_finding(sarif_path, fallback, message))
            executions.append(
                ScannerExecution(
                    name=fallback,
                    outcome=ScannerOutcome.FAILED,
                    reason=message,
                    scope=scope,
                )
            )
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        name = override_scanner or _scanner_name(driver, default_scanner)
        results = run.get("results")
        if results is not None and not isinstance(results, list):
            message = (
                f"imported {name} SARIF run #{index} has a "
                f"{type(results).__name__} 'results', not an array"
            )
            findings.append(_import_control_finding(sarif_path, name, message))
            executions.append(
                ScannerExecution(
                    name=name,
                    outcome=ScannerOutcome.FAILED,
                    reason=message,
                    scope=scope,
                )
            )
            continue
        run_findings = _findings_from_run(run, name)
        findings.extend(run_findings)
        executions.append(_execution_from_run(run, name, len(run_findings), scope))
    return findings, executions


def _execution_from_run(run: dict, name: str, finding_count: int, scope: str) -> ScannerExecution:
    """Classify an imported run by provenance, not by self-description.

    We did not watch this process. Even `executionSuccessful: true` is a file
    describing itself, so a successful import is UNVERIFIED rather than
    COMPLETED — the operator vouched for it, we did not observe it. A run that
    declares its own failure is still FAILED: we do not launder that regardless
    of where it came from.
    """
    driver = (run.get("tool") or {}).get("driver") or {}
    invocations = run.get("invocations") or []
    declared_failure = any(
        isinstance(invocation, dict) and invocation.get("executionSuccessful") is False
        for invocation in invocations
    )
    if declared_failure:
        return ScannerExecution(
            name=name,
            outcome=ScannerOutcome.FAILED,
            version=driver.get("version"),
            reason=f"imported {name} SARIF reports executionSuccessful=false",
            scope=scope,
        )
    return ScannerExecution(
        name=name,
        outcome=ScannerOutcome.UNVERIFIED,
        version=driver.get("version"),
        finding_count=finding_count,
        reason="coverage from an imported artifact; execution was not observed",
        scope=scope,
    )


def _import_control_finding(sarif_path: Path, scanner: str, message: str) -> Finding:
    return Finding(
        rule_id=f"{scanner}.tool_error",
        scanner=scanner,
        fingerprint=f"sarif_import_error.{sarif_path.name}",
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.POLICY_DOCS,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        file_path=sarif_path,
        line_start=0,
        line_end=None,
        code_snippet=None,
        message=message,
        short_desc=None,
        fix_hint=(
            "Regenerate the imported SARIF, or drop the --sarif-import argument "
            "rather than gating on coverage it cannot supply."
        ),
    )


def _read_sarif(path: Path) -> tuple[dict, str | None]:
    """Return the parsed document, or an operator-readable reason it failed."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, f"could not read imported SARIF {path}: {exc}"
    except json.JSONDecodeError as exc:
        return {}, f"imported SARIF {path} is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return {}, f"imported SARIF {path} root must be a JSON object"
    return payload, None


def _scanner_name(driver: dict, default_scanner: str) -> str:
    """Normalize a SARIF driver name toward this project's scanner ids.

    Drivers spell themselves inconsistently ("OSV-Scanner", "npm audit"), so
    separators are folded. A driver that still does not match the id used in
    `gates.require_scanners` can be named explicitly via `--sarif-import
    NAME=PATH`.
    """
    raw = driver.get("name") or default_scanner
    return raw.strip().lower().replace(" ", "_").replace("-", "_")


def _findings_from_run(run: dict, scanner: str) -> list[Finding]:
    """`scanner` is the already-resolved id, so findings and the coverage
    execution for the same run can never disagree about who produced them."""
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = {r.get("id"): r for r in (driver.get("rules") or []) if isinstance(r, dict)}

    findings: list[Finding] = []
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            continue  # a non-object result carries nothing we can normalize
        findings.append(_finding_from_result(result, rules, scanner))
    return findings


def _finding_from_result(result: dict, rules: dict, scanner: str) -> Finding:
    from secure_code_audit.findings import Category
    from secure_code_audit.standards import is_top25, lookup

    rule_id = result.get("ruleId") or "unknown"
    rule = rules.get(rule_id, {})
    msg = (result.get("message") or {}).get("text") or rule_id

    severity = _severity_from_result(result, rule)
    cwe = _cwe_from_rule(rule)
    file_path, line_start, line_end, snippet = _location_from_result(result)

    entry = lookup(scanner, rule_id)
    canonical_cwe = cwe or (entry.canonical_cwe if entry else None)

    fingerprint = Finding.make_fingerprint(
        canonical_cwe=canonical_cwe,
        rule_id=rule_id,
        file_path=file_path,
        code_snippet=snippet,
    )
    return Finding(
        rule_id=rule_id,
        scanner=scanner,
        fingerprint=fingerprint,
        canonical_cwe=canonical_cwe,
        owasp_top10=entry.owasp_top10 if entry else None,
        asvs_section=entry.asvs_section if entry else None,
        nist_ssdf=entry.nist_ssdf if entry else None,
        category=entry.category if entry else Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.MEDIUM,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end if line_end and line_end != line_start else None,
        code_snippet=snippet,
        message=msg,
        short_desc=entry.short_desc if entry else None,
        fix_hint=entry.fix_hint if entry else None,
        cwe_top25=is_top25(canonical_cwe),
    )


def _severity_from_result(result: dict, rule: dict) -> Severity:
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return _SARIF_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)


def _cwe_from_rule(rule: dict) -> str | None:
    props = rule.get("properties") or {}
    cwe = props.get("cwe")
    if isinstance(cwe, list) and cwe:
        return cwe[0]
    if isinstance(cwe, str):
        return cwe
    return None


def _location_from_result(result: dict) -> tuple[Path, int, int | None, str | None]:
    locs = result.get("locations") or [{}]
    phys = (locs[0].get("physicalLocation") or {}) if locs else {}
    file_uri = (phys.get("artifactLocation") or {}).get("uri") or ""
    region = phys.get("region") or {}
    line_start = int(region.get("startLine") or 0)
    line_end = int(region.get("endLine") or line_start) if region else None
    snippet = (region.get("snippet") or {}).get("text")
    file_path = Path(file_uri) if file_uri else Path(".")
    return file_path, line_start, line_end, snippet
