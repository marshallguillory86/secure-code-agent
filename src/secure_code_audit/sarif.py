"""SARIF 2.1.0 emit + ingest.

Spec: https://www.oasis-open.org/standard/sarif-v2-1-0/
SARIF JSON schema: https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schemas/sarif-schema-2.1.0.json
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from secure_code_audit import __version__
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.standards import cwe_url

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}


def emit(findings: Iterable[Finding]) -> dict:
    """Build a SARIF 2.1.0 document from canonical findings."""
    findings = list(findings)

    # Build the rules array per-canonical-rule (rule_id is local; dedupe).
    rule_meta: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = f.rule_id
        if rid not in rule_meta:
            rule_meta[rid] = _rule(f)
        results.append(_result(f))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
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
        ],
    }


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


def _result(f: Finding) -> dict:
    region: dict = {"startLine": max(1, f.line_start)}
    if f.line_end and f.line_end != f.line_start:
        region["endLine"] = f.line_end
    if f.code_snippet:
        region["snippet"] = {"text": f.code_snippet}

    return {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f.message},
        "fingerprints": {"secure-code-agent/v1": f.fingerprint},
        "properties": {
            "confidence": f.confidence.value,
            "category": f.category.value,
            "is_new": f.is_new,
            "suppressed": f.suppressed,
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


def write(findings: Iterable[Finding], output: Path) -> None:
    output.write_text(json.dumps(emit(findings), indent=2), encoding="utf-8")


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
    payload = _read_sarif(sarif_path)
    if payload is None:
        return []

    out: list[Finding] = []
    for run in payload.get("runs", []):
        out.extend(_findings_from_run(run, default_scanner))
    return out


def _read_sarif(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _findings_from_run(run: dict, default_scanner: str) -> list[Finding]:
    driver = (run.get("tool") or {}).get("driver") or {}
    scanner = (driver.get("name") or default_scanner).lower().replace(" ", "_")
    rules = {r.get("id"): r for r in (driver.get("rules") or [])}

    findings: list[Finding] = []
    for result in run.get("results", []):
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
