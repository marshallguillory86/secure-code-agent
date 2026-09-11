"""Semgrep — multi-language SAST.

Invocation:
  semgrep --config=auto --sarif --metrics=off --error <target>

Output: SARIF 2.1.0. We piggyback the canonical SARIF parser since other
scanners (CodeQL, Snyk, Trivy) emit the same format.
"""

from __future__ import annotations

import json
import tempfile
from importlib.resources import files
from pathlib import Path

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

#: Ruleset shipped inside the wheel, used when `online` is false. Deliberately
#: narrower than the Registry packs — see docs/scanners.md.
OFFLINE_RULESET = "data/semgrep-offline.yaml"


def offline_ruleset_path() -> Path | None:
    """Filesystem path to the packaged offline ruleset, or None if absent."""
    candidate = Path(str(files("secure_code_audit").joinpath(OFFLINE_RULESET)))
    return candidate if candidate.is_file() else None


def _cwe_from_rule(rule: dict) -> str | None:
    """Recover a CWE id from a Semgrep SARIF rule.

    Semgrep does not surface `metadata.cwe` as `properties.cwe`; it folds it
    into `properties.tags` alongside confidence and OWASP entries. Reading only
    `properties.cwe` meant every Semgrep finding — registry rules included —
    arrived with no CWE, so it scored without the Top-25 weighting and mapped
    to no standard. Both shapes are accepted now.
    """
    props = rule.get("properties") or {}
    explicit = props.get("cwe")
    if isinstance(explicit, list) and explicit:
        return str(explicit[0]).split(":", 1)[0].strip() or None
    if isinstance(explicit, str) and explicit.strip():
        return explicit.split(":", 1)[0].strip()
    for tag in props.get("tags") or []:
        if isinstance(tag, str) and tag.upper().startswith("CWE-"):
            return tag.split(":", 1)[0].strip()
    return None


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"
    #: **No `python_module` fallback.** Semgrep deprecated `python -m
    #: semgrep` in 1.38.0: it now prints a notice, exits 0, and analyses
    #: nothing. The fallback fires whenever the module is importable but the
    #: binary is off PATH — which is the normal state after installing
    #: njsscan, since that pulls semgrep in as a dependency.
    #:
    #: The outcome was FAILED rather than a silent COMPLETED, so coverage
    #: caught it and no grade was claimed on an unrun scanner. But "semgrep
    #: failed" is the wrong thing to tell an operator whose actual situation
    #: is "semgrep is not on PATH", and it sent five of this project's own
    #: tests from skipped to failing the moment njsscan was installed.
    #:
    #: bandit, njsscan, checkov and pip-audit all still run correctly under
    #: `python -m`, so the mechanism stays; semgrep simply opts out.
    default_category = Category.CODE_VULNERABILITIES
    install_hint = "pip install 'secure-code-agent[python-scanners]'"

    def scope(self, config: ScannerConfig) -> str | None:
        """Which rules produced the findings is part of the finding.

        Citing the profile by id, version and digest is what makes an offline
        run reproducible rather than merely repeatable. Online runs draw from
        the Registry, which has no such identity to cite.
        """
        if config.online:
            return None
        from secure_code_audit import ruleset as ruleset_mod

        path = offline_ruleset_path()
        profile = ruleset_mod.describe(path) if path else None
        return f"offline profile {profile.cite()}" if profile else "offline profile unavailable"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        config_arg = "auto"  # registry-curated pack; requires network
        if not sc_cfg.online:
            # `p/security-audit` used to be selected here and described as a
            # bundled offline set. It is a Registry ruleset and is fetched over
            # the network, so "offline" silently was not. Use the ruleset we
            # ship, and fail closed if the installation lacks it rather than
            # falling back to something that reaches the network.
            ruleset = offline_ruleset_path()
            if ruleset is None:
                return self.failed(
                    target,
                    f"offline semgrep requested but the packaged ruleset "
                    f"({OFFLINE_RULESET}) is missing from this installation; "
                    "reinstall secure-code-agent, or set scanners.semgrep.online "
                    "to allow the Semgrep Registry",
                )
            config_arg = str(ruleset)

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            sarif_path = Path(tmp.name)
        try:
            args = [
                *self.command,
                "--config",
                config_arg,
                "--sarif",
                "--metrics=off",
                # Semgrep derives a rule-id prefix from the config file path,
                # so a local ruleset would emit ids like
                # `src.secure_code_audit.data.sca.offline.…` that vary by
                # install location — breaking standards lookup and making
                # baseline fingerprints unstable across machines.
                "--no-rewrite-rule-ids",
                "--output",
                str(sarif_path),
                str(target),
            ]
            args.extend(sc_cfg.extra_args)
            r = self._exec(
                args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
            )
            if r.returncode == 124:
                return self.timed_out(target, f"semgrep timed out: {r.stderr[:200]}")
            if r.returncode not in (0, 1):
                return self.failed(target, f"semgrep failed: {r.stderr[:300]}")
            if not sarif_path.exists() or sarif_path.stat().st_size == 0:
                return self.failed(target, "semgrep emitted no SARIF output")
            try:
                payload = json.loads(sarif_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                return self.failed(target, f"semgrep SARIF parse failure: {exc}")
            return self.completed(self._parse_sarif(payload, target), scope=self.scope(sc_cfg))
        finally:
            sarif_path.unlink(missing_ok=True)

    # -- minimal SARIF parser; a fuller one lives in sarif.py for ingest --
    def _parse_sarif(self, payload: dict, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for run in payload.get("runs", []):
            rules = {
                r.get("id"): r
                for r in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId") or "unknown"
                rule = rules.get(rule_id, {})
                level = (
                    result.get("level")
                    or rule.get("defaultConfiguration", {}).get("level")
                    or "warning"
                )
                msg = (
                    (result.get("message") or {}).get("text")
                    or rule.get("shortDescription", {}).get("text")
                    or rule_id
                )

                locs = result.get("locations") or []
                if not locs:
                    continue
                loc = locs[0]
                phys = loc.get("physicalLocation") or {}
                file_uri = (phys.get("artifactLocation") or {}).get("uri") or ""
                region = phys.get("region") or {}
                line_start = int(region.get("startLine") or 0)
                line_end = int(region.get("endLine") or line_start)
                snippet = (region.get("snippet") or {}).get("text")

                # SARIF severity: "error" → HIGH, "warning" → MEDIUM, "note" → LOW.
                if level == "error":
                    severity = Severity.HIGH
                elif level == "note":
                    severity = Severity.LOW
                else:
                    severity = Severity.MEDIUM

                cwe = _cwe_from_rule(rule)

                findings.append(
                    self._make_finding(
                        rule_id=rule_id,
                        message=msg,
                        file_path=Path(file_uri) if file_uri else target,
                        line_start=line_start,
                        line_end=line_end if line_end != line_start else None,
                        code_snippet=snippet,
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        cwe_override=cwe,
                    )
                )
        return findings
