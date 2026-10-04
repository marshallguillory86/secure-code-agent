"""Trivy — containers / filesystem / IaC / Kubernetes scanner.

Invocation:
  trivy fs --format sarif --output <tmp> --quiet --no-progress <target>

Trivy's `fs` subcommand covers filesystem scanning for vulnerable deps
(via its own DB ingest of OSV/GHSA/NVD), secrets, misconfigurations
(Terraform / CloudFormation / Dockerfile / Helm / k8s), and license
issues. We focus on the security-relevant categories: vulnerabilities,
misconfigs, secrets.

SARIF output goes through `secure_code_audit.sarif.ingest()` so we get
canonical Findings with the same normalization as every other SARIF
source.

Trivy emits a single SARIF file per scan with results across all
categories — the standards mapping table routes findings into the
right `Category` based on rule properties.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Finding, Severity
from secure_code_audit.sarif import ingest as sarif_ingest
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


class TrivyScanner(Scanner):
    name = "trivy"
    binary = "trivy"
    default_category = Category.CONFIG_IAC
    install_hint = "brew install trivy, or follow trivy.dev/latest/getting-started/installation"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            sarif_path = Path(tmp.name)
        try:
            args = [
                *self.command,
                "fs",
                "--format",
                "sarif",
                "--output",
                str(sarif_path),
                "--quiet",
                "--no-progress",
                # Skip license findings — we focus on security only.
                "--scanners",
                "vuln,secret,misconfig",
                str(target),
            ]
            args.extend(sc_cfg.extra_args)

            r = self._exec(args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds)
            if r.returncode == 124:
                return self.timed_out(target, f"trivy timed out: {r.stderr[:200]}")
            if r.returncode not in (0, 1):
                return self.failed(target, f"trivy failed: {r.stderr[:300]}")
            if not sarif_path.exists() or sarif_path.stat().st_size == 0:
                # Say what trivy said. This was "trivy emitted no SARIF
                # output" and nothing else, while `r.stderr` held the cause
                # and the remedy — the two paths above both carry it, and the
                # one path with no diagnosis of its own was the one that threw
                # the text away.
                #
                # Found by this repository's own audit, where every one of
                # sixty committed trend rows reads `coverage_complete: false`
                # on a required scanner. What trivy was actually saying:
                # a 429 from Maven Central with a `Retry-After`, and
                # "populate the local Maven cache before scanning". The
                # operator was told a required scanner failed and given
                # nowhere to go, which is the absence-of-evidence failure this
                # tool exists to prevent, committed by the tool itself.
                #
                # The exit code is reported rather than judged: trivy returns
                # 1 both for a fatal error and, with `--exit-code`, for
                # findings, so output decides success here (D30) and the code
                # only helps a reader place the message.
                detail = (r.stderr or "").strip()
                reason = f"trivy emitted no SARIF output (exit {r.returncode})"
                if detail:
                    reason += f": {detail[:300]}"
                return self.failed(target, reason)

            ingested = sarif_ingest(sarif_path, default_scanner="trivy")
            # Trivy tags its rules with a category prefix (CVE-, AVD-, etc.);
            # route them into the right Category bucket.
            return self.completed(self._route_category(f) for f in ingested)
        finally:
            sarif_path.unlink(missing_ok=True)

    def _route_category(self, f: Finding) -> Finding:
        """Trivy bundles three rule families into one SARIF output.
        Route by rule_id prefix so the scoring layer puts them in the
        right category."""
        rid = f.rule_id.upper()
        if rid.startswith("CVE-") or rid.startswith("GHSA-"):
            return replace(f, category=Category.DEPENDENCIES, scanner="trivy")
        if rid.startswith("AVD-") or "MISCONFIG" in rid:
            return replace(f, category=Category.CONFIG_IAC, scanner="trivy")
        if "SECRET" in rid or rid.startswith("AWS") or rid.startswith("PRIVATE-KEY"):
            return replace(
                f, category=Category.SECRETS, scanner="trivy", severity=Severity.CRITICAL
            )
        return replace(f, scanner="trivy")
