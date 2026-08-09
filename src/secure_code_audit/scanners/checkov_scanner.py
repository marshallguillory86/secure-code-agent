"""Checkov — IaC scanning (Terraform / CloudFormation / Helm / k8s / Dockerfile).

Invocation:
  checkov -d <target> --output sarif --output-file-path <tmp> --quiet --soft-fail

`--soft-fail` makes checkov exit 0 even on findings; we want our own
gate logic to drive exit codes, not checkov's. SARIF goes through the
canonical ingest.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.sarif import ingest as sarif_ingest
from secure_code_audit.scanners.base import Scanner


class CheckovScanner(Scanner):
    name = "checkov"
    binary = "checkov"
    python_module = "checkov"
    default_category = Category.CONFIG_IAC

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        # Checkov writes to a directory and names the file itself.
        # Use a temp directory so cleanup is straightforward.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            args = [
                *self.command,
                "-d",
                str(target),
                "--output",
                "sarif",
                "--output-file-path",
                str(tmpdir_path),
                "--quiet",
                "--soft-fail",
            ]
            args.extend(sc_cfg.extra_args)

            r = self._exec(
                args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1, 2)
            )
            if r.returncode == 124:
                return [
                    self._make_finding(
                        rule_id=f"{self.name}.tool_timeout",
                        message=f"checkov timed out: {r.stderr[:200]}",
                        file_path=target,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                    )
                ]
            if r.returncode not in (0, 1, 2):
                return [
                    self._make_finding(
                        rule_id=f"{self.name}.tool_error",
                        message=f"checkov failed: {r.stderr[:300]}",
                        file_path=target,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                    )
                ]

            # Checkov writes results.sarif into the output directory.
            sarif_path = tmpdir_path / "results_sarif.sarif"
            if not sarif_path.exists():
                # Older versions write `results.sarif` instead.
                alt = tmpdir_path / "results.sarif"
                sarif_path = alt if alt.exists() else sarif_path
            if not sarif_path.exists():
                return [
                    self._make_finding(
                        rule_id=f"{self.name}.tool_error",
                        message="checkov emitted no SARIF output",
                        file_path=target,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                    )
                ]

            ingested = sarif_ingest(sarif_path, default_scanner="checkov")
            # All Checkov findings are config_iac by rule family. Preserve
            # the adapter identity after generic SARIF normalization.
            return [replace(f, scanner="checkov", category=Category.CONFIG_IAC) for f in ingested]
