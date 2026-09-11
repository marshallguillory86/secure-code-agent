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
from secure_code_audit.findings import Category
from secure_code_audit.sarif import ingest as sarif_ingest
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


class CheckovScanner(Scanner):
    name = "checkov"
    binary = "checkov"
    #: **No `python_module` fallback.** checkov ships no `__main__`, so
    #: `python -m checkov` fails with "No module named checkov.__main__".
    #: Declaring the fallback meant that with the package installed but the
    #: console script off PATH, checkov resolved to a command that could
    #: never run — reported as FAILED rather than the honest UNAVAILABLE.
    #:
    #: Caught by the test added alongside the identical semgrep defect,
    #: running in CI where the full floor is installed. It passed locally
    #: only because checkov was not installed on this machine.
    default_category = Category.CONFIG_IAC
    install_hint = "pip install 'secure-code-agent[python-scanners]'"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

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
                return self.timed_out(target, f"checkov timed out: {r.stderr[:200]}")
            if r.returncode not in (0, 1, 2):
                return self.failed(target, f"checkov failed: {r.stderr[:300]}")

            # Checkov writes results.sarif into the output directory.
            sarif_path = tmpdir_path / "results_sarif.sarif"
            if not sarif_path.exists():
                # Older versions write `results.sarif` instead.
                alt = tmpdir_path / "results.sarif"
                sarif_path = alt if alt.exists() else sarif_path
            if not sarif_path.exists():
                return self.failed(target, "checkov emitted no SARIF output")

            ingested = sarif_ingest(sarif_path, default_scanner="checkov")
            # All Checkov findings are config_iac by rule family. Preserve
            # the adapter identity after generic SARIF normalization.
            return self.completed(
                replace(f, scanner="checkov", category=Category.CONFIG_IAC) for f in ingested
            )
