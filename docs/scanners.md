# Scanner integrations

The agent is an orchestrator — it shells out to each scanner, parses canonical output, and maps to the unified `Finding` schema. We don't reimplement SAST.

## Tier 1 — shipped in v0.1

All Tier-1 scanners are wired and emit canonical findings.

| Scanner               | Category               | Binary / Invocation                                              | Output      | Standards covered                                 |
|-----------------------|------------------------|------------------------------------------------------------------|-------------|---------------------------------------------------|
| **Bandit**            | `code_vulnerabilities` | `bandit -r <path> -f json -ll -ii`                               | JSON        | CWE per rule, OWASP A03/A07/A02                   |
| **Semgrep**           | `code_vulnerabilities` | `semgrep --config=auto --sarif --output=...`                     | SARIF       | CWE per rule (multi-language), OWASP all          |
| **pip-audit**         | `dependencies`         | `pip-audit -r requirements.txt --format=json`                    | JSON        | CWE-1104, OWASP A06                               |
| **npm audit**         | `dependencies`         | `npm audit --json`                                               | JSON        | CWE-1104, OWASP A06                               |
| **Gitleaks**          | `secrets`              | `gitleaks detect --no-banner --report-format=json --report-path=`| JSON        | CWE-798, OWASP A07                                |
| **TruffleHog**        | `secrets`              | `trufflehog filesystem --json --no-update <path>`                | JSON Lines  | CWE-798, OWASP A07                                |
| **eslint-plugin-security** | `code_vulnerabilities` | `eslint --no-eslintrc --plugin security --format=json ...`     | JSON        | CWE-89/79/22/78 (JS/TS)                           |
| **Built-in regex rules** | `multiple`           | Internal — no subprocess                                         | (in-proc)   | CWE-798, CWE-89, CWE-78, CWE-22, CWE-918          |
| **SARIF import**      | `multiple`             | `--sarif-import path/to/file.sarif`                              | SARIF       | Whatever the upstream emitted                     |

## Tier 2 — interface defined, implementation tracked for v0.2

Scanner protocol stubs exist; full implementation is pending v0.2. Calling `--only-scanners trivy` today emits a `tool_unavailable` informational finding.

| Scanner                | Category                  | Why deferred                                                     |
|------------------------|---------------------------|------------------------------------------------------------------|
| **Trivy**              | `config_iac`, `dependencies` | Container + IaC support is wide; needs careful invocation matrix |
| **Checkov**            | `config_iac`              | Terraform / CloudFormation / Helm / k8s — extensive ruleset      |
| **Hadolint**           | `config_iac`              | Dockerfile-only; small surface but needs its own renderer        |
| **OSV-Scanner**        | `dependencies`            | Multi-ecosystem (overlaps pip-audit/npm-audit) — needs dedupe    |
| **OpenSSF Scorecard**  | `supply_chain`            | Runs against a remote repo — special case in the runner          |

## Tier 3 — documented, no code yet

Will be considered after v0.2 ships.

- **gosec** — Go SAST. Add when first Go-heavy repo is dogfooded.
- **Brakeman** — Rails SAST.
- **SpotBugs / FindSecBugs** — JVM SAST.
- **Snyk** — proprietary; out-of-the-box ingest of Snyk SARIF, but no `snyk` invocation (license + auth burden).
- **CodeQL** — *ingest only* (CodeQL runs in GitHub-hosted analysis; we read the SARIF artifact).
- **detect-secrets** — overlaps Gitleaks/TruffleHog; track if customer ask emerges.
- **Trivy SBOM** + **Syft / CycloneDX** — SBOM generation is a separate workflow; pair this agent with a dedicated SBOM tool.
- **cosign verify** — signature verification on releases; nice-to-have for `supply_chain` category.

## Scanner protocol

```python
# src/secure_code_audit/scanners/base.py

from typing import Protocol
from pathlib import Path
from secure_code_audit.findings import Finding, Category

class Scanner(Protocol):
    name:     str         # canonical id used in config + reports
    category: Category    # which audit bucket findings land in
    binary:   str         # the command we exec ("bandit", "semgrep", ...)
    version_flag: str     # how to ask the binary its version ("--version")

    def is_available(self) -> bool:
        """Probe for the binary on PATH. Cached after first call."""

    def run(self, target: Path, config: "Config") -> list[Finding]:
        """Execute the scanner against target, parse output, return findings.
        MUST NOT raise. Errors → return [finding(severity=INFO,
        rule_id='scanner_error', message=<reason>)]."""

    def fingerprint(self, finding: Finding) -> str:
        """Compute a stable fingerprint for baseline + dedupe. Default
        impl in base.Scanner; scanners can override if they have a
        better signal."""
```

## Adding a new scanner

1. Subclass `scanners.base.Scanner` in `scanners/<name>_scanner.py`.
2. Implement `run()` — invoke binary, parse output, yield `Finding` objects.
3. Add rule-id → standards mappings in `src/secure_code_audit/data/rule_map.json`.
4. Register in `scanners.registry.SCANNERS`.
5. Add unit test fixtures in `tests/fixtures/<name>/` with at least:
   - one HIGH finding
   - one false-positive that should be suppressible
   - one parse-failure to confirm graceful degradation
6. Document the scanner's invocation + output format in this file.

## Per-scanner caveats

### Bandit
- `--severity-level low --confidence-level low` and we filter ourselves (Bandit's own filtering is too coarse for our scoring model).
- Bandit's `B101 (assert_used)` is noisy in tests; we ship a default suppression for `tests/` paths.

### Semgrep
- Use `--config=auto` for the curated registry pack, or `--config=<file>` for repo-specific rules.
- Semgrep timeouts on huge repos — we default to a 600s wall clock per run and fail soft (informational finding) on timeout.

### Gitleaks
- Default config is `gitleaks.toml` — we ship a curated one in `secure_code_audit/data/gitleaks.toml`.
- Run against history: `gitleaks detect --redact` to avoid leaking secrets in the report itself.
- We render the **redacted** match in the report, not the raw secret. The fingerprint hashes the raw match so dedupe still works.

### TruffleHog
- High-noise; we filter to `verified: true` matches by default (real, currently-valid secrets).
- Set `--only-verified` in scanner config; expose `--include-unverified` for noisy adoption mode.

### npm audit
- npm's "fix" suggestions are often major-version downgrades. We ingest findings only — we never auto-apply `npm audit fix`.
- Three severity levels in npm output (`info / low / moderate / high / critical`) — we map `moderate → medium`.

### pip-audit
- Reads `requirements.txt` by default; supports `pyproject.toml` via `--strict`.
- We pass `--ignore-vuln <id>` flags from `.scignore.yaml` for accepted-risk dependencies.

### Built-in regex rules

Located in `src/secure_code_audit/rules/`. Each rule:
- Targets a single CWE.
- Has a confidence rating documented inline.
- Is unit-tested with at least one true-positive and one false-positive fixture.

The built-in set is **opinionated and small** — high-confidence, low-false-positive rules that catch what the big scanners miss. We are not building a parallel Semgrep. Current rules:

| Rule id              | CWE     | What it catches                                                        |
|----------------------|---------|------------------------------------------------------------------------|
| `sca.python.eval`    | CWE-95  | `eval()`, `exec()`, `compile()` on non-literal input                   |
| `sca.python.pickle`  | CWE-502 | `pickle.load` / `pickle.loads` on non-literal input                    |
| `sca.python.yaml.unsafe_load` | CWE-502 | `yaml.load(...)` without `Loader=SafeLoader`                  |
| `sca.python.requests.verify_false` | CWE-295 | `requests.*(... verify=False ...)`                          |
| `sca.python.subprocess.shell_true` | CWE-78  | `subprocess.*(shell=True)` with non-literal command          |
| `sca.python.fstring_sql` | CWE-89  | `f"...SELECT ... {var}..."` patterns in `.execute()`/`.executemany()` |
| `sca.python.hashlib.md5_sha1_security` | CWE-327 | `hashlib.md5()`/`sha1()` in a non-test, non-checksum path |
| `sca.web.dangerously_set_inner_html` | CWE-79 | React `dangerouslySetInnerHTML={{__html: nonliteral}}`        |
| `sca.web.cors_wildcard` | CWE-942 | `Access-Control-Allow-Origin: *` with credentials enabled            |
| `sca.shell.curl_pipe_sh` | CWE-78 | `curl ... \| sh` / `wget ... \| bash` patterns in Dockerfiles + scripts |

Suppression by file/path/rule via `.scignore.yaml` per [design.md §10](design.md).

## SARIF import

`--sarif-import path/to/file.sarif` ingests external scanner output. We've validated against:

- **CodeQL** (GitHub's hosted analysis)
- **Semgrep Cloud** (`semgrep ci --sarif`)
- **Snyk** (`snyk test --sarif-file-output=...`)
- **Trivy** (`trivy fs --format=sarif`)
- **Checkov** (`checkov -d . --output sarif`)

Multiple SARIF imports merge by `fingerprint`. Standards mappings for imported findings come from the SARIF `rules` array if present, otherwise from our local `rule_map.json`.
