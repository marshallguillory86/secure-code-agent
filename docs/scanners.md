# Scanner integrations

The agent is an orchestrator — it shells out to each scanner, parses canonical output, and maps to the unified `Finding` schema. We don't reimplement SAST.

## The declared floor

`src/secure_code_audit/scanners/floor.py` is the minimum set this project
asserts, with the licence and rationale for every tool and the reason each
excluded one is opt-in. `gates.require_scanners: ["floor"]` requires it without
enumerating it.

**Floor, commit cadence** — evaluated on every run: `builtin_rules`, `bandit`,
`semgrep`, `pip_audit`, `osv_scanner`, `gitleaks`, `checkov`, `trivy`.

**Floor, repository cadence** — `scorecard`. It answers questions about the
project rather than the change, and takes over half an hour, so it runs in
[`supply-chain.yml`](../.github/workflows/supply-chain.yml) on a schedule and
reaches an audit by SARIF import. Reports name it as deferred rather than
omitting it.

**Opt-in** — `trufflehog` (duplicates gitleaks for detection; AGPL; live
verification is the genuine gain), `hadolint` (overlaps checkov and trivy on
Dockerfiles; GPL), `npm_audit` (osv_scanner covers the same advisories with
fewer false positives and without needing Node).

A floor tool with nothing to scan is `not_applicable` with a reason, never a
coverage gap: requiring a Terraform scanner of a pure-Python repository would
make every such repository permanently incomplete.

## Obtaining scanners

**The agent never installs a scanner for you.** A security gate that downloads
and executes binaries to satisfy its own coverage requirement is a supply-chain
liability, and it is the kind of thing this tool exists to flag. Acquisition
stays with your package manager or a pinned CI action.

Run `secure-code-agent --preflight` to see what resolves on the current host
before spending a full audit on it. It reports each enabled scanner's resolved
command and version, prints the install command for anything missing, and exits
nonzero when a required scanner cannot be resolved.

Resolution order per scanner is `scanners.<name>.command`, then `PATH`, then
`python -m <module>` for the Python-packaged ones.

### Python-packaged scanners

Installable as extras, so the version is pinned alongside the agent:

| Extra | Scanners | Command |
| --- | --- | --- |
| `required-scanners` | Bandit, pip-audit | `pip install 'secure-code-agent[required-scanners]'` |
| `python-scanners` | the above plus Semgrep, Checkov | `pip install 'secure-code-agent[python-scanners]'` |

`required-scanners` is pinned exactly because the default configuration lists
those scanners in `gates.require_scanners`; a gate asserting "Bandit completed"
should mean a known Bandit completed. It is also included in `dev`, so a fresh
checkout can run its own audit.

### Standalone binaries

These ship as Go/Haskell binaries and **cannot come from PyPI**. Install them
locally, or — better in CI — run the upstream pinned action and hand us its
SARIF (see [SARIF import](#sarif-import)).

| Scanner | Local install | Pinned CI action |
| --- | --- | --- |
| **Trivy** | `brew install trivy` | `aquasecurity/trivy-action` |
| **Gitleaks** | `brew install gitleaks` | `gitleaks/gitleaks-action` |
| **OSV-Scanner** | `brew install osv-scanner` | `google/osv-scanner-action` |
| **OpenSSF Scorecard** | `brew install scorecard` | `ossf/scorecard-action` |
| **Hadolint** | `brew install hadolint` | `hadolint/hadolint-action` |
| **TruffleHog** | `brew install trufflehog` | `trufflesecurity/trufflehog` |
| **npm audit** | install Node.js | any Node setup action |

Non-Homebrew hosts should take a pinned release archive from each project's
GitHub releases rather than piping an installer script to a shell.

## Tier 1 — shipped in v0.1

All Tier-1 scanners are wired and emit canonical findings.

| Scanner               | Category               | Binary / Invocation                                              | Output      | Standards covered                                 |
|-----------------------|------------------------|------------------------------------------------------------------|-------------|---------------------------------------------------|
| **Bandit**            | `code_vulnerabilities` | `bandit -r <path> -f json -ll -ii`                               | JSON        | CWE per rule, OWASP A03/A07/A02                   |
| **Semgrep**           | `code_vulnerabilities` | `semgrep --config=auto --sarif --output=...`                     | SARIF       | CWE per rule (multi-language), OWASP all          |
| **pip-audit**         | `dependencies`         | requirements, local project, lock, or configured environment mode | JSON      | CWE-1104, OWASP A06                               |
| **npm audit**         | `dependencies`         | `npm audit --json`                                               | JSON        | CWE-1104, OWASP A06                               |
| **Gitleaks**          | `secrets`              | `gitleaks detect --no-banner --report-format=json --report-path=`| JSON        | CWE-798, OWASP A07                                |
| **TruffleHog**        | `secrets`              | `trufflehog filesystem --json --no-update <path>`                | JSON Lines  | CWE-798, OWASP A07                                |
| **eslint-plugin-security** | `code_vulnerabilities` | `eslint --no-eslintrc --plugin security --format=json ...`     | JSON        | CWE-89/79/22/78 (JS/TS)                           |
| **Built-in regex rules** | `multiple`           | Internal — no subprocess                                         | (in-proc)   | CWE-798, CWE-89, CWE-78, CWE-22, CWE-918          |
| **SARIF import**      | `multiple`             | `--sarif-import path/to/file.sarif`                              | SARIF       | Whatever the upstream emitted                     |

## Tier 2 — shipped in v0.2

All Tier-2 scanners are wired and emit canonical findings.

| Scanner                | Category                                  | Binary / Invocation                                                | Output     | Standards covered                                       |
|------------------------|-------------------------------------------|--------------------------------------------------------------------|------------|---------------------------------------------------------|
| **Trivy**              | `dependencies`, `config_iac`, `secrets`   | `trivy fs --format sarif --scanners vuln,secret,misconfig <target>`| SARIF      | CWE-1104 (vuln), CWE-1188 (misconfig), CWE-798 (secret) |
| **Checkov**            | `config_iac`                              | `checkov -d <target> --output sarif --soft-fail`                   | SARIF      | CWE-1188, OWASP A05                                     |
| **Hadolint**           | `config_iac`                              | `hadolint --no-fail --format json <Dockerfile>`                    | JSON       | CWE-250 (USER root), CWE-78 (shell-form CMD)            |
| **OSV-Scanner**        | `dependencies`                            | `osv-scanner scan source --format=json --recursive <target>`       | JSON       | CWE-1104, OWASP A06                                     |
| **TruffleHog**         | `secrets`                                 | `trufflehog filesystem --json --only-verified <target>`            | JSON Lines | CWE-798, OWASP A07                                      |
| **OpenSSF Scorecard**  | `supply_chain`, `policy_docs`             | `scorecard --repo=<github-url> --format=json --show-details`       | JSON       | CWE-732, CWE-345, CWE-829, CWE-272 (per-check)          |

### Per-scanner caveats (Tier 2)

**Trivy** — routes findings into `dependencies` / `config_iac` / `secrets` by rule-id prefix (`CVE-`/`GHSA-` → deps, `AVD-` / contains `MISCONFIG` → IaC, contains `SECRET` / `AWS` / `PRIVATE-KEY` → secrets). Secret findings are bumped to CRITICAL.

**Checkov** — `--soft-fail` so the tool always exits 0; gate logic is our concern, not Checkov's. Writes `results_sarif.sarif` (or legacy `results.sarif`) into the output directory.

**Hadolint** — twelve security-relevant rule ids carry specific severities (`DL3002` USER root → HIGH; `DL3025` shell-form CMD → MEDIUM; `SC2086` unquoted variable → MEDIUM; etc.). Style-only rules (`DL3007` latest tag, `DL3008` unpinned apt) → LOW.

**OSV-Scanner** — overlaps `pip_audit` + `npm_audit` by design. Findings have stable baseline fingerprints, but the current scorer does not deduplicate across scanners; enabling overlapping SCA adapters can double-count an advisory.

**TruffleHog** — defaults to `--only-verified` (high-precision matches confirmed live by upstream services). Verified secrets are CRITICAL; if operators opt into unverified findings via `scanners.trufflehog.extra_args: ["--no-only-verified"]`, those land as HIGH.

**OpenSSF Scorecard** — special-cased. Operates against a remote GitHub URL inferred via `git remote get-url origin`. Needs `GH_TOKEN` (or equivalent) in the environment to query GitHub APIs. Score → severity mapping: `<0 → INFORMATIONAL` (inconclusive), `<3 → HIGH`, `<7 → MEDIUM`, `<10 → LOW`, `==10` → no finding emitted (passed cleanly).

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

    def configure(self, target: Path, config: "Config") -> None:
        """Resolve an explicit command, PATH executable, or Python module."""

    def run(self, target: Path, config: "Config") -> list[Finding]:
        """Execute the scanner against target, parse output, return findings.
        MUST NOT raise. Errors → return [finding(severity=INFO,
        rule_id='scanner_error', message=<reason>)]."""

    @property
    def command(self) -> tuple[str, ...]:
        """The resolved external command and any configured arguments."""
```

## Adding a new scanner

1. Subclass `scanners.base.Scanner` in `scanners/<name>_scanner.py`.
2. Implement `run()` — invoke binary, parse output, yield `Finding` objects.
3. Add rule-id → standards mappings in `src/secure_code_audit/standards.py`.
4. Register in `scanners.registry.SCANNERS`.
5. Add unit test fixtures in `tests/fixtures/<name>/` with at least:
   - one HIGH finding
   - one false-positive that should be suppressible
   - one parse-failure to confirm graceful degradation
6. Document the scanner's invocation + output format in this file.

## Per-scanner caveats

### Bandit
- `--severity-level low --confidence-level low` and we filter ourselves (Bandit's own filtering is too coarse for our scoring model).
- Bandit's `B101 (assert_used)` is noisy in tests; the repository example excludes `tests/`. Consumers should make that choice explicitly in their own config.

### Semgrep
- `scanners.semgrep.online: true` (the default) uses `--config=auto`, the curated Registry pack. **This reaches the network.**
- `scanners.semgrep.online: false` uses the ruleset shipped in the wheel at `secure_code_audit/data/semgrep-offline.yaml`. No registry fetch, no rule server.
- **The offline set is deliberately narrower than the Registry packs — it is not equivalent, and you should not read a clean offline run as equivalent to a clean `auto` run.** It is ten high-precision rules covering command injection, unsafe deserialization, weak hashes, disabled TLS verification, debug mode, `eval`, and DOM XSS, across Python and JavaScript/TypeScript. Every rule carries a CWE, and each is regression-tested to actually match its target pattern.
- If the packaged ruleset is missing from an installation, offline Semgrep fails with a `tool_error` rather than falling back to anything that would reach the network.
- We pass `--no-rewrite-rule-ids`. Semgrep otherwise prefixes rule ids with the config file's path, which would vary by install location and destabilize baseline fingerprints.
- Semgrep timeouts on huge repos — we default to a 600s wall clock per run and fail soft (informational finding) on timeout.

### Gitleaks
- Default config is `gitleaks.toml` — we ship a curated one in `secure_code_audit/data/gitleaks.toml`.
- Run against history: `gitleaks detect --redact` to avoid leaking secrets in the report itself.
- We render the **redacted** match in the report, not the raw secret. The fingerprint is derived from the redacted evidence and location; the adapter never receives the raw secret from Gitleaks JSON.

### TruffleHog
- High-noise; we filter to `verified: true` matches by default (real, currently-valid secrets).
- Set `--only-verified` in scanner config; expose `--include-unverified` for noisy adoption mode.

### npm audit
- npm's "fix" suggestions are often major-version downgrades. We ingest findings only — we never auto-apply `npm audit fix`.
- Three severity levels in npm output (`info / low / moderate / high / critical`) — we map `moderate → medium`.

### pip-audit
- `auto` discovers `requirements*.txt` and `pyproject.toml` recursively while honoring configured exclusions. A requirements file wins over a `pyproject.toml` in the same directory to avoid duplicate resolution.
- `requirements` invokes `pip-audit -r <file>`; `project` invokes `pip-audit <project>`; `locked` invokes `pip-audit --locked <project>`; `environment` audits the environment belonging to the configured command.
- Use `inputs` for explicit manifests and `command` to bind the audit to a specific interpreter or tool environment.
- Dependency resolution can access package indexes and should only be run against trusted project metadata. Suppressions are applied to normalized findings after scanner execution; they are not forwarded as pip-audit arguments.

### Built-in regex rules

Located in `src/secure_code_audit/scanners/builtin_rules.py`. Each rule:
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

`--sarif-import path/to/file.sarif` ingests external scanner output. The parser
targets common output from:

- **CodeQL** (GitHub's hosted analysis)
- **Semgrep Cloud** (`semgrep ci --sarif`)
- **Snyk** (`snyk test --sarif-file-output=...`)
- **Trivy** (`trivy fs --format=sarif`)
- **Checkov** (`checkov -d . --output sarif`)

Multiple SARIF imports merge by `fingerprint`. Standards mappings for imported findings come from the SARIF `rules` array if present, otherwise from our local `rule_map.json`.

### Imports are coverage

A scanner someone else ran on our behalf covers the same ground as one we
invoke, so an import produces a scanner execution and **can satisfy
`gates.require_scanners`**. This is the supported way to gate on a scanner the
audit host cannot install:

```yaml
- uses: aquasecurity/trivy-action@<pinned-sha>
  with: { format: sarif, output: trivy.sarif }
- run: secure-code-agent --fail-on-gate --sarif-import trivy.sarif
```

with `"require_scanners": ["trivy"]` in the config. Rules:

- The execution is named from the SARIF `tool.driver.name`, lowercased with
  spaces and hyphens folded to underscores — `OSV-Scanner` becomes
  `osv_scanner`. When a driver names itself something else entirely, say so
  explicitly: `--sarif-import trivy=vendor-output.sarif`.
- **An import is `unverified`, never `completed`.** We did not watch the
  process, so we cannot assert it succeeded — only that you vouched for the
  file. Even `executionSuccessful: true` is the artifact describing itself.
  Unverified coverage satisfies `require_scanners` (naming the import is your
  assertion, the same kind we trust from `scanners.<name>.command`), but every
  report says so: `coverage: COMPLETE (1 unverified: trivy)`, `coverage.unverified`
  in JSON, `unverifiedScanners` in the emitted SARIF. If we also ran the scanner
  ourselves, our observation wins over the import.
- Naming an import on the command line asserts it contributes coverage, so an
  unreadable, malformed, structurally invalid, or run-less SARIF **fails the
  gate** rather than ingesting zero findings quietly.
- An import whose own `invocations[].executionSuccessful` is `false` is
  recorded as a failed execution. We do not launder another tool's failure.
- If the same scanner reports twice — once locally, once by import — the worse
  outcome wins, so a clean import cannot mask a failed local run.
