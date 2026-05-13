# Threat model

`secure-code-agent` runs on developer machines and CI runners. The tool reads source files, exec's scanner binaries, emits report artifacts. Threats below are considered in design; the listed mitigation is what we ship in v0.1.

## Trust boundaries

```
┌────────────────────────────────────────────────┐
│ Operator (trusted)                             │
│   · Authors config, runs CLI, reads reports    │
│   · Approves baseline + suppressions           │
└─────┬──────────────────────────────────────────┘
      │
┌─────▼──────────────────────────────────────────┐
│ secure-code-agent CLI (trusted — our code)     │
│   · stdlib only at runtime                     │
│   · subprocess scanners with bounded env       │
└─────┬──────────────────────────────────────────┘
      │
┌─────▼──────────────────────────────────────────┐
│ Scanner binaries (semi-trusted — vendored)     │
│   · MIT/Apache-2.0; pinned versions in CI      │
│   · Run with cwd=target, shell=False           │
└─────┬──────────────────────────────────────────┘
      │
┌─────▼──────────────────────────────────────────┐
│ Repo content (UNTRUSTED — may be malicious)    │
│   · Filenames, file contents, .scignore.yaml   │
│   · Never eval'd, never exec'd, never imported │
└────────────────────────────────────────────────┘
```

## Threats considered

### T1 — Malicious repo content

**Threat:** A repo contains crafted filenames, source files, or config that triggers code execution in the agent.

**Mitigations:**
- All scanner invocations are `subprocess.run(args=[...], shell=False, cwd=target, env=_sanitized_env())`.
- We never `eval()`, `exec()`, `pickle.load()`, `yaml.load()` (only `yaml.safe_load`), or `import` repo content.
- File paths are passed via argv, never via shell interpolation.
- `.scignore.yaml` is parsed with `yaml.safe_load`; deserializing it cannot construct arbitrary Python objects.
- The agent reads source files in text mode with UTF-8 decoding and explicit `errors='replace'` — a malicious binary file can't crash the parser.

### T2 — Output injection (report or PR-comment)

**Threat:** A finding's code snippet or message contains characters that escape the report formatting and inject content into operator-visible UIs.

**Mitigations:**
- Markdown report renders code snippets inside fenced code blocks (` ``` `) — markdown does not interpret inside fences.
- PR-comment output applies GitHub-flavored markdown escaping for `<`, `>`, `|`, backticks in non-code spans.
- SARIF output JSON-encodes all strings; the SARIF spec is interpreted by consumers, not us.
- We never emit raw HTML in any output format.

### T3 — Scanner output deception

**Threat:** A scanner is configured (or compromised) to emit findings that frame attacker-controlled paths.

**Mitigations:**
- Standards mapping is local (`rule_map.json`), not scanner-supplied. A scanner cannot claim `category: "policy_docs"` for a CWE-89 finding to dodge the `auth_authz` gate.
- Severity overrides flow operator → tool, never tool → operator. The scanner's severity is a hint; the operator's `severity_overrides` in config is the ground truth.
- Fingerprints are computed from `(canonical_cwe, file_path, normalized_code_hash)` — a scanner cannot manipulate the fingerprint by changing its rule id.

### T4 — Suppression bypass

**Threat:** Operator suppresses overly-broad rules to silence the gate.

**Mitigations:**
- `.scignore.yaml` requires a `reason` field. Empty reasons fail config validation.
- `.scignore.yaml` requires an `expires` date (max 365 days). Past-expiry suppressions become CRITICAL findings on their own.
- Wildcard rule suppressions (`rule_id: "*"`) require a `file:` or `paths:` scope — you cannot disable a rule globally.
- Category-level suppressions are not supported. Operators must enumerate specific rules.

### T5 — Baseline tampering

**Threat:** Operator silently flips a finding into the baseline (`--bump-baseline`) without review.

**Mitigations:**
- Baseline is a checked-in JSON artifact with operator-attributable git diffs. Reviewers must approve baseline changes in PR.
- `--bump-baseline` records the operator's git config `user.email` in a `bumped_by` field per fingerprint.
- Bumping a CRITICAL or HIGH finding requires `--bump-baseline --i-acknowledge-risk` (extra flag).
- The report includes a "baseline drift" section showing how many findings were acknowledged in the last N runs.

### T6 — Cleartext secret in report

**Threat:** Scanner emits the raw matched secret in its output; we render it into a checked-in artifact.

**Mitigations:**
- Secret-scanning scanners (Gitleaks, TruffleHog) are configured with `--redact` (Gitleaks) and `--only-verified --concurrency=1` (TruffleHog) by default.
- The Markdown report renders only the redacted match.
- Fingerprints are computed from a hash of the raw secret so dedupe still works, but the raw secret never reaches the report file.
- SARIF output redacts secret matches via `secrets_redaction` mode (configurable; default: redact).

### T7 — Exfiltration via scanner network calls

**Threat:** A scanner makes outbound network calls that leak repo content (filenames, snippets).

**Mitigations:**
- Default scanner configuration uses **offline modes** where supported (`semgrep --no-rewrite-rule-ids`, `bandit` is local-only, `pip-audit --disable-pip` to skip live PyPI, `osv-scanner --offline` for local DB).
- Operators who want online scans (e.g. Semgrep Pro registry) opt in via config (`scanners.semgrep.online: true`).
- The CLI does not phone home. No telemetry, no version-check pings.

### T8 — Resource exhaustion

**Threat:** A pathological repo causes a scanner to consume unbounded CPU/RAM.

**Mitigations:**
- Each scanner runs under a wall-clock timeout (`scanners.<name>.timeout_seconds`, default 600).
- On timeout we kill the process group, emit a `tool_timeout` informational finding, and continue the audit.
- The agent itself uses bounded memory; we stream scanner JSON output rather than loading entire SARIF files into memory.

### T9 — Supply-chain attack on the agent itself

**Threat:** A compromised release of `secure-code-agent` injects malicious behavior into a security-critical step.

**Mitigations:**
- PyPI releases are signed (via Sigstore/cosign).
- GitHub Action references should be pinned to a SHA (`uses: marshallguillory86/secure-code-agent@<sha>`), not a tag.
- Releases publish a CycloneDX SBOM as a release asset.
- We dogfood the agent against itself in CI (`secure-code-agent` runs against its own source on every PR).

## Out of scope

- **Runtime attacks** — WAFs, IDS, RASP, runtime memory protections.
- **Operator account compromise** — if your GitHub account is taken over, this tool cannot help.
- **CI runner compromise** — if your CI runner is owned, gate output is untrusted by definition.
- **Compromise of the underlying scanners** — we rely on Bandit, Semgrep, etc. being correctly built and distributed. We pin versions; we don't audit their source.

## Reporting vulnerabilities in this tool

See [SECURITY.md](../SECURITY.md). Coordinated disclosure via GitHub Security Advisory.
