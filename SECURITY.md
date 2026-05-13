# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in `secure-code-agent` itself (not
findings the tool emits about *your* code — those go in your repo's issue
tracker), please **do not open a public GitHub issue**.

Instead, use the [private security advisory flow](https://github.com/marshallguillory86/secure-code-agent/security/advisories/new).

We aim to:

- Acknowledge the report within 72 hours.
- Provide a preliminary assessment within 7 days.
- Coordinate disclosure with the reporter — credit is happily given.

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.
Short version: the agent runs on developer machines and CI runners; it reads
source files, exec's scanner binaries, emits report artifacts. We consider:

- Malicious repo content (no eval / exec / pickle of repo bytes)
- Output injection (markdown / SARIF / PR-comment escaping)
- Scanner output deception (operator-controlled standards mapping)
- Suppression bypass (mandatory `reason` + `expires`)
- Baseline tampering (git-attributable diffs)
- Cleartext secret in report (default `--redact` for secret scanners)
- Scanner network calls (offline modes by default)
- Resource exhaustion (per-scanner wall-clock timeouts)
- Supply-chain attack on this tool (Sigstore-signed releases, pinnable SHAs)

## Out of scope

- Runtime attacks against running services (this is a static tool).
- Operator account compromise (out of our control).
- CI runner compromise (gate output is untrusted by definition in that case).
- Compromise of upstream scanners (Bandit, Semgrep, etc.) — we pin versions
  but do not audit their source.

## Supported versions

`secure-code-agent` is in v0.x pre-release. Only the latest minor version is
supported with security fixes during the pre-1.0 phase. Once v1.0 ships, we
will publish an explicit support matrix.
