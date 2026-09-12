# Standards anchors

> Status: **v0.12.0 — 2026-09-11.** CWE / OWASP / ASVS / NIST SSDF mapping.

`secure-code-agent` does not invent a new taxonomy. Known rules map to fields
from widely-cited public standards. Unmapped or control findings may have null
fields; reports preserve the scanner rule rather than inventing a mapping.

## NIST SSDF — SP 800-218

[Source](https://csrc.nist.gov/pubs/sp/800/218/final). The Secure Software Development Framework defines four practice groups:

| Group | Name                           | What it covers                                                                                |
|-------|--------------------------------|-----------------------------------------------------------------------------------------------|
| **PO** | Prepare the Organization       | Security policies, training, infrastructure prerequisites                                     |
| **PS** | Protect the Software           | Source integrity, supply-chain verification, secret management                                |
| **PW** | Produce Well-Secured Software  | Threat modeling, secure design, secure code review, code analysis, defect fixing              |
| **RV** | Respond to Vulnerabilities     | Vulnerability identification, fix, disclosure                                                 |

This tool primarily exercises **PW** (well-secured production) and **RV**
(response). Mapped findings carry an SSDF practice id. The reviewed mappings
live in `src/secure_code_audit/standards.py`.

## OWASP Top 10 (2021)

[Source](https://owasp.org/Top10/2021/). Ten web-app risk buckets, refreshed every ~3 years. The agent tags every applicable finding with one or more bucket ids:

| Id   | Bucket                                       |
|------|----------------------------------------------|
| A01  | Broken Access Control                        |
| A02  | Cryptographic Failures                       |
| A03  | Injection                                    |
| A04  | Insecure Design                              |
| A05  | Security Misconfiguration                    |
| A06  | Vulnerable and Outdated Components           |
| A07  | Identification and Authentication Failures   |
| A08  | Software and Data Integrity Failures         |
| A09  | Security Logging and Monitoring Failures     |
| A10  | Server-Side Request Forgery (SSRF)           |

Mappings are versioned with the package and require an explicit reviewed update.

## OWASP ASVS 5.0

[Source](https://github.com/OWASP/ASVS). Application Security Verification Standard — verification-requirement granularity. Three levels:

- **L1** — minimum, all apps
- **L2** — apps handling sensitive data (the Trovik baseline)
- **L3** — apps requiring the highest trust

Mapped findings carry the applicable ASVS section (for example `V5.3`). The
current release does not implement an ASVS-level gate or severity adjustment;
configuration that claims one is rejected rather than silently ignored.

## MITRE CWE Top 25 (2025)

[Source](https://cwe.mitre.org/top25/). The canonical weakness id contributes to the stable finding fingerprint and standards mapping. The current scorer preserves separate scanner findings rather than collapsing cross-scanner evidence.

The Top 25 list as of 2025-cycle (subject to MITRE's annual refresh):

| Rank | CWE     | Name                                                              |
|------|---------|-------------------------------------------------------------------|
| 1    | CWE-79  | Cross-site Scripting                                              |
| 2    | CWE-787 | Out-of-bounds Write                                               |
| 3    | CWE-89  | SQL Injection                                                     |
| 4    | CWE-352 | Cross-Site Request Forgery (CSRF)                                 |
| 5    | CWE-22  | Path Traversal                                                    |
| 6    | CWE-125 | Out-of-bounds Read                                                |
| 7    | CWE-78  | OS Command Injection                                              |
| 8    | CWE-416 | Use After Free                                                    |
| 9    | CWE-862 | Missing Authorization                                             |
| 10   | CWE-434 | Unrestricted Upload of File with Dangerous Type                   |
| 11   | CWE-94  | Improper Control of Code Generation                               |
| 12   | CWE-20  | Improper Input Validation                                         |
| 13   | CWE-77  | Command Injection                                                 |
| 14   | CWE-287 | Improper Authentication                                           |
| 15   | CWE-269 | Improper Privilege Management                                     |
| 16   | CWE-502 | Deserialization of Untrusted Data                                 |
| 17   | CWE-200 | Exposure of Sensitive Information                                 |
| 18   | CWE-863 | Incorrect Authorization                                           |
| 19   | CWE-918 | Server-Side Request Forgery (SSRF)                                |
| 20   | CWE-119 | Improper Restriction within Memory Buffer                         |
| 21   | CWE-476 | NULL Pointer Dereference                                          |
| 22   | CWE-798 | Use of Hard-coded Credentials                                     |
| 23   | CWE-190 | Integer Overflow / Wraparound                                     |
| 24   | CWE-400 | Uncontrolled Resource Consumption                                 |
| 25   | CWE-306 | Missing Authentication for Critical Function                      |

Findings hitting a Top-25 CWE are weighted **1.25×** in the scoring model. Full CWE id space (1700+ ids) is supported — the Top 25 is a weighting hint, not a filter.

## OpenSSF Scorecard

[Source](https://openssf.org/projects/scorecard/). Upstream repo-hygiene checks are scored 0-10:

- **Critical**: `Code-Review`, `Token-Permissions`, `Branch-Protection`, `Signed-Releases`, `Pinned-Dependencies`
- **High**: `Maintained`, `License`, `Dangerous-Workflow`, `SAST`, `Vulnerabilities`
- **Medium**: `Binary-Artifacts`, `CII-Best-Practices`, `Fuzzing`, `Packaging`, `Webhooks`
- **Low**: `Contributors`, `CI-Tests`, `Security-Policy`

We import Scorecard's JSON output and map each check into the `supply_chain` and `policy_docs` categories. Scorecard runs in CI; this agent ingests its output rather than re-implementing.

## SARIF 2.1.0

[Source](https://www.oasis-open.org/standard/sarif-v2-1-0/). The Static Analysis Results Interchange Format — the lingua franca for scanner output. We:

- **Ingest** SARIF from CodeQL, Semgrep, Snyk, and any tool that emits compliant SARIF (`--sarif-import path/to/file.sarif`).
- **Emit** SARIF 2.1.0 for the merged + normalized findings so downstream tools (GitHub Code Scanning, IDE extensions, Sonar) can ingest the merged view.

We emit SARIF 2.1.0-shaped JSON and unit-test required structure plus a local
round trip. The current CI does not validate every artifact against the full
OASIS JSON schema, so strict downstream compatibility remains a release check.

---

## Mapping table

The mapping `rule_id → (CWE, OWASP Top 10, ASVS, SSDF, category, severity, confidence)` lives in `src/secure_code_audit/standards.py`. PRs adding new mappings need:

1. A citation (URL to the scanner's docs page for the rule).
2. The CWE id the rule targets when a defensible mapping exists; it becomes a stable fingerprint input.
3. The ASVS section (mandatory if a section applies; null otherwise).
4. The default category + severity (use the scanner's default unless overriding with justification).

Mapping updates require source review and focused tests; no automatic refresh is claimed.
