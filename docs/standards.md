# Standards anchors

`secure-code-agent` does not invent a new taxonomy. Every finding maps to five widely-cited public standards. Operators see *which standard is failing*, not just *which scanner shouted*.

## NIST SSDF — SP 800-218

[Source](https://csrc.nist.gov/pubs/sp/800/218/final). The Secure Software Development Framework defines four practice groups:

| Group | Name                           | What it covers                                                                                |
|-------|--------------------------------|-----------------------------------------------------------------------------------------------|
| **PO** | Prepare the Organization       | Security policies, training, infrastructure prerequisites                                     |
| **PS** | Protect the Software           | Source integrity, supply-chain verification, secret management                                |
| **PW** | Produce Well-Secured Software  | Threat modeling, secure design, secure code review, code analysis, defect fixing              |
| **RV** | Respond to Vulnerabilities     | Vulnerability identification, fix, disclosure                                                 |

This tool primarily exercises **PW** (well-secured production) and **RV** (response). Each finding carries an SSDF practice id (e.g. `PW.5.1 — Configure compilation and build processes to use compiler-generated warnings and errors`). The map lives in `src/secure_code_audit/data/standards_ssdf.json`.

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

We will refresh the mapping table the day OWASP publishes the 2024-cycle update.

## OWASP ASVS 5.0

[Source](https://github.com/OWASP/ASVS). Application Security Verification Standard — verification-requirement granularity. Three levels:

- **L1** — minimum, all apps
- **L2** — apps handling sensitive data (the Trovik baseline)
- **L3** — apps requiring the highest trust

Each finding carries the ASVS section it violates (e.g. `V5.3 — Output Encoding and Injection Prevention`). Operators can require **L2 minimum** via config; findings that only violate L3 are downgraded to LOW.

## MITRE CWE Top 25 (2025)

[Source](https://cwe.mitre.org/top25/). The canonical weakness id is the **dedupe key** for cross-scanner findings. When Semgrep, CodeQL, and Bandit all fire on the same SQL-injection sink with three different rule ids, they all map to `CWE-89` and the scorer counts one underlying weakness.

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

[Source](https://openssf.org/projects/scorecard/). 18 repo-hygiene checks scored 0-10:

- **Critical**: `Code-Review`, `Token-Permissions`, `Branch-Protection`, `Signed-Releases`, `Pinned-Dependencies`
- **High**: `Maintained`, `License`, `Dangerous-Workflow`, `SAST`, `Vulnerabilities`
- **Medium**: `Binary-Artifacts`, `CII-Best-Practices`, `Fuzzing`, `Packaging`, `Webhooks`
- **Low**: `Contributors`, `CI-Tests`, `Security-Policy`

We import Scorecard's JSON output and map each check into the `supply_chain` and `policy_docs` categories. Scorecard runs in CI; this agent ingests its output rather than re-implementing.

## SARIF 2.1.0

[Source](https://www.oasis-open.org/standard/sarif-v2-1-0/). The Static Analysis Results Interchange Format — the lingua franca for scanner output. We:

- **Ingest** SARIF from CodeQL, Semgrep, Snyk, and any tool that emits compliant SARIF (`--sarif-import path/to/file.sarif`).
- **Emit** SARIF 2.1.0 for the merged + normalized findings so downstream tools (GitHub Code Scanning, IDE extensions, Sonar) can ingest the merged view.

We emit OASIS-conformant SARIF, validated against the official schema in CI.

---

## Mapping table

The full mapping `rule_id → (CWE, OWASP Top 10, ASVS, SSDF, category, severity, confidence)` lives in `src/secure_code_audit/data/rule_map.json`. PRs adding new mappings need:

1. A citation (URL to the scanner's docs page for the rule).
2. The CWE id the rule targets (mandatory — this is the dedupe key).
3. The ASVS section (mandatory if a section applies; null otherwise).
4. The default category + severity (use the scanner's default unless overriding with justification).

The map is reviewed quarterly against OWASP, CWE, and NIST publication cycles.
