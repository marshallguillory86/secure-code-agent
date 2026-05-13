# Finding taxonomy

Use this reference when interpreting a `secure-code-agent` finding.

## Severity

| Level         | Meaning                                                          | Action                                       |
|---------------|------------------------------------------------------------------|----------------------------------------------|
| `critical`    | Active or imminent compromise vector                             | Fix immediately. Block merge.                 |
| `high`        | Exploitable with effort                                          | Fix in-PR. Don't merge without a fix or doc'd suppression.|
| `medium`      | Defense-in-depth weakness                                        | Fix in current sprint. Suppress with reason if accepted risk.|
| `low`         | Hygiene / posture issue                                          | Track. Fix as time permits.                  |
| `informational`| Awareness only                                                   | Read; no action required.                    |

## Confidence

- `high` — scanner is sure (rule + AST match + no documented FP pattern).
- `medium` — pattern match with some heuristic. Read the snippet before patching.
- `low` — broad pattern, likely false-positive surface. Investigate before changing code.

## Categories

| Category                | Examples                                                                        | Default weight |
|-------------------------|---------------------------------------------------------------------------------|---------------:|
| `secrets`               | Hardcoded API keys, tokens in history, `.env` in git                            | 1.5×           |
| `dependencies`          | CVE in pinned dep, yanked package, abandoned upstream                           | 1.0×           |
| `code_vulnerabilities`  | SQLi, XSS, command-injection, path-traversal, SSRF, XXE, deserialization        | 1.5×           |
| `auth_authz`            | Missing auth gate, IDOR, broken access control, JWT misuse                      | 1.5×           |
| `crypto`                | Weak alg, hardcoded IV, ECB, MD5/SHA-1 for security, missing constant-time      | 1.5×           |
| `supply_chain`          | Unpinned action, missing SBOM, no signed releases, low Scorecard                | 0.8×           |
| `config_iac`            | World-readable S3, public security group, Dockerfile `USER root`, k8s privileged| 1.0×           |
| `logging_observability` | Secrets in logs, PII in URLs, missing audit trail on auth events                | 0.8×           |
| `policy_docs`           | Missing SECURITY.md, no responsible-disclosure path, no threat model            | 0.5×           |

## Standards

Every finding carries up to four standards refs. Read them — they are the
authoritative description, not the scanner's one-liner.

- **CWE id** — https://cwe.mitre.org/data/definitions/<num>.html (the dedupe key)
- **OWASP Top 10 (2021)** — https://owasp.org/Top10/2021/
- **OWASP ASVS 5.0** — https://github.com/OWASP/ASVS
- **NIST SSDF SP 800-218** — https://csrc.nist.gov/pubs/sp/800/218/final

CWE Top 25 (2025) findings get a 1.25× scoring boost. The list is reproduced
in `docs/standards.md`.

## How to read a finding

1. **Read the standard.** The scanner's rule description is a summary. The
   linked CWE / ASVS / OWASP entry is the contract.
2. **Read the snippet.** Confidence is about the pattern, not the context.
3. **Identify the attacker-controlled input.** If you can't name the input,
   you can't fix the finding properly.
4. **Patch at the boundary.** Sanitize / parameterize / validate at the
   trust boundary, not at every call site.
5. **Add a test.** The test must FAIL on the pre-fix code.

## When to suppress vs. fix

Fix when:
- The finding is a real defect (even if exploit cost is high).
- The fix is bounded (≤30 LOC patch + a test).
- The fix doesn't touch unrelated code.

Suppress when:
- The finding is a verifiable false positive (you can name why the pattern
  is safe in context).
- The risk is accepted with a documented expiry (≤365 days).
- The underlying behavior is being rewritten and the suppression is
  scoped to that rewrite's window.

Never:
- Suppress because "it's noisy."
- Suppress with `reason: "TODO"` or empty.
- Suppress without an expiry.

## Suppression syntax

`.scignore.yaml`:

```yaml
- file: services/legacy_billing.py
  rule_id: "*"
  reason:  "Slated for rewrite Q3 2026 — gated by initiative INV-44."
  expires: "2026-09-30"

- rule_id: "B101"
  paths:   ["tests/"]
  reason:  "assert statements are legitimate in test code."
  expires: "2027-05-13"
```

Wildcard rule (`rule_id: "*"`) **requires** a `file` or `paths` scope. You
cannot disable a rule globally.
