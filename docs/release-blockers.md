# v0.3.0 Release Blockers

> Status: **open — do not tag v0.3.0.** Raised by hostile audit against
> `a65527c`, 2026-08-10. All eight findings independently verified against the
> source before being recorded here. None are fixed.
> Related: [`architecture.md`](architecture.md) for the structural causes,
> [`product-intent.md`](product-intent.md) §4 for the success criteria these
> violate.

## Why this exists

Two of these are false-green paths: the gate reports success while the tool has
either detected a HIGH finding or failed to scan. That contradicts
[`product-intent.md`](product-intent.md) §4 criterion 1 — *"a green gate means
something"* — which is the product's central promise. Tagging a release in this
state would ship the exact failure mode v0.3.0 was written to eliminate.

Two of these (§3, §4) were introduced by the v0.3.0 SARIF-import work itself.

## Release boundary

The minimum set that must close before `v0.3.0` is tagged:

- [ ] **§1** — absent gate configuration cannot read as a passing gate
- [ ] **§2** — Gitleaks/TruffleHog findings-exit with no parseable findings fails coverage
- [ ] **§3** — trust model for SARIF imports decided and enforced
- [ ] **§4** — malformed SARIF contained as failed coverage, not a traceback
- [ ] **§5** — offline Semgrep is genuinely offline
- [ ] **§6** — failed-coverage SARIF reaches Code Scanning

§7 and §8 are not release blockers but should land in the same cycle.

---

## 1. Critical — `--fail-on-gate` does nothing when no gates are configured

`config.py` defaults `gates` to an empty mapping; `scoring.py` treats every
missing gate as "not configured"; `action.yml` makes config optional while
defaulting `fail-on-gate` to true.

Reproduced: input containing `subprocess.run(user_input, shell=True)` produced a
correct HIGH CWE-78 finding, scored `0.0/F`, coverage complete — and
`gate.passed` was `true` with exit `0`.

The earlier fix rejecting an explicit `require_scanners: []` does not cover an
*omitted* configuration. A naive Action adoption is a green check with no
security floor.

**Note:** this was identified during the v0.3.0 session and under-rated as
"residual, CI is protected." That assessment was wrong. The failure is not
"nothing ran so nothing was found" — it is "a HIGH finding was found and the
gate passed anyway."

**Bounded fix:** reject `--fail-on-gate` when no gates are configured, *or*
ship documented safe default gates, *or* require a config in the Action. Prefer
the first: it fails closed and needs no policy invention.

## 2. Critical — secret scanners launder a findings-exit into a clean result

`gitleaks_scanner.py` accepts exit 1 as "findings present," then returns `[]`
when the report is missing or zero-length. `trufflehog_scanner.py` has the same
shape for exit 183 with empty stdout.

Reproduced: Gitleaks exit 1 + empty report → zero findings, outcome
`completed`. TruffleHog exit 183 + empty stdout → zero findings, outcome
`completed`.

The scanner told us it found secrets and we recorded a clean scan. When either
is in `require_scanners`, this is a false-green gate.

**Bounded fix:** a findings-signaling exit code must require successfully
parsed, non-empty findings. Otherwise emit a `tool_error` control finding so the
outcome is `failed`. Audit the other adapters for the same pattern — this is a
class, not two instances.

## 3. High — unverified SARIF can satisfy required scanner coverage

`sarif.py::_execution_from_run` marks a run `failed` only when
`executionSuccessful` is explicitly `false`. A run with no `invocations` at all
is classified `completed`.

Reproduced: a minimal SARIF with a valid tool name, no results, no
`invocations`, and no version satisfied a required `trivy` that was locally
disabled. Exit `0`, coverage complete, gate passed, Trivy recorded as completed
with version `unknown`.

"A scanner someone else ran" is being treated as "verified successful scanner
execution." This was a deliberate v0.3.0 design choice and the critique is
correct: the trust assumption is undocumented and the default is too generous.

**Bounded fix:** decide the trust model explicitly. Preferred — required
coverage from an import demands positive invocation evidence, with a distinct
`reported` / `unverified` outcome for imports that lack it. Minimum — document
the assumption in `docs/scanners.md` and surface `unverified` in the report.

## 4. Medium — structurally malformed SARIF crashes the audit

`{"version":"2.1.0","runs":[null]}`, or a `results` object where an array is
expected, raises an uncaught `AttributeError` in `sarif.py`.

The process does exit nonzero, but emits a traceback instead of a controlled
failed-coverage report, and produces no evidence artifacts. This violates the
adapter failure-isolation rule described in [`architecture.md`](architecture.md)
§1 — the same rule the v0.3.0 import work was supposed to extend to imports.

**Bounded fix:** validate run/results shape during ingest and route any
structural violation to the existing failed-execution path already used for
unreadable and malformed input.

## 5. High — `online: false` does not make Semgrep offline

`semgrep_scanner.py` selects `p/security-audit` when online operation is
disabled, and the code comment describes it as a bundled offline ruleset. It is
a Semgrep Registry ruleset and requires retrieval. An offline hostile run
entered the network path and failed with an X.509 error.

The comment is not merely imprecise — it asserts a security property the code
does not have, which is the failure mode [`product-intent.md`](product-intent.md)
§5 principle 8 exists to prevent.

**Bounded fix:** package a local ruleset for offline execution, or reject
offline Semgrep when no local config is available. Delete the inaccurate comment
either way.

## 6. Medium — CI skips Code Scanning upload on the failures that matter

In `ci.yml`, the audit step exits nonzero when required coverage fails. The
following `Upload SARIF to code scanning` step's `if:` contains only the fork
condition, with no `always()`, `failure()`, or `!cancelled()`. GitHub applies an
implicit `success()` when no status-check function is present, so the upload is
skipped exactly when the SARIF carries `executionSuccessful: false`.

The Security tab therefore retains an older clean result. The adjacent artifact
upload correctly uses `always()`.

**Bounded fix:** add `!cancelled() &&` to the existing condition.

## 7. Medium — default config resolves against the shell's cwd, not the target

`cli.py::_prepare_audit` calls `config_mod.load(args.config)` before resolving
the audit target, and the default path is cwd-relative.

Reproduced: auditing `/tmp/another-project` from this repository without
`--config` applied *this repository's* required scanners rather than the target
project's configuration. This undermines the one-target-root model and can apply
the wrong security policy silently.

**Bounded fix:** resolve the target first, then look for the default config
under the target root.

## 8. Low — emitted SARIF declares a broken schema URL

`sarif.py` emits a `$schema` pointing at an `oasis-tcs` path containing
`/schemas/`, which 404s; the repository path is singular `/schema/`. The stable
official schema lives at
`https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`.

Both the CI SARIF and a failed-coverage SARIF validate against the official
schema, so the document shape is sound — only the declared locator is broken.

**Bounded fix:** point `$schema` at the OASIS canonical URL.

---

## Sequencing note

§1, §2, and §4 are the same class the architecture audit already named:
outcomes inferred from weak signals (an empty file, an absent key, an absent
`invocations` block) rather than asserted by a type.
[`architecture.md`](architecture.md) §2 proposes `ScanResult` as the structural
fix. Closing these blockers tactically is correct for the release; doing the
`ScanResult` refactor immediately afterward is what stops the class from
regenerating.
