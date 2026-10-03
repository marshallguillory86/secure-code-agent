# Threat model

> Status: **v0.12.10 — 2026-10-02.** What this tool trusts, and where the lines are.

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
│   · PyYAML for safe suppression parsing        │
│   · subprocess scanners with bounded env       │
└─────┬──────────────────────────────────────────┘
      │
┌─────▼──────────────────────────────────────────┐
│ Scanner binaries (semi-trusted — external)     │
│   · Operator-installed; versions reported      │
│   · Run with cwd=target, shell=False           │
└─────┬──────────────────────────────────────────┘
      │
┌─────▼──────────────────────────────────────────┐
│ Repo content (UNTRUSTED — may be malicious)    │
│   · Filenames, manifests, config, source       │
│   · Passed to semi-trusted external scanners   │
└────────────────────────────────────────────────┘
```

## Threats considered

### T1 — Malicious repo content

**Threat:** A repo contains crafted filenames, source files, or config that triggers code execution in the agent.

**The ruling, and why it was needed.** This document called repository content
untrusted *and* called the operator the author of the config, while
`secure-code-agent.json` normally lives in the audited tree. Both could not be
true, and the code took the permissive reading: `scanners.<name>.command`
accepted a relative path, resolved it under the audit target, and executed it.
A repository could choose what the auditing host ran — T1, realised by the
tool.

**The line is drawn at executing what the tree supplies, not at distrusting
repositories wholesale.** A config the operator keeps *outside* the tree is an
operator artifact and may still name a tree-local interpreter, which is the
documented `.audit-tools/bin/python` workflow. A config found *inside* the tree
is repository content, and a command it names that also resolves inside the
tree is refused — the scanner reports `unavailable`, which fails required
coverage rather than silently skipping. Auditing a repository you own with a
tree-local toolchain takes `--trust-target-config`, which is a command-line
flag by design: a config file cannot grant itself the trust the flag exists to
withhold.

The containment check runs on the resolved path from **every** route, not just
the relative one, because `PATH` may contain `.` or a tree-local directory.

**The line above was drawn at the executable, and the arguments walked past
it (D29, 2026-10-02).** A config inside the tree could not name an executable
inside the tree, but it could name any program on `PATH` and give it any
arguments — and `python -c "<code>"` is any program. Preflight's `--version`
probe ran it before a single scanner had audited anything, and
maintainability-agent, which runs preflight before its user has said "run",
made that a zero-click execution. **An untrusted config no longer chooses a
scanner's command at all**: the scanner resolves as it would with no config,
the preflight row carries `ignored_command`, and `--trust-target-config`
restores the tree's choice for a repository you own. A config outside the
tree keeps its command, as before.

**A file target's boundary is its parent directory.** Nothing lives beneath a
regular file, so `secure-code-agent app.py` made every containment test false
at once and the single-file shape silently opted out of the guard above. A
configured executable beside the file was executed without the flag. Both
checks now normalise a file target to its parent.

### The tree does not choose where the host writes, either

The line above is about *executing* what the tree supplies, and for a while it
was the only line. The tree could still choose **paths**: the default config is
loaded from the audit target, and `outputs.*_path`, `baseline_path` and
`history_path` were resolved with no containment check at all. A repository
shipping `{"outputs": {"markdown_path": "../../../../.bashrc"}}` had an
ordinary audit overwrite that file with the report's own content. Arbitrary
write is not a lesser thing than arbitrary execute; it is usually a slower
route to the same place.

A config supplied by the tree may now only write beneath the audit root, with
`..` traversal, absolute paths and **symlinks inside the tree pointing out of
it** all refused — the last is why the check resolves before comparing rather
than inspecting the string. The run exits 2 before any scanner starts.

Explicit CLI output flags are untouched: `--output /tmp/report.md` is the
operator speaking.

### The tree does not grade itself, either

**Threat:** the audited repository supplies the numbers its own audit reports.

`severity_overrides` and `category_overrides` map a rule id to a severity or
a category, and they were applied from any config — including one discovered
inside the audited tree, with no `--trust-target-config`. `INFORMATIONAL` is
weight 0.0, so re-labelling a finding removes it from the score while leaving
it visible in the report.

Measured on one `subprocess.run(cmd, shell=True)`: **0.00 (F)** honestly, and
**5.00 (A+)** with an in-tree `severity_overrides` naming that rule. Nothing
was hidden; the weight was.

This is the same shape as the T1 ruling one step removed. T1 was about what
the tree may make the host *run*; this is about what the tree may make the
host *report*. An auditing tool whose grade is settable by the audited party
has no product left, so it is a trust-boundary question rather than a
configuration one. [D32](decisions.md) records it.

**Ruling.** A config inside the containment root, without
`--trust-target-config`, does not supply either key. They are dropped before
any consumer reads them, and the run warns on stderr naming the file. A
config kept outside the tree, and the flag, both still apply them — the
operator auditing their own repository is the ordinary case, and that case
has an owner-shaped escape hatch already.

### What `--trust-target-config` grants

It says: *treat this tree's config as though you wrote it.* That is *three*
grants, and all three are real:

1. the config may name executables from that tree, which this host will run;
2. the config may direct outputs, baseline and history to paths outside the
   tree;
3. the config may re-label a finding's severity and category, which moves the
   grade.

One flag rather than three because it is one judgement — whether this
repository's config is an operator artifact. But it is worth being plain that
saying yes hands over all three, not just the first.

**Mitigations:**
- All scanner invocations are `subprocess.run(args=[...], shell=False, cwd=target, env=_sanitized_env())`.
- Repository-supplied configuration cannot select an executable inside the audited tree; see the ruling above.
- Repository-supplied configuration cannot set a finding's severity or category, so the audited tree cannot move its own grade (D32).
- Unknown top-level configuration keys are rejected rather than ignored, so a config asserting a privilege this tool does not read fails loudly instead of appearing accepted.
- The orchestrator does not `eval()`, `exec()`, `pickle.load()`, or import target source. `.scignore.yaml` uses `yaml.safe_load`; PyYAML is a bounded runtime dependency.
- File paths are passed via argv, never via shell interpolation.
- `.scignore.yaml` is parsed with `yaml.safe_load`; deserializing it cannot construct arbitrary Python objects.
- Built-in rules read source files as UTF-8 with decoding errors ignored. External scanners have their own parsers and trust models; project dependency resolution may process package metadata and access configured indexes. Run audits of untrusted repositories in an isolated runner.

### T2 — Output injection (report or PR-comment)

**Threat:** A finding's code snippet or message contains characters that escape the report formatting and inject content into operator-visible UIs.

**Current controls and limitation:**
- JSON and SARIF serializers JSON-encode strings.
- Markdown uses fenced code blocks, but scanner-controlled backticks and other Markdown constructs are not comprehensively escaped in this release. Treat generated Markdown and PR-comment artifacts as untrusted text and do not render them in privileged HTML contexts.

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
- Baseline entries record the best-effort local Git email, but this release does not add an interactive acknowledgment or cryptographic identity. Repository review and branch protection are the approval boundary.

### T6 — Cleartext secret in report

**Threat:** Scanner emits the raw matched secret in its output; we render it into a checked-in artifact.

**Mitigations:**
- Secret-scanning scanners (Gitleaks, TruffleHog) are configured with `--redact` (Gitleaks) and `--only-verified --concurrency=1` (TruffleHog) by default.
- The Markdown report renders only the redacted match.
- Fingerprints use the redacted evidence supplied to the normalized finding; the orchestrator does not retain the raw secret for deduplication.
- SARIF serializes the normalized finding. It does not perform a second redaction pass, so adapter redaction is part of the scanner contract and must be regression-tested.

### T7 — Exfiltration via scanner network calls

**Threat:** A scanner makes outbound network calls that leak repo content (filenames, snippets).

**Mitigations:**
- The CLI itself has no telemetry or version-check request. External scanners may access registries, advisory services, GitHub, or package indexes depending on their arguments and local caches.
- Bandit and built-in rules are local-only. Dependency resolution and registry-backed scanners must be treated as network-capable unless the operator has independently configured and verified an offline mode.
- `scanners.<name>.online` only changes adapters that explicitly implement it. It is not a global network sandbox.

### T8 — Resource exhaustion

**Threat:** A pathological repo causes a scanner to consume unbounded CPU/RAM.

**Mitigations:**
- Each scanner runs under a wall-clock timeout (`scanners.<name>.timeout_seconds`, default 600).
- On timeout `subprocess.run` terminates the child, a `tool_timeout` finding is emitted, and required coverage fails. Child-created process trees may require runner-level isolation.
- Scanner output is captured in memory and SARIF is loaded as JSON. CI runners should enforce repository-size, memory, and process limits.

### T9 — Supply-chain attack on the agent itself

**Threat:** A compromised release of `secure-code-agent` injects malicious behavior into a security-critical step.

**Mitigations:**
- GitHub Action references should be pinned to a SHA (`uses: marshallguillory86/secure-code-agent@<sha>`), not a tag.
- GitHub CI tests the package and dogfoods selected scanners against the repository. Scanner versions are pinned in that workflow.
- Release signing, provenance attestations, and SBOM publication are release-process goals and must not be assumed unless the corresponding release artifacts are present.

## Out of scope

- **Runtime attacks** — WAFs, IDS, RASP, runtime memory protections.
- **Operator account compromise** — if your GitHub account is taken over, this tool cannot help.
- **CI runner compromise** — if your CI runner is owned, gate output is untrusted by definition.
- **Compromise of the underlying scanners** — we rely on Bandit, Semgrep, etc. being correctly built and distributed. We pin versions; we don't audit their source.

## Reporting vulnerabilities in this tool

See [SECURITY.md](../SECURITY.md). Coordinated disclosure via GitHub Security Advisory.
