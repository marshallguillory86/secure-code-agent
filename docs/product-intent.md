# secure-code-agent — Product Intent

> Status: **v0.3.0 — consolidated 2026-08-10.** The single source of truth for
> *why this exists, who it serves, and what it refuses to become.*
> Companion docs: [`design.md`](design.md) for how it is built,
> [`architecture.md`](architecture.md) for where the build diverges from the
> design, [`threat-model.md`](threat-model.md) for what it defends against.

## 1. Intent in one sentence

**Give a repository with AI coding agents in the loop a deterministic security
gate, and give the agent a bounded task brief so that fixing a finding does not
become an unreviewed rewrite of the security-critical code around it.**

Every part of that sentence constrains the product. *Deterministic* rules out
an LLM in the audit path. *Gate* rules out an advisory dashboard. *Bounded task
brief* is the differentiator — it is the thing no existing scanner ships.

## 2. The problem

Security scanners are a solved-enough problem. Semgrep, Bandit, CodeQL, Trivy,
Gitleaks, and OSV are mature, well-maintained, and better at finding defects
than anything this project would write. The problem is not detection.

The problem is what happens *after* detection, once an AI agent is the one
holding the patch. Pointed at a security finding, agents exhibit a consistent
and documented set of failure modes:

| Anti-pattern | What the agent actually does |
| --- | --- |
| **Crypto roulette** | "Replace MD5 with SHA-256" → rewrites the hashing module using a library it saw in training data. |
| **Auth-flow rewrite** | "Fix the IDOR" → refactors the session model. Now there is an unaudited new auth path. |
| **Validation softening** | "Make the tests pass after the fix" → weakens the regex or removes the bounds check. |
| **Test deletion** | "The security test is failing" → deletes the test. |
| **Lint disable** | "This rule fires repeatedly" → `# nosec`, `# noqa`, `eslint-disable` everywhere. |
| **Scope creep** | "I fixed the SQLi" → followed by 600 lines of unrelated refactoring. |
| **Dependency thrash** | "Bumping the vulnerable package" → introduces twelve unrelated new dependencies. |
| **Silent behavior change** | "It works now" → same input, different output. Downstream callers break. |

Each of these turns a *known, scoped, one-line defect* into an *unknown,
unscoped, unreviewed change to security-critical code*. The net security
posture can be worse after the fix than before it, and the review burden lands
on a human who was already saturated — which is why the agent was doing it.

Existing scanners stop at "here is a list of findings." None of them ship a
prompt back to the agent that says *fix only these findings, do not touch
crypto, auth, validation, or logging, preserve behavior, add a test that fails
before and passes after.*

That gap is the product.

## 3. Who this is for

**Primary: the engineer who owns a repository where agents write code.** They
need a CI gate that fails honestly, and an artifact they can hand to Claude
Code, Codex, Cursor, Copilot, or an SDK agent that constrains the fix. They are
not a security specialist and should not need to be.

**Secondary: the security engineer standardizing multiple repositories.** They
care about the standards anchoring — CWE, OWASP Top 10, OWASP ASVS, NIST SSDF —
because they report against frameworks, not scanner rule ids. They need SARIF
out and plain files in git, not a SaaS they must procure.

**Secondary: the platform/CI owner.** They care that it is one binary, runs the
same locally and in CI, has a meaningful exit code, and never phones home.

**Explicitly not for:** teams looking for a SAST engine, a runtime defense, a
vulnerability management SaaS, or a compliance dashboard. See §6.

## 4. What success looks like

The product is working when all of the following hold. These are the criteria
the design already implies; they are written down here so future features can
be judged against them.

1. **A green gate means something.** The gate cannot pass while a required
   scanner failed to run. A clean finding set with a broken toolchain must be
   reported as incomplete, never as safe. This is non-negotiable and was the
   subject of the v0.3.0 coverage-integrity work.
2. **The audit is reproducible.** Same inputs, same commit, same scanner
   versions → same score, same exit code. No LLM in the audit path, no network
   dependency in scoring, no wall-clock dependence except suppression expiry.
3. **The remediation prompt actually bounds the agent.** The patch that comes
   back touches the named findings and little else, preserves behavior, and
   carries a test that fails pre-fix and passes post-fix.
4. **A finding survives a reformat.** Baseline identity is stable across
   whitespace-only edits, so adopting the tool on an existing repository does
   not produce a wall of false "new" findings.
5. **Suppressions cannot rot.** Every suppression carries a reason and an
   expiry, and an expired one becomes a hard failure rather than silently
   continuing to hide a defect.
6. **The tool is honest about its own limits.** Documented behavior matches
   executable behavior. Claims that cannot be substantiated are removed rather
   than softened.

Criterion 3 is currently **unmeasured**. We assert the prompt bounds the agent
because it encodes the anti-patterns in §2 as explicit constraints, but no
empirical evaluation has been run. This is stated as an open question in §8
rather than claimed as a result.

## 5. Product principles

Each principle exists to settle a class of future argument. When a proposed
feature conflicts with one, the principle wins unless it is explicitly revised
here.

1. **Deterministic first, AI optional.** The audit never calls an LLM. The
   remediation prompt is a generated file the operator chooses to hand to an
   agent. *Consequence:* no "AI triage" of findings, no LLM-assisted severity
   scoring, no model in the gate path.

2. **Orchestrate, do not reimplement.** We shell out to best-in-class scanners
   and normalize their output. *Consequence:* no custom AST analysis, and no
   parallel ruleset competing with Semgrep or Bandit.

   **Amended 2026-09-09 — the line is a bound, not a refusal.** This read as a
   blanket ban on authoring rules, and we author rules: the built-in regex pack,
   and the offline Semgrep ruleset that exists because the registry rules an
   online run fetches are licensed for internal, non-competing, non-SaaS use
   only. Left unqualified, the principle would have been violated the moment we
   shipped either.

   The bound that replaces the ban: **our ruleset is the offline floor, not a
   competitor.** Online, the maintained registries do the job, because online is
   where they are available. Offline, our rules answer the highest-consequence
   patterns so that "no network" does not mean "no coverage."

   That bound is enforceable because it is about rule *shape*: the offline set
   takes **language primitives** — `shell=True`, `eval`, `pickle.loads`,
   `hashlib.md5`, `verify=False` — and **refuses framework-specific rules**.
   Primitives do not change and cost almost nothing to keep correct. Framework
   rules rot with every framework release, and framework breadth is exactly what
   the online path is for. See [D9](decisions.md).

   Parity with a registry remains a non-goal. A one-maintainer project cannot
   maintain thousands of rules, and a stale ruleset claiming to be a standard is
   worse than a small one honestly labelled.

3. **Never overstate coverage.** Findings and scanner coverage are separate
   axes and are reported separately. A scanner that was unavailable, timed out,
   crashed, produced unparseable output, or was excluded from the run fails
   coverage rather than reading as clean. *Consequence:* the honest answer is
   sometimes "we do not know," and the product must be able to say it.

4. **Never install anything.** A security gate that downloads and executes
   binaries to satisfy its own coverage requirement is the supply-chain risk it
   exists to catch. Acquisition stays with the operator's package manager or a
   pinned CI action. *Consequence:* onboarding friction is accepted as the price
   of not being a malware delivery vector.

5. **Standards-anchored, not scanner-anchored.** Findings map to CWE, OWASP Top
   10, OWASP ASVS, and NIST SSDF. *Consequence:* operators see which standard is
   failing rather than which scanner shouted, and reports survive swapping one
   scanner for another.

6. **Plain files, no lock-in.** Markdown, JSON, SARIF 2.1.0, PR comment,
   baseline — all plain files in the repository. *Consequence:* no hosted
   service, no account, no telemetry, ever.

7. **Bounded remediation.** The prompt forbids touching crypto, auth,
   validation, logging, and tests unless a finding names them as the defect.
   *Consequence:* the product deliberately refuses to help an agent do a large
   refactor, even when the refactor might be correct.

8. **Say the true thing.** Documentation describes shipped behavior. When a
   claim cannot be substantiated it is removed, not hedged. *Consequence:*
   release notes will sometimes read as retractions, and that is correct.

## 6. Scope boundaries

**In scope.** Static analysis orchestration; dependency and supply-chain
posture; secret detection; IaC and container configuration; standards mapping;
deterministic scoring and gating; baseline and suppression lifecycle; SARIF in
and out; bounded remediation prompt generation; per-agent standing-instruction
files.

**Out of scope, permanently.**

- **Not a SAST engine.** No custom AST analysis.
- **Not a runtime defense.** No WAF, IDS, or agent in the request path.
- **Not a SaaS dashboard.** Findings live as files in the repository.
- **Not a license scanner.** License compliance is a separate concern.
- **Not an exploit generator.** No DAST, no fuzzing, no proof-of-concept
  generation.
- **No telemetry.** Not opt-in, not anonymized, not "just crash reports."

**Deferred, not rejected.** These are tracked so that "not yet" is not confused
with "never," and so a contributor knows what a good proposal looks like.

- Additional language SAST adapters — gosec, Brakeman, SpotBugs/FindSecBugs —
  added when a repository that needs them is actually being dogfooded, not
  speculatively.
- Ingest-only integrations for tools we will not invoke ourselves: CodeQL
  (runs in GitHub-hosted analysis) and Snyk (license and auth burden).
- Cross-scanner deduplication. Overlapping SCA adapters can currently
  double-count one advisory. Fingerprints are stable enough to support this; the
  scorer does not yet do it.
- Operator-defined standards rule packs. The mapping table is currently
  compiled into the package.
- Scoped changed-file audits. `--changed-only` is reserved and fails explicitly
  rather than silently auditing the wrong scope.
- SBOM generation and signature verification — better served by dedicated tools
  this agent can be paired with.

## 7. Positioning

This is **not** a competitor to Semgrep, Bandit, Trivy, or CodeQL. It is a
layer above them, and it is strictly worse than any of them at finding defects.
Its value is in four things they do not do together:

1. Normalizing many scanners into one standards-anchored finding schema.
2. Turning that into a deterministic, configurable gate with a real exit code.
3. Reporting scanner coverage as a first-class result, so a green build cannot
   silently mean an empty one.
4. Emitting a bounded remediation prompt for the agent that will do the fix.

It is the security sibling of
[`maintainability-agent`](https://github.com/marshallguillory86/maintainability-agent):
same shape — deterministic CI gate, plain-file outputs, per-host skill bundle —
different concern.

## 8. Open product questions

Recorded rather than resolved. Each of these should be answered deliberately
rather than settled by whichever feature lands first.

1. **Should the deliverable be one verdict or two numbers?** Today a report
   carries a letter grade *and* a coverage status, and the reader must combine
   them. The score's null state is "perfect" — a repository where nothing ran
   still grades A+ — which is why coverage had to be added beside it. See
   [`architecture.md` §5](architecture.md).
2. **Does the remediation prompt measurably bound agent behavior?** Criterion 3
   in §4 is asserted from first principles and has never been evaluated.
   An honest answer needs a fixture repository, a set of seeded findings, and
   patches from several agents scored against the constraint list.
3. **Who owns the standards mapping?** It is compiled into the package today,
   so adding a rule requires a release and operators cannot extend it. Shipping
   it as data with an operator overlay is a product decision about how much
   customization to invite.
4. **How far does "never install anything" extend?** It is settled for scanner
   binaries. It is not settled for whether the tool should offer to *verify*
   installed scanner versions against pinned expectations, which is adjacent to
   supply-chain assurance and might belong here.
5. **What is the adoption path for a repository with thousands of existing
   findings?** Baseline plus expiring suppressions is the current answer, but it
   has not been exercised on a large legacy codebase.
