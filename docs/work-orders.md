# Work orders — the first-class output

> Status: **v0.11.0 — 2026-09-11.** Triage tiers and outcome verification.

The score is second class. It is worth something as a *trend* and very
little as a number, and the thing that actually improves a repository is a
bounded, specific instruction an agent can act on and a way to check
afterwards that it did.

This page is the whole loop: **audit → work order → fix → verify → trend.**

---

## 1. Audit

```bash
secure-code-agent .
```

Writes two files by default:

| file | what it is |
| --- | --- |
| `secure-code-report.md` | what the audit found, for a person |
| `secure-code-remediation-prompt.md` | **the work order**, for an agent |

Both are written without a flag. The report describes your code; the work
order changes it, and the one that changes it used to be reachable only by
passing `--prompt-output` — so the artifact that grades you was always on
and the artifact that helps you was off unless you knew to ask.

Set any `outputs.*_path` to `null` to turn that file off. SARIF, JSON and
the PR comment stay off until asked, because they are for other systems to
read rather than for the person at the terminal.

---

## 2. The work order

Three tiers, each with its own instructions, because a flat list gives a
command injection and a variable-name match the same billing.

### §FIX — patch these

The scanner is confident, and the rule has not been measured producing
noise. Each finding carries file and line, the offending snippet, its CWE,
OWASP, ASVS and SSDF anchoring, and a concrete suggested fix.

### §REVIEW — confirm before changing

Either the scanner reported low confidence, or the rule is on the measured
low-precision list. **The reason is stated per finding**, so the agent is
not being told "be careful" without being told why.

A justified suppression is a *successful* outcome for this tier, not a
failure. That is the point of having it: a noisy rule is demoted, never
dropped.

> Bandit's `B105` scored **zero** useful hits out of 22 across the
> calibration corpus — `EMAIL_HOST_PASSWORD = ""`, `PASSWORD_FIELD =
> "password"`, `django-insecure-` — and still caught a planted
> `DB_PASSWORD = "SuperSecret123!"` in a synthetic vulnerable repository.
> Dropping it would lose the credential. Leaving it unlabelled buries the
> credential under noise. So it is labelled, and the *value* is judged as
> well as the rule: twelve characters with a digit and an uppercase letter
> promotes a finding back to §FIX. Checked against all 22 corpus values, it
> promotes none of them.

### §ACCEPT — test tree and documentation

Summarised rather than listed, grouped by rule, with a drafted
`.scignore.yaml` entry. The decision here is per rule, not per line.

> Listing these individually produced a 541KB, 15,390-line work order when
> this tool audited itself — past most context windows and useless to a
> person. The same content is now 111 lines.

§FIX and §REVIEW are capped at 40 blocks each and **say what they left
out**, with a pointer to the JSON report where everything lives. Capping is
fine; capping silently is the absence-of-evidence failure this whole project
exists to prevent.

---

## 3. Fix

Hand the work order to any agent. The hard constraints and patch protocol
travel with it — see [`remediation.md`](remediation.md).

---

## 4. Verify

```bash
secure-code-agent . --verify-against secure-code-report.json
```

Re-audits and compares against the run that produced the order.

| outcome | meaning |
| --- | --- |
| **fixed** | reported before, gone now, and the code actually changed |
| **still open** | reported before and after |
| **silenced** | gone, but only because a suppression or an inline marker now covers it |
| **introduced** | did not exist before this work |
| **deferred** | test tree and documentation — reported, never required |

Exit code is 0 only if the run **passes**: nothing regressed, and either
work was done or there was none to do. A verification step that always
passes verifies nothing.

Two distinctions worth stating, because both were wrong at first:

**"Improved" and "passed" are different questions.** They were one property,
and with nothing to fix, nothing was fixed, so a clean repository exited 1
forever — a CI step that could never go green again, which is a good way to
teach people to delete the CI step. `improved` stays strict for reporting;
`passed` is the gate.

**Silencing is not fixing.** Hard constraint 6 forbids `# nosec`, `# noqa`
and friends, and forbidding is not detecting: Bandit honours `# nosec`
itself, so the finding stops arriving and simply reads as repaired. Measured
on a fixture, two real findings silenced that way reported *"improved: 2
fixed"* and exited 0. Verification now reads the source back around the
reported line and calls it what it is.

---

## 5. Trend

Every run appends one line to `.secure-code/history.jsonl` and prints the
movement:

```
trend: 3.90 (B+) — up 3.86 from 0.04 (F), 3 scored runs
```

Append-only. A malformed line costs one run rather than the history, and
unknown keys from a newer version are ignored so an old reader survives a
new writer. Findings are deliberately *not* stored: they would grow without
bound, duplicate the reports, and — since findings quote source — turn the
history into a second copy of the repository.

A run whose coverage was too thin to grade records `score: null`, and the
trend skips it rather than plotting a collapse to zero that never happened.

---

## In CI

```yaml
- name: Audit
  run: secure-code-agent . --json-output report.json --fail-on-gate

# ... agent applies the work order ...

- name: Prove it helped
  run: secure-code-agent . --verify-against report.json
```

The second step fails the build if the agent silenced findings, introduced
new ones, or left the order undone.
