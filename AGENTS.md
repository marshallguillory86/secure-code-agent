<!-- WORKSPACE-PREAMBLE v4 — managed by workspace-config. Do not edit below
     this line by hand; edit workspace-config/claude/repo-preamble.md and run
     ./install.sh. Repo-specific rules go AFTER the end marker. -->

# Claude Code — session rules

## Where the rules live

| What | Where |
| --- | --- |
| Core instructions, every project | `~/.claude/CLAUDE.md` |
| The standing rulebook | `~/repos/RULES.md` — read it before acting |
| Source of both, and the hooks | `~/repos/workspace-config` (`./install.sh`) |
| Reference implementation | `~/repos/maintainability-agent` — the most mature repo. Look there first for how a thing is done here. |

The rulebook beats a compaction summary, a wrap-up, or an agent saying "we
decided". **When Marshall states a new rule, write it into
`workspace-config/RULES.md` in the same turn** — not the copy at
`~/repos/RULES.md`, which `install.sh` overwrites.

## Engineering workflow — applies to every repo

**Test-driven development.** The failing test is written first, watched
failing, and only then is the code written to pass it. Per behaviour. Not
tests-eventually, not tests-alongside. A test written after the code describes
the code, including its mistakes.

**Coverage is reported with the work, not when asked.** The house floor is
`fail_under = 92` (see `maintainability-agent/pyproject.toml`). A repo below it
says so out loud.

**Falsifiers are a separate property and do not substitute for TDD.** Watching
a check fail afterwards proves the check bites; it says nothing about what was
never tested at all.

**Roles.** Claude implements. Codex writes tests and edits docs. Grok audits,
in personal repos only. Claude is not tests-only, and does not audit its own
work and call it verified.

**A repo uses only the AI subscriptions its organisation pays for.** The
repo's `.ai-profile` marker names the organisation. Agile Rising
(`agilerising`) pays for Claude and Codex and nothing else. So in an Agile
Rising repo, Grok and Antigravity are never used, not for audits, prompts or
images, and nothing from the repo is sent to them. There, audits go to Codex
and to Claude sub-agents, on a different model from the one that did the work.
The full rule and the model assignments are in `~/repos/RULES.md`.

**Do not invent product intent.** If the documents are silent, ask. In
`maintainability-agent` it is `docs/product-intent.md`.

**PR-first.** Feature branch → `gh pr create` → CI on the PR → merge when
green. **Never `git push` without a fresh, per-push go.** Owner is
`marshallguillory86`, never outcomes360 — verify before push.

**Never discard uncommitted work.** `reset --hard`, `checkout --`, `restore`,
`clean -fd` and `stash` all destroy it and none is undoable. Commit first. A
`PreToolUse` hook enforces this; it exists because that family of command has
destroyed finished work twice.

**Verify, do not assert.** A claim about the state of the world is checked
against the world — the API, the file, the deployed page — and a check that
cannot see what an earlier search found is a check shaped to pass.

**Semantic versioning, for packages and for documents.** `MAJOR.MINOR.PATCH`:
major for a breaking change, minor for a feature or new content, patch for a
fix. Before 1.0 a feature is a minor bump (0.9.1 → 0.10.0).

- **Packages bump at release scope.** Not every fix, and never a long run of
  merged work at a frozen number. When a set of merged work amounts to a
  release, bump it and say which packages moved and why. If the repo does not
  say what a release is, ask.
- **Every content change to a versioned document bumps its version in the same
  commit**, a link fix included: patch for fixes and wording, minor for new
  content or decisions. A version in a file name must match the header, and the
  rendered copy follows. Where a repo has a version lint or hook, it enforces
  this; where it does not, you do.

**Wrap up with: files / tests / still open.**

## CI/CD — and why some repos deliberately do less of it

**GitHub Actions minutes are a real, metered cost he pays.** Several repos were
moved to local gates precisely because CI was burning them. So the shape of a
repo's pipeline is a *decision*, not an oversight, and it is not to be
"improved" without asking.

**Read the repo before assuming the mode:**

| If the repo has | It gates | Do this |
| --- | --- | --- |
| `.pre-commit-config.yaml` and/or a `Makefile` gate target | **locally, on purpose** | run the local gate before every commit; do NOT add workflows to duplicate it |
| `.github/workflows/*.yml` and no local gate | in CI | PR-first, let CI run, merge when green |
| both | locally first, CI as the backstop | run local, keep CI narrow |
| neither | nothing yet | ask before adding either |

Today `cq-team` and `scrollworkapp` are the local-gate repos.
`maintainability-agent`, `trovik-terminal`, `secure-code-agent` and
`practitioner-learning-series` carry real CI.

**Rules that follow:**

- **Never move a gate from local to CI to make it easier for yourself.** That
  spends his money to save your patience.
- **Never add a workflow that duplicates a local gate.** One or the other runs
  a given check.
- **Keep CI narrow and fast.** A job that runs on every push and takes minutes
  is a bill. Prefer one job that runs the same entry point the local gate runs,
  so the two cannot disagree.
- **A required status check must actually run on pull requests.** Requiring a
  context that only runs on `push` deadlocks every merge — this has happened
  here. Verify with `gh api repos/OWNER/REPO/branches/BRANCH/protection`; the
  API is the truth, not a note.
- **`gh pr merge --auto` merges immediately when nothing is required.** Do not
  treat `--auto` as "wait for checks" without confirming protection requires
  them.
- **Deploys are separate from checks.** A deploy workflow that only runs on the
  default branch must never be a required check.
- **Run the checks CI runs, locally, before pushing.** Finding out from a red
  PR is the slow, expensive version of finding out.

<!-- END WORKSPACE-PREAMBLE — repo-specific rules follow -->

## secure-code-agent
