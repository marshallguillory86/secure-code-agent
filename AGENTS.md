<!-- WORKSPACE-PREAMBLE v10 — managed centrally. Do not edit below this line
     by hand; its source and installer are named at the top of
     ~/repos/RULES.md. Repo-specific rules go AFTER the end marker. -->

# Agent rules

The standard every repository here follows is not copied into it. Each agent
loads it from its own global file, kept current from one source:

| Agent | Global file |
| --- | --- |
| Claude | `~/.claude/CLAUDE.md`, which imports `~/.claude/workspace-standard.md` |
| Codex | `~/.codex/AGENTS.md` |
| Grok | `~/.grok/AGENTS.md` |
| Antigravity | the `workspace-rules` plugin |

The standing rulebook is `~/repos/RULES.md`. If none of these loaded, read
`~/.claude/workspace-standard.md` and `~/repos/RULES.md` before acting.

<!-- END WORKSPACE-PREAMBLE — repo-specific rules follow -->

## secure-code-agent
