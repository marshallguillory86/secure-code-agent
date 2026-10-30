<!-- machine translation of README.md; the English README is the complete copy -->
# secure-code-agent

[English](README.md) | [Español](README.es.md) | **Deutsch** | [Français](README.fr.md) | [हिन्दी](README.hi.md) | [简体中文](README.zh-CN.md)

> Maschinelle Übersetzung. Die [englische README](README.md) ist die vollständige und einzige aktuell gehaltene Fassung.

## Was es ist

Ein deterministisches Sicherheits-Gate für Repositories, in denen KI-Coding-Agenten
mitarbeiten. Es führt einen festen Satz von Sicherheitsscannern aus, bewertet das
Ergebnis und macht aus jedem Befund einen **begrenzten Arbeitsauftrag**: einen
Prompt, der sagt *behebe genau das und ändere sonst nichts*. Befunde werden NIST
SSDF, OWASP ASVS, OWASP Top 10 und MITRE CWE Top 25 zugeordnet und als SARIF für
GitHub Code Scanning ausgegeben. Es nutzt kein Sprachmodell und sendet deinen
Code an keinen Dienst.

## Installation

```bash
pip install secure-code-agent
```

## Erster Lauf

```bash
secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md
```

Konfiguration, Scanner, Baselines, CI-Integration und die GitHub Action sind in
der [englischen README](README.md) beschrieben.

## Lizenz

MIT.
