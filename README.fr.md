<!-- machine translation of README.md; the English README is the complete copy -->
# secure-code-agent

[English](README.md) | [Español](README.es.md) | [Deutsch](README.de.md) | **Français** | [हिन्दी](README.hi.md) | [简体中文](README.zh-CN.md)

> Traduction automatique. Le [README anglais](README.md) est la version complète et la seule tenue à jour.

## Ce que c'est

Une porte de sécurité déterministe pour les dépôts où travaillent des agents de
programmation IA. Il exécute un ensemble fixe de scanners de sécurité, note le
résultat et transforme chaque constat en un **ordre de travail borné** : un prompt
qui dit *corrige exactement ceci et ne change rien d'autre*. Les constats sont
rattachés à NIST SSDF, OWASP ASVS, OWASP Top 10 et MITRE CWE Top 25, et exportés en
SARIF pour l'analyse de code GitHub. Il n'utilise aucun modèle de langage et
n'envoie votre code à aucun service.

## Installation

```bash
pip install secure-code-agent
```

## Premier lancement

```bash
secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md
```

La configuration, les scanners, les références, l'intégration CI et la GitHub
Action sont décrits dans le [README anglais](README.md).

## Licence

MIT.
