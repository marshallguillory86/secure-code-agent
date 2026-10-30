<!-- machine translation of README.md; the English README is the complete copy -->
# secure-code-agent

[English](README.md) | **Español** | [Deutsch](README.de.md) | [Français](README.fr.md) | [हिन्दी](README.hi.md) | [简体中文](README.zh-CN.md)

> Traducción automática. El [README en inglés](README.md) es la versión completa y la única que se mantiene al día.

## Qué es

Una puerta de seguridad determinista para repositorios con agentes de programación
con IA. Ejecuta un conjunto fijo de escáneres de seguridad, puntúa el resultado y
convierte cada hallazgo en una **orden de trabajo acotada**: un prompt que dice
*corrige exactamente esto y no cambies nada más*. Los hallazgos se asignan a NIST
SSDF, OWASP ASVS, OWASP Top 10 y MITRE CWE Top 25, y se exportan en SARIF para el
escaneo de código de GitHub. No usa modelos de lenguaje ni envía tu código a
ningún servicio.

## Instalación

```bash
pip install secure-code-agent
```

## Primer uso

```bash
secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md
```

La configuración, los escáneres, las líneas base, la integración con CI y la
GitHub Action se describen en el [README en inglés](README.md).

## Licencia

MIT.
