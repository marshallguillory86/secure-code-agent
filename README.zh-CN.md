<!-- machine translation of README.md; the English README is the complete copy -->
# secure-code-agent

[English](README.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [Français](README.fr.md) | [हिन्दी](README.hi.md) | **简体中文**

> 机器翻译。[英文 README](README.md) 是唯一完整且持续更新的版本。

## 简介

一个面向有 AI 编码代理参与的代码仓库的确定性安全关卡。它运行一组固定的安全扫描器，
为结果评分，并把每个发现转换为一份**有边界的工作单**：一条提示，内容是
*只修复这一处，其他什么都不要改*。发现会映射到 NIST SSDF、OWASP ASVS、
OWASP Top 10 和 MITRE CWE Top 25，并以 SARIF 格式输出，供 GitHub 代码扫描使用。
它不使用语言模型，也不会把你的代码发送给任何服务。

## 安装

```bash
pip install secure-code-agent
```

## 首次运行

```bash
secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md
```

配置、扫描器、基线、CI 集成以及 GitHub Action 的说明见[英文 README](README.md)。

## 许可证

MIT。
