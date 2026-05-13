#!/usr/bin/env bash
# Local CI script — drop this in any repo to run secure-code-agent + a few
# common scanners as a local pre-merge gate. Mirrors what the GitHub Action
# does, minus the SARIF upload.

set -euo pipefail

CONFIG="${CONFIG:-secure-code-agent.json}"
PATHS="${1:-.}"

echo "==> secure-code-agent local pipeline"
echo "    config: ${CONFIG}"
echo "    paths:  ${PATHS}"

secure-code-agent \
  --config         "${CONFIG}" \
  --fail-on-gate \
  --output         secure-code-report.md \
  --json-output    secure-code-report.json \
  --sarif-output   secure-code.sarif \
  --prompt-output  secure-code-remediation-prompt.md \
  --comment-output secure-code-pr-comment.md \
  "${PATHS}"

echo "==> gate passed."
echo "    report:      secure-code-report.md"
echo "    sarif:       secure-code.sarif"
echo "    remediation: secure-code-remediation-prompt.md"
