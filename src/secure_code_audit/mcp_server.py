"""An MCP door, because almost nobody lives in the CLI.

A reviewer's objection: *"It is named agent and there is no chat door. No
MCP. Skills are files you copy. MA already learned almost nobody lives in the
CLI. This still does."* That is fair, and `maintainability-agent` learned it
first — its server is the reference for the shape used here.

**The server never audits unasked.** `audit_repository` without an explicit
`action` returns a question, not a result. Scanning someone's repository is
not a thing to do because a model inferred it might be useful, and a tool
that audits on mention trains people to stop reading what it did.

**It returns the work order, not only the score.** The score is second class
here by design; the work order is the product, and a chat surface that hands
back a letter grade would invert that.

Optional: `pip install 'secure-code-agent[mcp]'`. Nothing in the package
imports this module unless the server is started, so the dependency stays
off the default install.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from secure_code_audit import __version__


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    """Drive the CLI rather than reimport its internals.

    The CLI is the tested surface: gates, containment, the axis split and
    coverage integrity all live behind it. A second entry point that
    assembled the same pieces differently would be a second set of bugs, and
    the one thing this project cannot afford is two answers to "what did you
    find".
    """
    completed = subprocess.run(
        [sys.executable, "-m", "secure_code_audit.cli", *args],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _audit(path: str, extra: list[str] | None = None) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        return {"error": f"path does not exist: {target}", "audit_ran": False}

    with tempfile.TemporaryDirectory(prefix="sca-mcp-") as tmp:
        report = Path(tmp) / "report.json"
        prompt = Path(tmp) / "work-order.md"
        code, out, err = _run_cli(
            [
                str(target),
                "--json-output",
                str(report),
                "--prompt-output",
                str(prompt),
                # No report, work order, SARIF or baseline is written into
                # the operator's tree from a chat surface — they land in a
                # temp directory and are read back.
                #
                # One thing IS written: `.secure-code/history.jsonl`, this
                # tool's own state directory, because that is how `trend`
                # works across runs and a trend is the score's one genuine
                # use. Saying "writes nothing" would have been the tidier
                # sentence and a false one; a test asserts the tree is
                # otherwise untouched.
                "--output",
                str(Path(tmp) / "report.md"),
                *(extra or []),
            ]
        )
        if not report.is_file():
            return {
                "error": "the audit did not produce a report",
                "exit_code": code,
                "stderr": err[-2000:],
                "audit_ran": False,
            }
        payload = json.loads(report.read_text(encoding="utf-8"))
        work_order = prompt.read_text(encoding="utf-8") if prompt.is_file() else ""

    score = payload.get("score", {})
    coverage = payload.get("coverage", {})
    return {
        "audit_ran": True,
        "exit_code": code,
        "summary": out.strip().splitlines()[:1],
        # The work order first, deliberately. It is the output that changes
        # the code; the score is the one that describes it.
        "work_order": work_order,
        "verified_grade": score.get("verified_grade"),
        "score": score.get("overall"),
        "evidence_status": score.get("evidence_status"),
        "evidence_reasons": score.get("evidence_reasons", []),
        "coverage_status": coverage.get("status"),
        "scanners_missing": [
            s.get("name") for s in coverage.get("scanners", []) if s.get("outcome") != "completed"
        ],
        "gate": payload.get("gate", {}),
        "producer": {"tool": "secure-code-agent", "version": __version__},
    }


def build_server():  # pragma: no cover - exercised by the smoke test below
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("secure-code-agent")

    @server.tool()
    def audit_repository(path: str, action: str | None = None) -> dict[str, Any]:
        """Audit a repository and return its bounded work order.

        `action` must be `"run"` before anything is scanned. Called without
        it, this returns the question instead — auditing someone's code
        because it came up in conversation is not a thing to do quietly.
        """
        if action != "run":
            return {
                "audit_ran": False,
                "choice_needed": (
                    f"Audit {path}? This runs the scanner floor over the tree. "
                    f"No report is written into it; only this tool's own "
                    f"`.secure-code/history.jsonl` trend log is appended. "
                    f"Call again with action='run' to proceed."
                ),
                "options": ["run", "preflight"],
            }
        return _audit(path)

    @server.tool()
    def preflight(path: str) -> dict[str, Any]:
        """Which scanners resolve here, and how to install the ones that do not.

        Read-only and safe to call unasked: it resolves tool paths and runs
        nothing against the code.
        """
        code, out, err = _run_cli([path, "--preflight"])
        return {"audit_ran": False, "exit_code": code, "report": out.strip() or err.strip()}

    @server.tool()
    def agent_info() -> dict[str, Any]:
        """What this tool is for, so a model does not have to guess."""
        return {
            "tool": "secure-code-agent",
            "version": __version__,
            "produces": [
                "a bounded work order an agent can act on (the product)",
                "a coverage report stating what was examined (never inferred)",
                "a score, which is second class to both",
            ],
            "never": [
                "installs a scanner",
                "audits without an explicit action='run'",
                "grades what it could not examine",
            ],
        }

    return server


def main() -> int:
    try:
        server = build_server()
    except ImportError:
        sys.stderr.write(
            "ERROR: the MCP server needs the `mcp` package.\n"
            "       pip install 'secure-code-agent[mcp]'\n"
        )
        return 2
    server.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
