"""What ACCESSIBILITY.md says about the outputs stays true.

These claims describe existing behaviour, so these tests may pass on the base
checkout. They are guards for the statement: a change that breaks one fails
here and must correct the statement in the same change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    return root


def test_terminal_output_carries_no_colour_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from secure_code_audit.cli import main

    root = _tree(tmp_path)
    assert (
        main(
            [
                str(root),
                "--only-scanners",
                "builtin_rules",
                "--output",
                str(tmp_path / "report.md"),
                "--prompt-output",
                str(tmp_path / "prompt.md"),
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert captured.out or captured.err
    assert "\x1b[" not in captured.out + captured.err


def test_scanner_version_strips_ansi_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from secure_code_audit.scanners import _resolution
    from secure_code_audit.scanners._resolution import CommandResolution

    class Probe(CommandResolution):
        binary = "probe"
        name = "probe"

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args, 0, stdout="\x1b[32mprobe 1.2.3\x1b[0m\n", stderr=""
        )

    monkeypatch.setattr(_resolution.subprocess, "run", fake_run)
    probe = Probe()
    probe._resolved_command = ("/tools/probe",)

    assert probe.binary_version() == "probe 1.2.3"


def test_project_html_is_self_contained_and_uses_table_headers() -> None:
    for relative in ("docs/index.html", "docs/example-report.html"):
        html = (ROOT / relative).read_text(encoding="utf-8")

        assert '<html lang="en"' in html
        assert not re.search(r"<script\b[^>]+\bsrc\s*=", html, re.IGNORECASE)
        assert not re.search(r"<link\b[^>]+\brel\s*=\s*[\"']stylesheet[\"']", html, re.IGNORECASE)

    assert "<th" in (ROOT / "docs/example-report.html").read_text(encoding="utf-8")


def test_readme_language_row_names_the_accessibility_languages() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    row = next(line for line in readme.splitlines() if "](README." in line)
    assert set(re.findall(r"\]\(README\.([A-Za-z-]+)\.md\)", row)) == {
        "es",
        "de",
        "fr",
        "hi",
        "zh-CN",
    }
