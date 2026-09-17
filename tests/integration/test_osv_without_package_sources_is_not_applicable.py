"""The real osv-scanner, against a tree it has nothing to read in (D23).

The defect this holds shut was not a logic error. It was a comment — "128 on
internal error" — that nobody had checked against the tool, and the adapter
was written to the comment. A mocked exit code cannot catch that class of
mistake, because the mock is written from the same belief as the code. This
test asks the installed binary what it actually does.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secure_code_audit.config import Config
from secure_code_audit.scanner_status import ScannerOutcome
from secure_code_audit.scanners.osv_scanner import OsvScanner

pytestmark = pytest.mark.skipif(
    shutil.which("osv-scanner") is None, reason="osv-scanner is not installed"
)


def test_a_tree_with_no_lockfile_is_not_applicable_rather_than_failed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def main() -> None:\n    print('hello')\n", encoding="utf-8")

    scanner = OsvScanner()
    config = Config()
    scanner.configure(tmp_path, config)
    result = scanner.scan(tmp_path, config)

    assert result.outcome is ScannerOutcome.NOT_APPLICABLE, (
        f"osv-scanner reported {result.outcome.value} for a tree with no package "
        f"sources: {result.reason}"
    )
