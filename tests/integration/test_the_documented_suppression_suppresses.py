"""The suppression README shows is copied verbatim and has to work.

`paths: ["tests/"]` for Bandit's `B101` is the example in README, `design.md`
and the skill. Until D21 it matched nothing, so an operator who copied it kept
every `assert` in their test tree as a live finding. Audited here the way
`maintainability-agent` runs this tool — an absolute root, from another working
directory — with the real Bandit.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys


def test_the_readme_b101_entry_suppresses_asserts_in_the_test_tree(tmp_path):
    tree = tmp_path / "repo"
    for place in ("tests", "src/tests"):
        (tree / place).mkdir(parents=True)
        (tree / place / "test_app.py").write_text(
            "def test_app():\n    assert 1 + 1 == 2\n", encoding="utf-8"
        )
    (tree / "src" / "app.py").write_text("def f(x):\n    assert x\n", encoding="utf-8")
    expires = (datetime.date.today() + datetime.timedelta(days=90)).isoformat()
    (tree / ".scignore.yaml").write_text(
        '- rule_id: "B101"\n'
        '  paths:   ["tests/"]\n'
        '  reason:  "assert statements are legitimate in test code."\n'
        f'  expires: "{expires}"\n',
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(tree),
            "--only-scanners",
            "bandit",
            "--json-output",
            str(out),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert out.exists(), result.stdout[-800:] + result.stderr[-800:]
    asserts = {
        f["file_path"]: f["suppressed"]
        for f in json.loads(out.read_text(encoding="utf-8"))["findings"]
        if f["rule_id"] == "B101"
    }

    assert asserts == {
        "tests/test_app.py": True,
        "src/tests/test_app.py": True,
        # Outside the directory the entry names: still live.
        "src/app.py": False,
    }, asserts
