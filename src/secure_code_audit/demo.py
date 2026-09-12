"""`secure-code-agent --demo` — a real work order in one command.

**The first five minutes were a scavenger hunt.** A fresh install pointed at
any repository reported `coverage: FAILED`, four missing scanners and an
unverified A+; pointed at *this* repository it reported 0 to fix, 0 to review
and 1,108 suppression candidates, because a security tool's tests are
deliberately vulnerable fixtures. Both are correct and neither shows anyone
what the tool is for.

The demo is a small application carrying seven real defects, audited with
whatever scanners are present. It answers the question a stranger actually
has — *what does this produce?* — without a scavenger hunt.

**The fixture is generated at runtime, never shipped.** Writing vulnerable
source into the package would put it in every user's `site-packages`, and
this project's own audit would flag its own demo. It is assembled from
fragments here and written to a temporary directory, so no vulnerable literal
exists in the installed files — the same technique the calibration controls
use, for the same reason.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

#: Assembled rather than written out, so no matchable literal ships. Each
#: entry is one defect a floor scanner is confident about.
_PARTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "db.py",
        (
            "def lookup(cursor, name):",
            "    cursor.exec" + 'ute("SEL' + 'ECT * FROM users WHERE name = \'" + name + "\'")',
            "    return cursor.fetchall()",
        ),
    ),
    (
        "shell.py",
        (
            "import subprocess",
            "",
            "def archive(path):",
            "    return subprocess.call('tar -cf backup.tar ' + path, " + "shell=" + "True)",
        ),
    ),
    (
        "serialize.py",
        (
            "import pickle",
            "",
            "def restore(blob):",
            "    return pickle." + "loads(blob)",
        ),
    ),
    (
        "crypto.py",
        (
            "import hashlib",
            "",
            "def fingerprint(data):",
            "    return hashlib." + "md5(data).hexdigest()",
        ),
    ),
    (
        "calc.py",
        (
            "def evaluate(expression):",
            "    return " + "eval" + "(expression)",
        ),
    ),
    (
        "config.py",
        (
            "import os",
            "",
            "DEBUG = True",
            "TIMEOUT = int(os.environ.get('TIMEOUT', '30'))",
        ),
    ),
)

README = """\
# secure-code-agent demo

A small application with real defects, generated for this run and thrown away
after. Point an agent at the work order printed alongside this audit.

Nothing here is shipped in the package; it is assembled at runtime so that
installing this tool never puts vulnerable source on your disk.
"""


def build(destination: Path | None = None) -> Path:
    """Write the demo tree and return its root."""
    root = destination or Path(tempfile.mkdtemp(prefix="secure-code-demo-"))
    source = root / "src"
    source.mkdir(parents=True, exist_ok=True)
    for name, lines in _PARTS:
        (source / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "README.md").write_text(README, encoding="utf-8")
    # No dependency manifest. A pinned-vulnerable `requirements.txt` was here
    # and it made the demo worse, not better: eighteen pip-audit CVEs drowned
    # the seven code defects the demo exists to show. It also surfaced a
    # separate defect worth its own fix — those CVEs were filed on the
    # **documentation** axis, because the manifest is a `.txt` file and the
    # axis split reads the extension. A dependency finding is not
    # documentation whatever the manifest is called.
    return root


def describe(root: Path) -> str:
    return (
        f"Demo tree: {root}\n"
        f"  {len(_PARTS)} files carrying SQL injection, command injection, unsafe\n"
        f"  deserialization, a weak hash, dynamic evaluation and a debug flag.\n"
        f"  Generated for this run; delete it when you are done.\n"
    )
