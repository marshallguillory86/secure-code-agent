"""Write the release version into every document that states it.

The number lives once in code: `secure_code_audit.__version__`. Prose cannot
point at it, so these places state it, and each is held by
`tests/unit/test_docs_are_current.py`:

* the `> Status: **vX.Y.Z` line of every document under `docs/` that has one;
* the GitHub Action pin `secure-code-agent@vX.Y.Z` in `README.md` and in
  `examples/github-actions/secure-code.yml`, which is the version a reader
  who copies the example actually gets.

Typing the number into each by hand is a release chore that has been done
wrong before. Run this in the release commit, after the version bump:

    python tools/stamp_version.py --root .

A document that no longer matches its pattern is refused rather than skipped:
silently stopping to stamp a file is the failure this exists to prevent.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

STATUS = re.compile(r"(> Status: \*\*)v[0-9]+\.[0-9]+\.[0-9]+")
ACTION = re.compile(r"(secure-code-agent@)v[0-9]+\.[0-9]+\.[0-9]+")


def version_of(root: Path) -> str:
    """The single source, read as text so this needs no install."""
    source = (root / "src" / "secure_code_audit" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', source)
    if not match:
        raise SystemExit("no __version__ literal in src/secure_code_audit/__init__.py")
    return match.group(1)


def _targets(root: Path) -> list[tuple[Path, re.Pattern[str]]]:
    docs = [
        (path, STATUS)
        for path in sorted((root / "docs").glob("*.md"))
        if STATUS.search(path.read_text(encoding="utf-8"))
    ]
    return [
        *docs,
        (root / "README.md", ACTION),
        (root / "examples" / "github-actions" / "secure-code.yml", ACTION),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True, help="repository root")
    root = parser.parse_args(argv).root.resolve()
    version = version_of(root)

    changed: list[str] = []
    for path, pattern in _targets(root):
        before = path.read_text(encoding="utf-8")
        after, count = pattern.subn(rf"\g<1>v{version}", before)
        if not count:
            print(f"no match for {pattern.pattern!r} in {path.relative_to(root)}", file=sys.stderr)
            return 1
        if after != before:
            path.write_text(after, encoding="utf-8")
            changed.append(path.relative_to(root).as_posix())
    print(f"version {version}")
    print("updated: " + (", ".join(changed) if changed else "nothing, already current"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
