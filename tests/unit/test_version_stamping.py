"""The version-stamping tool keeps every release claim current.

The tool is loaded from ``tools/stamp_version.py`` with importlib and exposes
``main(argv)`` with a required ``--root PATH`` option. The implementation is
intentionally absent at this red-test stage; these tests therefore fail until
the tool is added.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "stamp_version.py"
VERSION = re.search(
    r'__version__\s*=\s*"([^"]+)"',
    (ROOT / "src" / "secure_code_audit" / "__init__.py").read_text(encoding="utf-8"),
).group(1)
STATUS_PATTERN = re.compile(r"(> Status: \*\*)v[0-9]+\.[0-9]+\.[0-9]+")
ACTION_PATTERN = re.compile(r"(secure-code-agent@)v[0-9]+\.[0-9]+\.[0-9]+")


def _load_tool():
    assert TOOL.is_file(), f"missing version-stamping tool: {TOOL}"
    spec = importlib.util.spec_from_file_location("stamp_version", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stamped_paths(root: Path) -> list[Path]:
    return [
        *sorted(
            path
            for path in (root / "docs").glob("*.md")
            if STATUS_PATTERN.search(path.read_text(encoding="utf-8"))
        ),
        root / "README.md",
        root / "examples" / "github-actions" / "secure-code.yml",
    ]


def _copy_release_claims(tmp_path: Path) -> Path:
    copy = tmp_path / "repo"
    for source in _stamped_paths(ROOT):
        target = copy / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = source.read_text(encoding="utf-8")
        text = STATUS_PATTERN.sub(r"\1v0.0.1", text)
        text = ACTION_PATTERN.sub(r"\1v0.0.1", text)
        target.write_text(text, encoding="utf-8")

    source = ROOT / "src" / "secure_code_audit" / "__init__.py"
    target = copy / source.relative_to(ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    (copy / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copy2(TOOL, copy / "tools" / "stamp_version.py")
    return copy


def _claims(root: Path) -> list[str]:
    return [path.read_text(encoding="utf-8") for path in _stamped_paths(root)]


def _assert_current_claims(root: Path) -> None:
    for path in _stamped_paths(root):
        text = path.read_text(encoding="utf-8")
        if path.parent.name == "docs":
            versions = re.findall(r"> Status: \*\*v([0-9]+\.[0-9]+\.[0-9]+)", text)
            assert versions == [VERSION], path
        else:
            versions = re.findall(r"secure-code-agent@v([0-9]+\.[0-9]+\.[0-9]+)", text)
            assert versions == [VERSION], path


def test_stamping_old_release_claims_updates_every_document(tmp_path: Path) -> None:
    tool = _load_tool()
    copy = _copy_release_claims(tmp_path)

    assert tool.main(["--root", str(copy)]) == 0

    _assert_current_claims(copy)


def test_the_real_tree_is_already_stamped() -> None:
    tool = _load_tool()
    before = _claims(ROOT)

    assert tool.main(["--root", str(ROOT)]) == 0
    assert _claims(ROOT) == before
    _assert_current_claims(ROOT)


def test_a_document_that_stops_matching_is_refused_not_skipped(tmp_path: Path) -> None:
    tool = _load_tool()
    copy = _copy_release_claims(tmp_path)
    readme = copy / "README.md"
    readme.write_text(
        re.sub(
            r"\n- uses: marshallguillory86/secure-code-agent@v[0-9.]+",
            "",
            readme.read_text(encoding="utf-8"),
        ),
        encoding="utf-8",
    )

    assert tool.main(["--root", str(copy)]) != 0
