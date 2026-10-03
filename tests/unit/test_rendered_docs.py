"""The documentation, all of it, in one readable form that cannot go stale.

`docs/html/` is a reading copy of every document this repository tracks. The
markdown stays the source of truth; `tools/render_docs.py` produces the copy.

A reading copy is only worth having if it is complete and current, so both
are enforced rather than hoped for. The set of documents is read from git, not
from a list someone has to remember to extend — a new document with no page
fails here, and so does a committed page that no longer matches its markdown.
That is docs-as-code applied to the docs' own presentation: if the copy can
drift without anything failing, it is decoration.

Reading the set from git also decides what is *not* published. A renderer
that walked the directory would pick up anything untracked that happened to be
lying in the tree — a draft, a scratch note, an agent's working file.

Adapted from `maintainability-agent`'s `tools/render_docs.py` and
`tests/test_rendered_docs.py`, which is the reference implementation for this
pattern. The differences are this repository's: every tracked markdown file is
rendered rather than only root and `docs/`, because `calibration/README.md` and
the skill documents are documents too; and `docs/audits/` holds standalone HTML
reports the index links as they are.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "render_docs.py"
HTML = ROOT / "docs" / "html"


def _load():
    """Import the renderer as a module, so these tests exercise it directly.

    `markdown` is a dev dependency, and this whole file skips without it.
    That is not politeness: the renderer imports it at module scope, so a
    bare `import` here failed collection in any environment that does not
    have it — including maintainability-agent's own virtualenv, which runs
    this repository's declared test command. It reported `pytest exited 2`
    and scored `test_effectiveness` as not measurable, undoing the fix that
    made the suite measurable at all a few hours earlier.

    Same shape as `test_one_coverage_floor.py`'s `tomllib` skip, and for the
    same reason: skip on the environment that lacks the tool rather than
    taking the suite down with it.
    """
    pytest.importorskip("markdown", reason="markdown is a dev dependency of the docs renderer")
    if not TOOL.is_file():
        pytest.fail(f"{TOOL} does not exist; the reading copy has no renderer")
    spec = importlib.util.spec_from_file_location("render_docs", TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_docs"] = module
    spec.loader.exec_module(module)
    return module


render_docs = _load()


def _git(*args: str) -> list[str]:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout.split()


def _tracked_documents() -> set[str]:
    """Every markdown file git tracks, wherever it lives."""
    return set(_git("ls-files", "*.md"))


def test_the_document_set_is_read_from_git():
    """A list of documents in the tool would rot the first time one is added."""
    expected = _tracked_documents()
    assert len(expected) >= 20, (
        f"only {len(expected)} documents found; the population is wrong and every "
        "check below would be measuring almost nothing"
    )

    assert {str(p) for p in render_docs.sources(ROOT)} == expected


def test_every_tracked_document_has_a_page():
    missing = [
        rel
        for rel in sorted(_tracked_documents())
        if not (HTML / render_docs.page_name(Path(rel))).is_file()
    ]

    assert not missing, f"documents with no rendered page — run tools/render_docs.py: {missing}"


def test_page_names_are_unique():
    """Two documents are called README.md, and both still get their own page."""
    names = [render_docs.page_name(p) for p in render_docs.sources(ROOT)]

    assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)


def test_an_untracked_file_is_never_rendered(tmp_path):
    """Walking the directory would publish whatever is lying in the tree.

    A draft, a scratch note, an agent's working file: none of them is a
    document this repository publishes, and the difference is that git does
    not track them.
    """
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (tmp_path / "scratch-note.md").write_text("# Not a document\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "README.md", "docs/guide.md"], check=True)

    assert {str(p) for p in render_docs.sources(tmp_path)} == {"README.md", "docs/guide.md"}


def test_the_index_reaches_every_page_and_every_standalone_report():
    """An unreachable page is a document nobody can find from the front door."""
    index = (HTML / "index.html").read_text(encoding="utf-8")
    pages = {render_docs.page_name(p) for p in render_docs.sources(ROOT)}
    standalone = [
        p
        for p in _git("ls-files", "docs/*.html", "docs/**/*.html")
        if not p.startswith("docs/html/")
    ]
    assert standalone, "no standalone HTML reports found; half this check reads nothing"

    unreached = sorted(p for p in pages if f'href="{p}"' not in index)
    unreached += sorted(p for p in standalone if Path(p).name not in index)

    assert not unreached, f"the index does not link: {unreached}"


def test_every_link_between_pages_resolves():
    """A cross-document link must land on a page, not a 404."""
    broken = []
    for page in HTML.glob("*.html"):
        text = page.read_text(encoding="utf-8")
        for target in re.findall(r'href="([^"#:]+\.html)(?:#[^"]*)?"', text):
            if "/" not in target and not (HTML / target).is_file():
                broken.append(f"{page.name} -> {target}")

    assert not broken, broken[:20]


def test_rendering_is_deterministic(tmp_path):
    """No timestamps: the same markdown always renders the same bytes.

    Without this the freshness check below could never pass twice, and the
    committed copy would churn on every run.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    render_docs.render(ROOT, first)
    render_docs.render(ROOT, second)

    assert sorted(p.name for p in first.iterdir()) == sorted(p.name for p in second.iterdir())
    for page in sorted(first.iterdir()):
        assert page.read_bytes() == (second / page.name).read_bytes(), page.name


def test_the_committed_copy_is_current(tmp_path):
    """A document changed without re-rendering fails here, not in a reader's tab.

    This is the check that makes the rendered copy generated rather than
    hand-maintained: it cannot be edited into agreement, only re-rendered.
    """
    fresh = tmp_path / "html"
    render_docs.render(ROOT, fresh)

    stale = sorted(
        p.name
        for p in fresh.iterdir()
        if not (HTML / p.name).is_file() or (HTML / p.name).read_bytes() != p.read_bytes()
    )
    orphaned = sorted(p.name for p in HTML.iterdir() if not (fresh / p.name).exists())

    assert not stale and not orphaned, (
        "docs/html is out of date — run `python3 tools/render_docs.py`. "
        f"stale: {stale[:10]} orphaned: {orphaned[:10]}"
    )
