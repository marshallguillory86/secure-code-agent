#!/usr/bin/env python3
"""Render every document in this repository into one readable HTML copy.

The markdown stays the source of truth; `docs/html/` is a reading copy of all
of it — the root documents, everything under `docs/`, the calibration study's
README, the skill documents — plus cards for the standalone HTML audit reports
that already live in `docs/audits/`. The whole body of documentation can then
be read in one place instead of file by file.

The set of documents is read from git rather than from a list: a new document
gets a page without anyone remembering to add it, and a file git does not
track is never rendered. The second half decides what is *not* published — a
renderer that walked the directory would pick up any draft or scratch note
lying in the tree.

Output is deterministic — no timestamps — so `tests/unit/test_rendered_docs.py`
can prove the committed copy matches its markdown. Change a document, re-run
this, commit both.

Adapted from `maintainability-agent`'s renderer, which is the reference
implementation for this pattern; styles in `tools/render_docs.css`.

Usage: python3 tools/render_docs.py [output_dir]      # default: docs/html
"""

from __future__ import annotations

import html
import os
import re
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Every git call in this repository goes through `git_tools`: an absolute
# `git`, a fixed argv, never a shell, and a timeout. The first cut of this
# tool invoked a child process itself, and the self-audit flagged it three
# ways — B404 for the import, B603 for the call, B607 for the partial path.
# A docs tool is not the place to become the second thing that shells out.
from secure_code_audit.git_tools import tracked_files  # noqa: E402

STYLES = Path(__file__).with_suffix(".css")
BRAND = "secure-code-agent"
#: Where the reading copy lives, relative to the repository root. Links to
#: repository files are written for here, wherever a given call writes to, so
#: that a copy rendered elsewhere is byte-identical to the committed one.
HOME = Path("docs/html")

#: Groups, in index order. The first matching rule wins; anything unmatched is
#: Reference, so a new document always lands somewhere.
GROUPS: list[tuple[str, object]] = [
    (
        "Start here",
        lambda rel: (
            rel.name in {"README.md", "CONTRIBUTING.md", "SECURITY.md"} and len(rel.parts) == 1
        ),
    ),
    ("Product and intent", lambda rel: rel.name in {"product-intent.md", "design.md"}),
    (
        "Security and standards",
        lambda rel: rel.name in {"threat-model.md", "standards.md", "scanners.md"},
    ),
    ("Scoring and calibration", lambda rel: rel.name in {"scoring.md", "calibration.md"}),
    ("Decisions and architecture", lambda rel: rel.name in {"decisions.md", "architecture.md"}),
    (
        "Work orders and remediation",
        lambda rel: rel.name in {"work-orders.md", "remediation.md", "ma-integration.md"},
    ),
    ("History", lambda rel: rel.name in {"CHANGELOG.md", "release-blockers.md"}),
    (
        "Agent instructions",
        lambda rel: rel.parts[0] in {"skills", ".github"} or rel.name in {"AGENTS.md", "CLAUDE.md"},
    ),
]
DEFAULT_GROUP = "Reference"


def sources(repo: Path) -> list[Path]:
    """Every markdown document git tracks, wherever it lives."""
    return sorted(Path(p) for p in tracked_files(repo, "*.md"))


def standalone_html(repo: Path) -> list[Path]:
    """HTML documents that already exist; the index links them as they are.

    The audit reports under `docs/audits/` are one file per audit, never
    overwritten, and are already readable HTML. Re-rendering them would be
    pointless and copying them would duplicate megabytes per audit.
    """
    listed = tracked_files(repo, "docs/*.html", "docs/**/*.html")
    return sorted(Path(p) for p in listed if not p.startswith("docs/html/"))


def page_name(rel: Path) -> str:
    """One stable page per document, with a name that cannot collide.

    The name is the whole path joined, so it is unique by construction: two
    documents can only produce one name if they are the same file.

    The first cut shortened names by dropping `docs` from the path, which
    read better and was wrong — `calibration/README.md` and
    `docs/calibration.md` both became `calibration.html`, and
    `test_page_names_are_unique` said so. Any rule that discards part of a
    path can be made to collide by adding a document, so the renderer does
    not discard any. The index is the front door; URL prettiness is worth
    less than a page that is always there.

    A version in a file name is dropped, so a bookmarked page survives a
    version bump. That cannot collide: it would need two documents differing
    only by version, and the version-stamped name is itself the thing being
    replaced.

    A leading dot becomes `dot-`, so `.github/…` is `dot-github-…` rather
    than `-github-…`. A filename beginning with a dash is a footgun: every
    shell tool reads it as a flag. The one way to collide is a real directory
    literally named `dot-github`, which is the kind of caveat worth stating
    rather than pretending away.
    """
    stem = re.sub(r"[-_]v\d+\.\d+\.\d+$", "", rel.stem)
    parts = tuple(f"dot-{p[1:]}" if p.startswith(".") else p for p in (*rel.parts[:-1], stem))
    return "-".join(parts).replace(".", "-").lower() + ".html"


def group_of(rel: Path) -> str:
    for name, rule in GROUPS:
        if rule(rel):
            return name
    return DEFAULT_GROUP


def title_of(text: str, rel: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return rel.stem


def _without_first_heading(text: str) -> str:
    """The page prints the title itself, so the body must not repeat it."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("# "):
            return "".join(lines[:index] + lines[index + 1 :])
    return text


def _anchor(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _rewrite_links(body: str, rel: Path, pages: dict[str, str], out_rel: Path) -> str:
    """Point each relative link at its page, or at the file it names."""

    def repl(match: re.Match) -> str:
        href = match.group(1)
        if href.startswith(("http:", "https:", "#", "mailto:")):
            return match.group(0)
        path, _, fragment = href.partition("#")
        target = Path(os.path.normpath(rel.parent / path)).as_posix()
        suffix = f"#{fragment}" if fragment else ""
        if target in pages:
            return f'href="{pages[target]}{suffix}"'
        return f'href="{Path(os.path.relpath(target, out_rel)).as_posix()}{suffix}"'

    return re.sub(r'href="([^"]+)"', repl, body)


def _nav(groups: list[str]) -> str:
    return "".join(f'<a href="index.html#{_anchor(g)}">{html.escape(g)}</a>' for g in groups)


#: Leads every page, before the doctype, and does two jobs at once.
#:
#: A human reading the page learns not to edit it. A consumer reading its
#: head learns the same thing: maintainability-agent honours an `@generated`
#: banner in the first 20 lines, which is how it tells a reading copy from
#: source. Without it MA scored `docs/html/` as source and the numbers moved
#: without anything being found — duplicate blocks doubled, because every
#: page duplicates its own markdown. Raised as maintainability-agent#292 and
#: answered in MA 4.2.0 with this mechanism rather than a directory-name
#: exclusion, which its ADR 010 rejects.
#:
#: The banner must *lead* the line once comment markers are stripped: MA
#: distinguishes a declaration from prose that merely mentions generated
#: code, so that a sentence about codegen cannot remove a team's own file
#: from their own audit.
GENERATED_BANNER = (
    "<!-- @generated by tools/render_docs.py from the Markdown documents in this "
    "repository: edit those, not this page. -->"
)


def _page(title: str, body: str, toc: str, nav: str, meta: str, footer: str) -> str:
    return f"""{GENERATED_BANNER}
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} · {BRAND}</title>
<link rel="stylesheet" href="style.css"></head><body>
<div class="top"><div class="top-inner"><a class="brand" href="index.html">{BRAND} docs</a><nav>{nav}</nav></div></div>
<div class="layout"><aside><p class="label">On this page</p>{toc}</aside>
<main><div class="meta">{meta}</div>{body}
<footer>{footer}</footer>
</main></div></body></html>
"""


def _render_document(
    repo: Path, rel: Path, out: Path, pages: dict[str, str], nav: str
) -> tuple[str, str]:
    """Write one document's page; return its group and title."""
    text = (repo / rel).read_text(encoding="utf-8")
    title = title_of(text, rel)
    converter = markdown.Markdown(
        extensions=["tables", "toc", "fenced_code", "sane_lists"],
        extension_configs={"toc": {"toc_depth": "2-3"}},
    )
    body = converter.convert(_without_first_heading(text))
    body = body.replace("<table>", '<div class="table-wrap"><table>').replace(
        "</table>", "</table></div>"
    )
    body = _rewrite_links(body, rel, pages, HOME)
    footer = (
        f"Rendered from <code>{html.escape(rel.as_posix())}</code> in the {BRAND} "
        "repository. The markdown is the source of truth."
    )
    (out / pages[rel.as_posix()]).write_text(
        _page(
            title, f"<h1>{html.escape(title)}</h1>{body}", converter.toc, nav, group_of(rel), footer
        ),
        encoding="utf-8",
    )
    return group_of(rel), title


def _render_index(
    out: Path, cards: dict[str, list[tuple[str, str, str]]], counts: tuple[int, int], nav: str
) -> None:
    """Write the index: one card per page, grouped, then the standalone reports."""
    filled = [(g, items) for g, items in cards.items() if items]
    sections = "".join(
        f'<h2 id="{_anchor(g)}">{html.escape(g)}</h2><div class="cards">'
        + "".join(
            f'<a class="card" href="{href}"><div class="t">{html.escape(t)}</div>'
            f'<div class="v">{html.escape(sub)}</div></a>'
            for t, href, sub in items
        )
        + "</div>"
        for g, items in filled
    )
    toc = (
        "<ul>"
        + "".join(f'<li><a href="#{_anchor(g)}">{html.escape(g)}</a></li>' for g, _ in filled)
        + "</ul>"
    )
    intro = (
        f"<h1>{BRAND} documentation</h1><p>Every document in the repository, in one "
        f"readable place: {counts[0]} rendered from markdown, plus {counts[1]} standalone "
        "audit reports. The markdown in the repository remains the source of truth.</p>"
    )
    (out / "index.html").write_text(
        _page(
            "Documentation",
            intro + sections,
            toc,
            nav,
            "Index",
            "Rendered by <code>tools/render_docs.py</code>. The markdown is the source of truth.",
        ),
        encoding="utf-8",
    )


def render(repo: Path, out: Path) -> list[Path]:
    """Write the whole reading copy into `out`, replacing what was there."""
    out.mkdir(parents=True, exist_ok=True)
    for old in list(out.glob("*.html")) + list(out.glob("*.css")):
        old.unlink()

    docs = sources(repo)
    pages = {rel.as_posix(): page_name(rel) for rel in docs}
    group_names = [g for g, _ in GROUPS] + [DEFAULT_GROUP]
    nav = _nav(group_names)
    cards: dict[str, list[tuple[str, str, str]]] = {g: [] for g in group_names}
    for rel in docs:
        group, title = _render_document(repo, rel, out, pages, nav)
        cards[group].append((title, pages[rel.as_posix()], rel.as_posix()))

    standalone = [
        (p.stem.replace("_", " "), Path(os.path.relpath(p, HOME)).as_posix(), p.as_posix())
        for p in standalone_html(repo)
    ]
    if standalone:
        cards["Audit reports"] = standalone
    _render_index(out, cards, (len(docs), len(standalone)), nav)
    # Written with a banner rather than copied, for the reason the pages
    # carry one: the copy is generated output. Copied plain, it stayed in the
    # audit after its 26 neighbours had left, and was reported as a 50-line
    # duplicate of the source it is a copy of.
    (out / "style.css").write_text(
        f"/* @generated by tools/render_docs.py from {STYLES.name}: edit that, not this. */\n"
        + STYLES.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return docs


def main(argv: list[str]) -> int:
    out = Path(argv[1]).expanduser() if len(argv) > 1 else ROOT / "docs" / "html"
    docs = render(ROOT, out)
    print(f"rendered {len(docs)} documents and an index to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
