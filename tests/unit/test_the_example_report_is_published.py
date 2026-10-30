"""The published example report is complete, current, and self-contained."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

from secure_code_audit import __version__

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "docs" / "example-report.html"
DOMAIN = "secure-code-agent.techportfolio.monster"
PAGES = f"https://{DOMAIN}/"


class _ResourceParser(HTMLParser):
    """Collect resource-bearing elements from the published report."""

    def __init__(self) -> None:
        super().__init__()
        self.resources: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag in {"script", "link", "img", "image", "source", "video", "audio"}:
            self.resources.append((tag, attributes))


def _report_text() -> str:
    assert REPORT.is_file(), f"published report is missing: {REPORT}"
    return REPORT.read_text(encoding="utf-8")


def test_pages_marker_is_committed() -> None:
    """GitHub Pages publishes the committed files without Jekyll processing."""
    assert (ROOT / "docs" / ".nojekyll").is_file()


def test_pages_custom_domain_is_committed() -> None:
    """GitHub Pages publishes the site at the committed custom domain."""
    assert (ROOT / "docs" / "CNAME").read_text(encoding="utf-8").strip() == DOMAIN


def test_published_example_report_tracks_current_package_version() -> None:
    """The published report contains the package version it documents."""
    assert __version__ in _report_text()


def test_published_example_report_is_self_contained() -> None:
    """Scripts, styles, and images in the report load from the page itself."""
    parser = _ResourceParser()
    parser.feed(_report_text())

    for tag, attrs in parser.resources:
        if tag == "script":
            assert "src" not in attrs
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            raise AssertionError("styles must be inline, not loaded through a stylesheet link")
        for attribute in ("src", "href"):
            value = attrs.get(attribute, "")
            assert not value.lower().startswith(("http://", "https://")), (
                f"{tag} {attribute} points outside the published report: {value}"
            )


def test_published_example_report_has_no_absolute_local_paths() -> None:
    """The report does not disclose machine-specific absolute paths."""
    report = _report_text()
    for path_fragment in ("/Users/", "/home/", "/private/tmp", "C:\\"):
        assert path_fragment not in report


def test_readme_links_to_published_reports() -> None:
    """The README points readers to both published report locations."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{PAGES}example-report.html" in readme
    assert f"{PAGES}html/" in readme
    assert "marshallguillory86.github.io/secure-code-agent" not in readme
    assert "outcomes360" not in readme.lower()


def test_contributing_describes_example_report_regeneration() -> None:
    """Release guidance names the step that regenerates the example report."""
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "example-report.html" in contributing
