from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
LANDING_PAGE = DOCS / "index.html"
PAGES_URL = "https://secure-code-agent.techportfolio.monster/"


class LandingPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.start_tags: list[tuple[str, dict[str, str]]] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_tags.append((tag, {name: value or "" for name, value in attrs}))

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)


def parse_landing_page() -> tuple[str, LandingPageParser]:
    html = LANDING_PAGE.read_text(encoding="utf-8")
    parser = LandingPageParser()
    parser.feed(html)
    return html, parser


def tags(parser: LandingPageParser, name: str) -> list[dict[str, str]]:
    return [attrs for tag, attrs in parser.start_tags if tag == name]


def test_landing_page_exists_and_declares_english() -> None:
    assert LANDING_PAGE.is_file()
    _, parser = parse_landing_page()

    html_tags = tags(parser, "html")
    assert html_tags
    assert html_tags[0].get("lang") == "en"


def test_landing_page_has_an_existing_branded_image_with_accessible_dimensions() -> None:
    _, parser = parse_landing_page()
    images = tags(parser, "img")

    assert images
    image = images[0]
    image_path = (DOCS / image["src"]).resolve()
    assert image_path.is_file()
    assert image_path.is_relative_to((DOCS / "brand").resolve())
    assert image["alt"]
    assert len(image["alt"]) >= 20
    assert int(image["width"]) >= 1
    assert int(image["height"]) >= 1


def test_landing_page_links_the_site_destinations_and_project_pages() -> None:
    _, parser = parse_landing_page()
    hrefs = {anchor.get("href") for anchor in tags(parser, "a")}

    assert "example-report.html" in hrefs
    assert "html/" in hrefs
    assert "https://github.com/marshallguillory86/secure-code-agent" in hrefs
    assert "https://pypi.org/project/secure-code-agent/" in hrefs


def test_landing_page_shows_the_install_command() -> None:
    _, parser = parse_landing_page()

    assert "pip install secure-code-agent" in "".join(parser.text_parts)


def test_landing_page_has_social_metadata_for_pages() -> None:
    _, parser = parse_landing_page()
    properties = {
        meta["property"]: meta.get("content", "")
        for meta in tags(parser, "meta")
        if "property" in meta
    }
    names = {
        meta["name"]: meta.get("content", "") for meta in tags(parser, "meta") if "name" in meta
    }

    assert properties.get("og:title")
    assert properties.get("og:description")
    image_url = properties.get("og:image", "")
    assert image_url.startswith(PAGES_URL)
    image_path = Path(urlparse(image_url).path.lstrip("/"))
    assert (DOCS / image_path).is_file()
    assert properties.get("og:url") == PAGES_URL
    assert names.get("twitter:card") == "summary_large_image"


def test_landing_page_keeps_embedded_resources_local() -> None:
    html, parser = parse_landing_page()

    assert tags(parser, "style")
    assert not tags(parser, "script") or all("src" not in attrs for attrs in tags(parser, "script"))
    assert not tags(parser, "link") or all(
        "stylesheet" not in attrs.get("rel", "").lower().split() for attrs in tags(parser, "link")
    )
    for tag in ("script", "link", "img"):
        assert all(
            not attrs.get(attribute, "").lower().startswith(("http://", "https://"))
            for attrs in tags(parser, tag)
            for attribute in ("src", "href")
        )
    assert "<script src" not in html.lower()


def test_landing_page_does_not_name_the_other_project() -> None:
    html, _ = parse_landing_page()

    assert "outcomes360" not in html.lower()


def test_landing_page_does_not_use_the_github_pages_url() -> None:
    """The landing page does not retain the former GitHub Pages URL."""
    html, _ = parse_landing_page()

    assert "marshallguillory86.github.io/secure-code-agent" not in html
