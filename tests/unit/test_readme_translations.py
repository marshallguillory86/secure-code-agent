"""The README language row, translations, and badge row stay consistent.

Each translation is a short page that points to the English README as the
only complete copy, says it is a machine translation, and carries no version
number, so a README change never leaves it stale. The set of languages is
read from the README's own language row, so a page added to the row without
a file, or a file the row does not reach, fails here.

Each badge is a shields.io image whose target is checked against this
repository: the package name, the owner, and a workflow file that exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")
LANGUAGES = {"es", "de", "fr", "hi", "zh-CN"}
NOTICE = "<!-- machine translation of README.md; the English README is the complete copy -->"


def _language_row(text: str) -> list[str]:
    """Return the translation codes from the first README language row."""
    row = next(line for line in text.splitlines() if "](README." in line)
    return re.findall(r"\]\(README\.([A-Za-z-]+)\.md\)", row)


def test_the_readme_links_exactly_the_expected_languages() -> None:
    assert set(_language_row(README)) == LANGUAGES


@pytest.mark.parametrize("code", sorted(LANGUAGES))
def test_each_translation_is_short_undated_and_points_to_the_english_readme(code: str) -> None:
    text = (ROOT / f"README.{code}.md").read_text(encoding="utf-8")

    assert text.startswith(NOTICE)
    assert "](README.md)" in text
    assert "pip install secure-code-agent" in text
    assert not re.search(r"\b\d+\.\d+\.\d+\b", text), "a version number goes stale"
    assert len(text.split()) < 400 or code == "zh-CN" and len(text) < 2000
    assert set(_language_row(text)) == LANGUAGES - {code}


def _badges(text: str) -> list[tuple[str, str]]:
    """Return the image and link target for every shields.io badge."""
    return re.findall(r"\[!\[[^\]]*\]\((https://img\.shields\.io/[^)]+)\)\]\(([^)]+)\)", text)


def test_every_badge_names_this_package_owner_and_a_real_workflow() -> None:
    badges = _badges(README)
    assert len(badges) >= 4

    for image, link in badges:
        assert "outcomes360" not in image + link
        if "/pypi/" in image:
            assert image.split("/pypi/")[1].split("/")[1].split("?")[0] == "secure-code-agent"
        if "/github/" in image:
            assert "marshallguillory86/secure-code-agent" in image
        for workflow in re.findall(r"workflows/([\w.-]+\.yml)", image + link):
            assert (ROOT / ".github" / "workflows" / workflow).is_file(), workflow


def test_a_badge_for_main_reads_a_workflow_that_runs_on_main() -> None:
    badges = [
        image
        for image, _ in _badges(README)
        if "/github/actions/workflow/status/" in image and "branch=main" in image
    ]
    assert badges, "README has no main-branch workflow status badge"

    for image in badges:
        match = re.search(r"/([^/?#]+\.ya?ml)(?:[?/#]|$)", image)
        assert match, f"could not find a workflow file name in badge URL: {image}"
        workflow = match.group(1)
        document = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        )
        triggers = document.get("on", document.get(True, {}))
        assert isinstance(triggers, dict), f"{workflow} has no workflow triggers"
        push = triggers.get("push")
        assert isinstance(push, dict), f"{workflow} does not trigger on push"
        assert "main" in push.get("branches", []), f"{workflow} does not trigger on push to main"
