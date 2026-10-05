"""No adapter may ignore `exclude_patterns` without saying so.

The register says `exclude_patterns` *"stops the scan"*. Four adapters did
honour it, in two different ways — bandit passed the tool its own
`--exclude`, while hadolint, npm_audit and pip_audit filter the inputs they
discover so an excluded path is never handed over at all. The rest took the
bare target root, and nothing anywhere recorded which was which.

That is how trivy came to walk 342 MB of vendored clones in this
repository's own excluded `calibration/.corpus/`, resolve their Maven
dependencies, and be rate-limited into failing — a *required* scanner, for
sixty consecutive runs, hiding 26 real dependency findings in `uv.lock`.

So support is now **declared, not inferred**: `honours_exclusions` is True
and `exclusion_args` returns something, or it is False and
`exclusion_note` says why. This is the lint that keeps the next adapter from
arriving silent, per the rule that an audit naming a bug class ships the
check that blocks the class rather than only fixing the instances.

A note is required rather than optional because "this tool cannot express
it" and "nobody got round to it" look identical in code and are entirely
different facts for an operator reading a slow, noisy scan.
"""

from __future__ import annotations

import inspect
from dataclasses import replace

import pytest

from secure_code_audit import scanners as scanners_pkg
from secure_code_audit.config import Config
from secure_code_audit.scanners.base import Scanner

#: Patterns with one unambiguous directory among them, so an adapter that
#: claims support has something to return.
_CONFIG = replace(Config(), exclude_patterns=["calibration/.corpus/", "**/*.min.js"])


def _adapters() -> list[type[Scanner]]:
    """Every concrete adapter the package exposes."""
    found: list[type[Scanner]] = []
    for name in dir(scanners_pkg):
        obj = getattr(scanners_pkg, name)
        if (
            inspect.isclass(obj)
            and issubclass(obj, Scanner)
            and obj is not Scanner
            and not inspect.isabstract(obj)
        ):
            found.append(obj)
    return sorted(set(found), key=lambda c: getattr(c, "name", c.__name__))


def test_the_adapter_inventory_is_not_empty():
    """A discovery that found nothing would make every check below vacuous."""
    assert len(_adapters()) >= 10, [c.__name__ for c in _adapters()]


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda c: getattr(c, "name", c.__name__))
def test_an_adapter_that_cannot_exclude_says_why(adapter):
    """Silence is the thing being prevented, so the note is mandatory."""
    if adapter.honours_exclusions:
        pytest.skip("declares support; covered by the test below")

    note = (adapter.exclusion_note or "").strip()
    assert note, (
        f"{adapter.name} does not pass exclude_patterns to its tool and gives no reason. "
        "Set exclusion_note to say whether the tool cannot express it, or implement "
        "exclusion_args — an adapter that silently scans excluded paths is how a "
        "required scanner failed for sixty runs here."
    )
    assert len(note) > 20, f"{adapter.name}: {note!r} is too short to be a reason"


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda c: getattr(c, "name", c.__name__))
def test_an_adapter_that_claims_support_actually_excludes_something(adapter):
    """The other half: a True that returns nothing is worse than a False.

    Two mechanisms count, because both genuinely keep excluded paths out of
    the tool: emitting flags from `exclusion_args`, or filtering the inputs
    the adapter discovers before it ever builds a command. The second is how
    hadolint, npm_audit and pip_audit do it, so this accepts an adapter that
    reads `exclude_patterns` in its own discovery instead.
    """
    if not adapter.honours_exclusions:
        pytest.skip("declares no support; covered by the test above")

    emits_flags = bool(adapter().exclusion_args(_CONFIG))
    source = inspect.getsource(adapter)
    filters_inputs = "exclude_patterns" in source

    assert emits_flags or filters_inputs, (
        f"{adapter.name} claims honours_exclusions and neither emits exclusion flags "
        "nor reads exclude_patterns when choosing its inputs. The claim is the part "
        "an operator trusts."
    )


def test_the_base_class_defaults_to_declaring_nothing():
    """A new adapter starts out False, so the lint catches it rather than
    letting it inherit a claim it has not earned."""
    assert Scanner.honours_exclusions is False
    assert Scanner.exclusion_note == ""


def test_the_lint_would_catch_a_silent_new_adapter():
    """The falsifier. Both checks above are parametrized over discovered
    classes, so a discovery that silently stopped matching, or a default that
    flipped to True, would leave them passing on nothing real."""

    class SilentScanner(Scanner):
        name = "silent"
        binary = "silent"

        def scan(self, target, config):  # pragma: no cover - never executed
            raise AssertionError("not run")

    assert SilentScanner.honours_exclusions is False
    assert not (SilentScanner.exclusion_note or "").strip(), (
        "a new adapter must start with no note, or the mandatory-reason check proves nothing"
    )
