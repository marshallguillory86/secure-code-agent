"""Turning the operator's exclude patterns into something a tool understands.

The decision register says `exclude_patterns` *"stops the scan and leaves no
trace in the report"*. Only the second half was true: patterns filtered
findings and LOC after the fact, and every adapter was handed the bare target
root. So excluded directories were scanned in full and then discarded.

On this repository that meant trivy walking `calibration/.corpus/` — 342 MB
of cloned third-party repositories, ten `pom.xml` files among them — and
resolving their dependencies against Maven Central until it was rate-limited
with a 429. That is why a *required* scanner failed, why sixty consecutive
trend rows read `coverage_complete: false`, and why 26 real dependency
findings in `uv.lock` went unreported.

**The invariant that makes this safe.** `findings`-level filtering stays
authoritative. What happens here is an optimisation: it saves work and
network egress. A tool that ignores its flag, or a pattern this module
declines to translate, changes nothing about the report. Correctness never
depends on the translation being complete — only speed does.

That asymmetry decides the design. Under-excluding is the status quo and
costs time; over-excluding silently stops scanning real code, and a silent
gap in coverage is the defect this project exists to find in other people's
pipelines. So this module is deliberately conservative: it passes on only the
patterns whose meaning is the same in every tool's language, and leaves the
rest alone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: In the pattern language of `git_tools.matches_pattern` (D21) a trailing
#: slash means "this directory, at any depth". That is the one form every
#: tool here expresses natively — trivy `--skip-dirs`, semgrep `--exclude`,
#: bandit `-x`, checkov `--skip-path` — so it is the form that travels.
#:
#: A bare name (`conftest.py`) and a file glob (`**/*.min.js`) do not: each
#: tool reads them differently, and a wrong guess over-excludes. They stay
#: with the post-filter, which already handles them.
_DIRECTORY_SUFFIX = "/"


def directory_excludes(patterns: Iterable[str]) -> tuple[str, ...]:
    """The exclude patterns that unambiguously name a directory subtree.

    Order is preserved and duplicates are dropped, so the argv a tool
    receives is stable across runs — an unstable command line shows up as
    noise in `coverage.scanners[].command` and in any diff of two reports.
    """
    out: list[str] = []
    for raw in patterns:
        pattern = (raw or "").strip()
        if not pattern.endswith(_DIRECTORY_SUFFIX):
            continue
        # Trailing slashes carry the directory meaning and are not part of the
        # path; a leading `./` is noise. Both are dropped before the tool sees
        # it, because `--skip-dirs ./x/` and `--skip-dirs x` are the same
        # intent and only one of them matches in every tool.
        cleaned = pattern.rstrip("/")
        while cleaned.startswith("./"):
            cleaned = cleaned[2:]
        cleaned = cleaned.strip()
        # `/`, `./` and `` all normalise to nothing. Passing an empty value
        # would tell the tool to skip its own target: it would report nothing,
        # and before D33 a scan of nothing graded A+. The one outcome worse
        # than the defect being fixed, so it is dropped here rather than
        # guarded for in four adapters.
        if not cleaned or cleaned == "." or cleaned.strip("/") == "":
            continue
        if cleaned not in out:
            out.append(cleaned)
    return tuple(out)


#: `**/` in this pattern language means "at any depth, including the root"
#: (D21). As a regex that is "either nothing, or anything ending in a slash".
_ANY_DEPTH = r"(?:.*/)?"


def as_regex(pattern: str) -> str:
    """A directory pattern as a regex, for a tool whose flag takes one.

    Checkov's `--skip-path` is a regex rather than a glob, and handing it a
    path unescaped is the over-exclusion this module exists to avoid:
    `calibration/.corpus` read as a regex has `.` matching any character, so
    it would also skip `calibration/Xcorpus`. A dot in a directory name is
    ordinary, so every literal is escaped and only the `**/` prefix is given
    back its meaning.
    """
    if pattern.startswith("**/"):
        return _ANY_DEPTH + re.escape(pattern[3:])
    return re.escape(pattern)
