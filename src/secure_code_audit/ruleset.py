"""Profile identity for the rules this project ships.

A finding is only reproducible if you can say *which rules produced it*. STIG
benchmarks solve this with a versioned identity: a named profile, a release
number, and rules that each carry their own version, so an audit result can be
cited and re-run years later against the same baseline. Scanner output alone
cannot do that — "semgrep found 3 things" is not a claim anyone can check.

This module is that identity for the offline profile:

- **id** names the profile,
- **version** is what an operator cites and what changes when rules change,
- **digest** is computed from the shipped file, so a report states not merely
  which version was intended but which bytes actually ran.

The digest matters more than it looks. A version is an assertion by whoever
edited the file; a digest is evidence. If someone edits the ruleset in an
installed wheel, the version still says 1.0.0 and the digest does not.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The offline profile's name. Stable across versions — it is the identity an
#: operator cites, the way a STIG is cited by benchmark rather than by release.
PROFILE_ID = "sca-offline"

#: Bump when rules are added, removed, or their meaning changes. A rule whose
#: pattern is broadened has changed meaning even if its id is unchanged, and a
#: report that cites an unchanged version after that is claiming a comparison
#: it cannot support.
PROFILE_VERSION = "1.0.0"


@dataclass(frozen=True)
class RuleProfile:
    """A named, versioned, verifiable set of rules."""

    id: str
    version: str
    digest: str
    rule_count: int
    #: Distinct CWEs the profile can report, so a reader can see the standards
    #: surface without reading the rules.
    cwes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "digest": self.digest,
            "rule_count": self.rule_count,
            "cwes": list(self.cwes),
        }

    def cite(self) -> str:
        """How the profile is named in a report: id, version, short digest."""
        return f"{self.id}@{self.version} ({self.digest[:12]})"


def describe(path: Path) -> RuleProfile | None:
    """Identify the ruleset actually present at `path`.

    Returns None when the file is missing rather than raising: a missing
    ruleset is already handled as a scanner failure, and this call exists to
    label a run, not to gate it.
    """
    if not path.is_file():
        return None
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        import yaml

        rules = yaml.safe_load(raw.decode("utf-8")).get("rules") or []
    except Exception:
        # An unparseable ruleset still gets an honest identity: we know which
        # bytes are there even when we cannot read what they mean.
        return RuleProfile(PROFILE_ID, PROFILE_VERSION, digest, 0, ())
    cwes = sorted(
        {
            str((rule.get("metadata") or {}).get("cwe"))
            for rule in rules
            if isinstance(rule, dict) and (rule.get("metadata") or {}).get("cwe")
        }
    )
    return RuleProfile(
        id=PROFILE_ID,
        version=PROFILE_VERSION,
        digest=digest,
        rule_count=len(rules),
        cwes=tuple(cwes),
    )
