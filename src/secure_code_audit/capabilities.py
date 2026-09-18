"""What a project declares it does, and the findings that follow from it.

Some findings are not defects and never will be. A tool that runs external
analyzers imports `subprocess` and spawns them; a tool that reads analyzer
output parses XML it did not write. Bandit reports both, correctly — the
observation is true. What was missing is any way for the project to say "yes,
that is what this is", so the same findings were reported as defects on every
run forever.

The instruments that existed could only hide them. `exclude_patterns` stops
the scan. `extra_args: --skip` turns the check off. Both leave a report that
says nothing, which is the silence this tool exists to refuse — the same shape
`_conformance` counts as a defect when it finds `NOSONAR` in someone else's
tree. `.scignore.yaml` states a reason, but a suppression expires, and an
architectural fact does not stop being true in a year; renewing it annually is
a ritual that teaches people to renew rituals.

A declaration is different from all three. The operator states, in the config,
what the project does. Findings consistent with that declaration are routed to
their own axis: **counted, listed in the report, and not scored**. Nothing is
hidden, nothing expires, and a subprocess call written next year is already
covered rather than generating a new exception.

**Declared, never inferred.** The tool does not decide that a project looks
like it spawns processes. It is told, in a file a reviewer reads, and the
report names the declaration next to the findings it accounts for. Inference
here would make the grade depend on a guess about the codebase, which is the
property this rubric does not have anywhere else.

**A declaration is falsifiable.** Declaring a capability the project does not
exercise is itself reported (`unexercised`), so the config cannot be padded
with pre-emptive declarations against findings that might arrive later.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from secure_code_audit.findings import Finding

#: Capability name -> the rule ids whose finding *is* that capability being
#: exercised. Deterministic and enumerated rather than pattern-matched: a
#: reader can see exactly which observations a declaration accounts for, and
#: a rule absent from this table is never routed by it.
#:
#: Scoped narrowly on purpose. `spawns_processes` covers the reports that say
#: "this code starts a process", not every report that happens to occur in a
#: file that also starts one. B602 (`shell=True`) is deliberately **not**
#: here: spawning a process is architecture, handing a string to a shell is a
#: decision, and a project that declares the former has not excused the latter.
CAPABILITY_RULES: dict[str, frozenset[str]] = {
    "spawns_processes": frozenset(
        {
            "B404",  # import subprocess
            "B603",  # subprocess call without shell
            "B606",  # start process with no shell
            "B607",  # start process with a partial executable path
        }
    ),
    "parses_untrusted_xml": frozenset(
        {
            "B313",  # xml.etree.cElementTree
            "B314",  # xml.etree.ElementTree
            "B405",  # import xml.etree
            "B406",  # import xml.sax
            "B408",  # import xml.minidom
            "B409",  # import xml.pulldom
        }
    ),
    "fetches_remote_urls": frozenset(
        {
            "B310",  # urllib.request.urlopen
        }
    ),
    "uses_nondeterministic_randomness": frozenset(
        {
            "B311",  # random, not suitable for cryptography
        }
    ),
}

#: The axis a declared finding is reported on, prefixed so a reader of the
#: report can tell a declaration apart from a path-derived side axis.
AXIS_PREFIX = "declared: "


@dataclass(frozen=True)
class DeclarationReport:
    """What the declarations accounted for, for the report to state."""

    #: Capability -> the operator's stated reason, as written in the config.
    declared: dict[str, str]
    #: Capability -> how many findings it accounted for.
    accounted: dict[str, int]
    #: Declared, and nothing matched it. A declaration that describes nothing
    #: this project does is reported rather than ignored, because a config can
    #: otherwise be padded against findings that have not arrived yet.
    unexercised: tuple[str, ...]

    @property
    def total_accounted(self) -> int:
        return sum(self.accounted.values())


def unknown_capabilities(declared: Iterable[str]) -> tuple[str, ...]:
    """Declared names this build has no rules for.

    A typo in a capability name would otherwise declare nothing and route
    nothing, silently, and the operator would read a report that still scored
    the findings they thought they had accounted for.
    """
    return tuple(sorted(name for name in declared if name not in CAPABILITY_RULES))


def capability_for(finding: Finding, declared: Iterable[str]) -> str | None:
    """The declared capability this finding is an instance of, or None."""
    for name in declared:
        if finding.rule_id in CAPABILITY_RULES.get(name, frozenset()):
            return name
    return None


def summarize_declarations(
    declared: dict[str, str], findings: Iterable[Finding]
) -> DeclarationReport:
    """Count what each declaration accounted for, and what accounted for nothing."""
    accounted = dict.fromkeys(declared, 0)
    for finding in findings:
        name = capability_for(finding, declared)
        if name is not None:
            accounted[name] += 1
    return DeclarationReport(
        declared=dict(declared),
        accounted=accounted,
        unexercised=tuple(sorted(n for n, count in accounted.items() if count == 0)),
    )
