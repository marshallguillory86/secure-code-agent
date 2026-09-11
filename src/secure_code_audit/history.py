"""Scan history — the only thing the score is actually good for.

Marshall, on what the grade is worth: *"The scoring model is really only
valuable for visualizing patterns over time if the score changes. Otherwise
its just a score. wooopee."*

A single B- tells you almost nothing. A B- that was an A- three runs ago
tells you something happened, and a B- that has been a B- for six months
tells you the gate is holding. So every run appends one line, and the line
carries enough to reconstruct the trend without keeping the reports.

**Append-only JSONL, one object per run.** No rewriting, so a corrupted or
half-written line costs one run rather than the history; unknown keys from a
newer version are ignored rather than rejected, so an old reader survives a
new writer.

What is deliberately *not* here: findings. A history file that accumulated
every finding of every run would grow without bound, would duplicate the
reports, and — since findings quote source — would end up being a second
copy of the repository in a file people commit.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

#: Bump when the shape changes in a way a reader must notice.
SCHEMA = 1


@dataclass(frozen=True)
class Entry:
    """One run, reduced to what a trend needs."""

    at: str
    version: str
    #: None when coverage was too thin to score — the distinction the whole
    #: tool rests on, and a trend that silently plotted 0.0 for "we could not
    #: look" would be worse than no trend.
    score: float | None
    letter: str | None
    #: Whether the grade was verified rather than provisional.
    coverage_complete: bool
    gate_passed: bool
    finding_count: int
    loc_scanned: int
    scanners: tuple[str, ...] = ()
    schema: int = SCHEMA
    #: Set by `--verify-against`, so the trend records repair as well as drift.
    verified_improvement: bool | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def entry_from(
    *,
    version: str,
    score,
    gate,
    coverage,
    finding_count: int,
    scanners: tuple[str, ...] = (),
    verified_improvement: bool | None = None,
) -> Entry:
    """Reduce a run to its trend line."""
    complete = coverage is None or getattr(coverage.status, "value", "") == "complete"
    return Entry(
        at=_now(),
        version=version,
        score=score.overall,
        letter=score.letter,
        coverage_complete=bool(complete),
        gate_passed=bool(gate.passed),
        finding_count=finding_count,
        loc_scanned=int(score.loc_scanned or 0),
        scanners=tuple(scanners),
        verified_improvement=verified_improvement,
    )


def append(path: Path, entry: Entry) -> None:
    """Add one run. Never rewrites what is already there.

    Failure here must not fail the audit: history is a convenience, and an
    unwritable path — a read-only checkout, a directory that does not exist
    — is not a reason to discard a security report the operator asked for.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
    except OSError:
        return


def read(path: Path) -> list[Entry]:
    """Every readable run, oldest first.

    A malformed line is skipped rather than raising. The file is appended to
    by every run and may be edited by hand or merged by git; one bad line
    must not make the whole history unreadable.
    """
    if not path.is_file():
        return []
    out: list[Entry] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        known = set(Entry.__dataclass_fields__)
        filtered = {k: v for k, v in raw.items() if k in known}
        if "at" not in filtered:
            continue
        filtered["scanners"] = tuple(filtered.get("scanners") or ())
        filtered["notes"] = tuple(filtered.get("notes") or ())
        try:
            out.append(Entry(**filtered))
        except TypeError:
            continue
    return out


def trend(entries: list[Entry]) -> str:
    """One line an operator can read at the end of a run.

    Comparison is against the last run that produced a *score*. A run whose
    coverage was too thin to grade has no number to compare against, and
    treating its absent score as a change would report movement that did not
    happen.
    """
    scored = [e for e in entries if e.score is not None]
    if not scored:
        return "no scored history yet"
    current = scored[-1]
    if len(scored) == 1:
        return f"first scored run: {current.score:.2f} ({current.letter})"
    previous = scored[-2]
    delta = current.score - previous.score
    if abs(delta) < 0.005:
        return (
            f"{current.score:.2f} ({current.letter}) — unchanged across {len(scored)} scored runs"
        )
    direction = "up" if delta > 0 else "down"
    return (
        f"{current.score:.2f} ({current.letter}) — {direction} "
        f"{abs(delta):.2f} from {previous.score:.2f} ({previous.letter}), "
        f"{len(scored)} scored runs"
    )
