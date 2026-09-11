"""Baseline — incremental adoption.

A baseline is a JSON file mapping `fingerprint → metadata` for findings the
operator has acknowledged at a point in time. On the next run:

  · fingerprint in baseline   → finding.is_new = False (acknowledged)
  · fingerprint not in baseline → finding.is_new = True  (trips fail_on_new)
"""

from __future__ import annotations

import datetime
import enum
import json
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from secure_code_audit.findings import Finding


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    rule_id: str
    severity: str
    category: str
    file_path: str
    first_seen: str  # ISO 8601 UTC
    bumped_by: str  # git user.email when added
    notes: str = ""


class State(enum.Enum):
    """Why the baseline is the shape it is.

    `load` returns an empty mapping for a baseline that is absent, one that
    is unreadable, and one that is genuinely empty. Downstream those look
    identical and every finding reads as new — which is correct for the
    first case, a silent failure for the second, and worth saying out loud
    in all three once `fail_on_new` gates by default.

    On a first run the honest message is "there is nothing to compare
    against yet", not "2 new findings since baseline", which claims a
    baseline exists and that these appeared after it.
    """

    ABSENT = "absent"
    UNREADABLE = "unreadable"
    PRESENT = "present"


def state(path: Path) -> State:
    """Distinguish a missing baseline from a broken one."""
    if not path.exists():
        return State.ABSENT
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return State.UNREADABLE
    return State.PRESENT if isinstance(raw, dict) else State.UNREADABLE


def load(path: Path) -> dict[str, BaselineEntry]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries: dict[str, BaselineEntry] = {}
    for fp, body in (raw.get("entries") or {}).items():
        entries[fp] = BaselineEntry(
            fingerprint=fp,
            rule_id=body.get("rule_id", ""),
            severity=body.get("severity", ""),
            category=body.get("category", ""),
            file_path=body.get("file_path", ""),
            first_seen=body.get("first_seen", ""),
            bumped_by=body.get("bumped_by", ""),
            notes=body.get("notes", ""),
        )
    return entries


def write(path: Path, findings: Iterable[Finding], existing: dict[str, BaselineEntry]) -> None:
    """Rewrite the baseline file. Existing entries' first_seen + bumped_by
    are preserved so a baseline bump only mutates net-new entries."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    operator = _git_user_email()

    entries: dict[str, dict] = {}
    for f in findings:
        if f.suppressed:
            continue
        prev = existing.get(f.fingerprint)
        entries[f.fingerprint] = {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "category": f.category.value,
            "file_path": f.file_path.as_posix(),
            "first_seen": prev.first_seen if prev else now_iso,
            "bumped_by": prev.bumped_by if prev else operator,
            "notes": prev.notes if prev else "",
        }

    path.write_text(
        json.dumps(
            {
                "version": 1,
                "updated": now_iso,
                "operator": operator,
                "entries": entries,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def mark_new(findings: list[Finding], baseline: dict[str, BaselineEntry]) -> list[Finding]:
    """Set is_new=True on findings whose fingerprint is not in the baseline.
    Returns a new list with mutated Finding objects (frozen dataclass →
    replace)."""
    from dataclasses import replace

    out: list[Finding] = []
    for f in findings:
        out.append(replace(f, is_new=f.fingerprint not in baseline))
    return out


def _git_user_email() -> str:
    git = shutil.which("git")
    if git is None:
        return "unknown"
    try:
        r = subprocess.run(
            [git, "config", "user.email"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.stdout.strip() or "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
