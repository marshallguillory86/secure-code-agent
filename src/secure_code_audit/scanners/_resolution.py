"""Where a scanner's command is, and what it says it is.

Split out of `Scanner`, which had reached 423 lines against a 300-line limit
by carrying four unrelated jobs in one declaration: resolving a command,
running a subprocess, building findings, and constructing outcomes. This is
the first of those. It answers *which program will run* and *can it run at
all* — a question with its own containment rules, its own threat model, and
no dependence on findings or outcomes.

The containment rules are the reason this is worth isolating. Three separate
defects in this file's history were all variations on the same thing: a check
applied on one resolution route and not the others.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from secure_code_audit.config import (
    Config,
    ScannerConfig,
    containment_root,
    is_within,
    target_config_is_untrusted,
    target_executables_allowed,
)

#: CSI escape sequences. Tools colourise `--version` and we store the result.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class CommandResolution:
    """Resolving the scanner binary, and probing its version.

    A mixin of `Scanner`. `name` and `cfg()` come from there; everything
    this declares is its own.
    """

    name: str  # supplied by Scanner
    binary: str  # name of the executable on PATH
    version_flag: str = "--version"
    python_module: str | None = None
    #: True when the audited tree's own config set this scanner's command and
    #: it was not honoured. See `configure`.
    ignored_command: bool = False

    def configure(self, target: Path, config: Config) -> None:
        """Resolve the command once so probing and execution use the same tool.

        The containment root is computed **first** and used for every
        decision below it. It was computed last, on the line after the two
        calls that needed it, so both of those compared against the raw
        target — and for a single-file audit nothing lives beneath a regular
        file, so both inverted to "allowed".
        """
        root = containment_root(target)
        self._allow_target_executables = target_executables_allowed(config, target)
        chosen = self.cfg(config)
        # An untrusted config does not choose the command — not just "not an
        # executable from the tree". It could name any program on PATH with
        # any arguments, and `python -c "<code>"` is any program; the
        # `--version` probe ran it during preflight, before anything was
        # audited (maintainability-agent's audit, 2026-10-02). The scanner
        # resolves as it would with no config, and says it ignored one.
        self.ignored_command = bool(chosen.command) and target_config_is_untrusted(config, target)
        if self.ignored_command:
            chosen = dataclasses.replace(chosen, command=[])
        self._resolved_command = self._resolve_command(root, chosen)

    @property
    def command(self) -> tuple[str, ...]:
        resolved = getattr(self, "_resolved_command", None)
        if resolved is not None:
            return resolved
        found = shutil.which(self.binary) if self.binary else None
        return (found,) if found else ()

    def _resolve_command(self, root: Path, config: ScannerConfig) -> tuple[str, ...]:
        """`root` is the containment root — a directory, never a file target."""
        resolved = self._resolve_candidate(root, config)
        if not resolved:
            return ()
        # One containment check for every resolution route, not just the
        # relative-path one. PATH can contain '.' or a tree-local directory, so
        # checking only the explicit-path branch would leave the same door open
        # a step to the left.
        if not getattr(self, "_allow_target_executables", False) and is_within(
            Path(resolved[0]), root
        ):
            return ()
        return resolved

    def _resolve_candidate(self, root: Path, config: ScannerConfig) -> tuple[str, ...]:
        if config.command:
            executable, *arguments = config.command
            candidate = Path(executable).expanduser()
            if candidate.is_absolute() or "/" in executable or "\\" in executable:
                if not candidate.is_absolute():
                    # Against the containment root. Joining onto a file target
                    # produced `app.py/scanner`, which resolves to nothing and
                    # quietly returned "no command" for a reason unrelated to
                    # the guard that should have refused it.
                    candidate = root / candidate
                candidate = candidate.resolve()
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return (str(candidate), *arguments)
                return ()
            found = shutil.which(executable)
            return (found, *arguments) if found else ()

        found = shutil.which(self.binary) if self.binary else None
        if found:
            return (found,)
        if self.python_module and importlib.util.find_spec(self.python_module) is not None:
            return (sys.executable, "-m", self.python_module)
        return ()

    def is_available(self) -> bool:
        return bool(self.command)

    def binary_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            r = subprocess.run(
                [*self.command, self.version_flag],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        # A failed probe is not a version. Reporting stderr here put
        # "Error: unknown flag: --version" in the version column of a report
        # that was otherwise claiming the scanner had run fine.
        if r.returncode != 0:
            return None
        # Strip ANSI colour before picking a line, and skip lines that were
        # nothing but colour. njsscan opens its version output with a bare
        # `\x1b[34m` on its own line and puts the version on the next one, so
        # taking the first line recorded the scanner version as `[34m` — in
        # the coverage block, in every report, and in a calibration study
        # whose whole claim is that it re-derives from pinned inputs.
        raw = r.stdout or r.stderr or ""
        for line in _ANSI.sub("", raw).splitlines():
            cleaned = line.strip()
            if cleaned:
                return cleaned
        return None
