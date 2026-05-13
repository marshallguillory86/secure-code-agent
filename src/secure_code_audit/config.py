"""Config loader. Reads secure-code-agent.json (or operator-pointed path),
validates against the schema, and exposes a Config dataclass."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("secure-code-agent.json")

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git/", "node_modules/", ".venv/", "venv/", "dist/", "build/",
    "__pycache__/", ".pytest_cache/", ".ruff_cache/", ".mypy_cache/",
    "**/*.min.js", "**/*.lock",
)

DEFAULT_INCLUDE_EXTS: tuple[str, ...] = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".rb",
    ".sh", ".yaml", ".yml", ".json", "Dockerfile",
)

DEFAULT_OUTPUTS: dict[str, str] = {
    "markdown_path": "secure-code-report.md",
    "json_path":     "secure-code-report.json",
    "sarif_path":    "secure-code.sarif",
    "comment_path":  "secure-code-pr-comment.md",
    "prompt_path":   "secure-code-remediation-prompt.md",
    "baseline_path": "secure-code-baseline.json",
}


@dataclass
class ScannerConfig:
    enabled:         bool          = True
    timeout_seconds: int           = 600
    online:          bool          = False
    extra_args:      list[str]     = field(default_factory=list)


@dataclass
class Config:
    """Parsed config. Operator-facing access is via attribute names."""
    version:           int                                = 1
    asvs_level:        int                                = 2
    include_extensions: tuple[str, ...]                   = DEFAULT_INCLUDE_EXTS
    exclude_patterns:  tuple[str, ...]                    = DEFAULT_EXCLUDES
    scanners:          dict[str, ScannerConfig]           = field(default_factory=dict)
    severity_overrides: dict[str, str]                    = field(default_factory=dict)
    category_overrides: dict[str, str]                    = field(default_factory=dict)
    gates:             dict[str, Any]                     = field(default_factory=dict)
    outputs:           dict[str, str]                     = field(default_factory=lambda: dict(DEFAULT_OUTPUTS))
    suppressions_file: str                                = ".scignore.yaml"
    loc_for_scoring:   dict[str, Any] | None              = None
    raw:               dict[str, Any]                     = field(default_factory=dict)


def load(path: Path | str | None = None) -> Config:
    """Load config from path. Missing file → defaults. Malformed file → ValueError."""
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    if not p.exists():
        return Config()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"{p}: invalid JSON: {e}") from e
    return _from_dict(raw)


def _from_dict(raw: dict[str, Any]) -> Config:
    cfg = Config(raw=raw)
    cfg.version    = int(raw.get("version", 1))
    cfg.asvs_level = int(raw.get("asvs_level", 2))
    if cfg.asvs_level not in (1, 2, 3):
        raise ValueError(f"asvs_level must be 1, 2, or 3; got {cfg.asvs_level}")

    paths = raw.get("paths") or {}
    if isinstance(paths.get("include_extensions"), list):
        cfg.include_extensions = tuple(paths["include_extensions"])
    if isinstance(paths.get("exclude_patterns"), list):
        cfg.exclude_patterns = tuple(paths["exclude_patterns"])

    scanners_raw = raw.get("scanners") or {}
    for name, sc_raw in scanners_raw.items():
        cfg.scanners[name] = ScannerConfig(
            enabled=bool(sc_raw.get("enabled", True)),
            timeout_seconds=int(sc_raw.get("timeout_seconds", 600)),
            online=bool(sc_raw.get("online", False)),
            extra_args=list(sc_raw.get("extra_args") or []),
        )

    cfg.severity_overrides = {
        str(k): str(v).lower() for k, v in (raw.get("severity_overrides") or {}).items()
    }
    cfg.category_overrides = {
        str(k): str(v).lower() for k, v in (raw.get("category_overrides") or {}).items()
    }
    cfg.gates = dict(raw.get("gates") or {})

    outputs = raw.get("outputs") or {}
    for k, default_v in DEFAULT_OUTPUTS.items():
        cfg.outputs[k] = outputs.get(k, default_v)

    if "suppressions_file" in raw:
        cfg.suppressions_file = str(raw["suppressions_file"])

    if "loc_for_scoring" in raw:
        cfg.loc_for_scoring = raw["loc_for_scoring"]

    return cfg


def scanner_cfg(cfg: Config, name: str) -> ScannerConfig:
    """Return the per-scanner config, defaulting to enabled."""
    return cfg.scanners.get(name, ScannerConfig())
