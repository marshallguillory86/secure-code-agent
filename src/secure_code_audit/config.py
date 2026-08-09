"""Config loader for secure-code-agent.json.

The JSON Schema is published for editor and CI validation.  Runtime parsing
also validates security-sensitive fields that affect subprocess execution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("secure-code-agent.json")

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git/",
    "node_modules/",
    ".venv/",
    "venv/",
    "dist/",
    "build/",
    "__pycache__/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".mypy_cache/",
    "**/*.min.js",
    "**/*.lock",
)

DEFAULT_INCLUDE_EXTS: tuple[str, ...] = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    "Dockerfile",
)

DEFAULT_OUTPUTS: dict[str, str] = {
    "markdown_path": "secure-code-report.md",
    "json_path": "secure-code-report.json",
    "sarif_path": "secure-code.sarif",
    "comment_path": "secure-code-pr-comment.md",
    "prompt_path": "secure-code-remediation-prompt.md",
    "baseline_path": "secure-code-baseline.json",
}

_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_CATEGORIES = {
    "secrets",
    "dependencies",
    "code_vulnerabilities",
    "auth_authz",
    "crypto",
    "supply_chain",
    "config_iac",
    "logging_observability",
    "policy_docs",
}


@dataclass
class ScannerConfig:
    enabled: bool = True
    timeout_seconds: int = 600
    online: bool = False
    extra_args: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    mode: str = "auto"
    inputs: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Parsed config. Operator-facing access is via attribute names."""

    version: int = 1
    include_extensions: tuple[str, ...] = DEFAULT_INCLUDE_EXTS
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    category_overrides: dict[str, str] = field(default_factory=dict)
    gates: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_OUTPUTS))
    suppressions_file: str = ".scignore.yaml"
    loc_for_scoring: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)


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
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a JSON object")
    cfg = Config(raw=raw)
    cfg.version = int(raw.get("version", 1))
    if "asvs_level" in raw:
        raise ValueError("asvs_level is not an implemented gate; remove it from the configuration")

    paths = raw.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("paths must be a JSON object")
    if "include_extensions" in paths:
        cfg.include_extensions = tuple(
            _string_list(paths["include_extensions"], "paths.include_extensions")
        )
    if "exclude_patterns" in paths:
        cfg.exclude_patterns = tuple(
            _string_list(paths["exclude_patterns"], "paths.exclude_patterns")
        )

    scanners_raw = raw.get("scanners", {})
    if not isinstance(scanners_raw, dict):
        raise ValueError("scanners must be a JSON object")
    for name, sc_raw in scanners_raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("scanner names must be non-empty strings")
        if not isinstance(sc_raw, dict):
            raise ValueError(f"scanners.{name} must be a JSON object")
        command = _string_list(sc_raw.get("command") or [], f"scanners.{name}.command")
        inputs = _string_list(sc_raw.get("inputs") or [], f"scanners.{name}.inputs")
        extra_args = _string_list(sc_raw.get("extra_args") or [], f"scanners.{name}.extra_args")
        enabled = sc_raw.get("enabled", True)
        online = sc_raw.get("online", False)
        if not isinstance(enabled, bool):
            raise ValueError(f"scanners.{name}.enabled must be a boolean")
        if not isinstance(online, bool):
            raise ValueError(f"scanners.{name}.online must be a boolean")
        timeout = sc_raw.get("timeout_seconds", 600)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ValueError(f"scanners.{name}.timeout_seconds must be a positive integer")
        mode = sc_raw.get("mode") or "auto"
        if not isinstance(mode, str):
            raise ValueError(f"scanners.{name}.mode must be a string")
        cfg.scanners[name] = ScannerConfig(
            enabled=enabled,
            timeout_seconds=timeout,
            online=online,
            extra_args=extra_args,
            command=command,
            mode=mode,
            inputs=inputs,
        )

    cfg.severity_overrides = _string_mapping(
        raw.get("severity_overrides", {}), "severity_overrides"
    )
    cfg.category_overrides = _string_mapping(
        raw.get("category_overrides", {}), "category_overrides"
    )
    if invalid := sorted(set(cfg.severity_overrides.values()) - _SEVERITIES):
        raise ValueError(f"invalid severity override: {', '.join(invalid)}")
    if invalid := sorted(set(cfg.category_overrides.values()) - _CATEGORIES):
        raise ValueError(f"invalid category override: {', '.join(invalid)}")
    cfg.gates = _validate_gates(raw.get("gates", {}))

    outputs = raw.get("outputs", {})
    if not isinstance(outputs, dict):
        raise ValueError("outputs must be a JSON object")
    for k, default_v in DEFAULT_OUTPUTS.items():
        value = outputs.get(k, default_v)
        if not isinstance(value, str) or not value:
            raise ValueError(f"outputs.{k} must be a non-empty string")
        cfg.outputs[k] = value

    if "suppressions_file" in raw:
        value = raw["suppressions_file"]
        if not isinstance(value, str) or not value:
            raise ValueError("suppressions_file must be a non-empty string")
        cfg.suppressions_file = value

    if "loc_for_scoring" in raw:
        value = raw["loc_for_scoring"]
        if not isinstance(value, dict):
            raise ValueError("loc_for_scoring must be a JSON object")
        loc = value.get("value")
        reason = value.get("reason")
        if isinstance(loc, bool) or not isinstance(loc, int) or loc < 1:
            raise ValueError("loc_for_scoring.value must be a positive integer")
        if not isinstance(reason, str) or not reason:
            raise ValueError("loc_for_scoring.reason must be a non-empty string")
        cfg.loc_for_scoring = value

    return cfg


def _string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field_name} must be a list of non-empty strings")
    return list(value)


def _string_mapping(value: object, field_name: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and key and isinstance(item, str) and item
        for key, item in value.items()
    ):
        raise ValueError(f"{field_name} must map non-empty strings to non-empty strings")
    return {key: item.lower() for key, item in value.items()}


def _validate_gates(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("gates must be a JSON object")
    gates = dict(value)
    for name in ("fail_on_severity", "fail_on_category", "require_scanners"):
        if name in gates:
            gates[name] = _string_list(gates[name], f"gates.{name}")
    invalid_severities = set(gates.get("fail_on_severity", [])) - _SEVERITIES
    if invalid_severities:
        raise ValueError(f"invalid gates.fail_on_severity value: {sorted(invalid_severities)[0]}")
    invalid_categories = set(gates.get("fail_on_category", [])) - _CATEGORIES
    if invalid_categories:
        raise ValueError(f"invalid gates.fail_on_category value: {sorted(invalid_categories)[0]}")
    if "fail_on_new" in gates and not isinstance(gates["fail_on_new"], bool):
        raise ValueError("gates.fail_on_new must be a boolean")
    if "min_score" in gates:
        score = gates["min_score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 5:
            raise ValueError("gates.min_score must be a number from 0 through 5")
    if "max_unsuppressed" in gates:
        limits = gates["max_unsuppressed"]
        if not isinstance(limits, dict) or not all(
            isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0
            for limit in limits.values()
        ):
            raise ValueError("gates.max_unsuppressed must map severities to non-negative integers")
        invalid_limits = set(limits) - (_SEVERITIES - {"informational"})
        if invalid_limits:
            raise ValueError(f"invalid gates.max_unsuppressed key: {sorted(invalid_limits)[0]}")
    return gates


def scanner_cfg(cfg: Config, name: str) -> ScannerConfig:
    """Return the per-scanner config, defaulting to enabled."""
    return cfg.scanners.get(name, ScannerConfig())
