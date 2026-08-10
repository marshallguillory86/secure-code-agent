import json

import pytest

from secure_code_audit.config import load


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "configuration root"),
        ({"paths": []}, "paths must"),
        ({"scanners": []}, "scanners must"),
        ({"scanners": {"bandit": []}}, "scanners.bandit must"),
        ({"scanners": {"bandit": {"enabled": "false"}}}, "enabled must"),
        ({"scanners": {"bandit": {"timeout_seconds": 0}}}, "positive integer"),
        ({"scanners": {"bandit": {"extra_args": "--quiet"}}}, "extra_args must"),
        ({"gates": {"require_scanners": "bandit"}}, "require_scanners must"),
        ({"gates": {"require_scanners": []}}, "at least one scanner"),
        ({"gates": {"min_score": "five"}}, "min_score must"),
        ({"outputs": []}, "outputs must"),
        ({"loc_for_scoring": {"value": 1}}, "reason must"),
        ({"severity_overrides": {"B101": "hihg"}}, "invalid severity"),
        ({"gates": {"fail_on_category": ["authentication"]}}, "invalid gates"),
        ({"gates": {"max_unsuppressed": {"urgent": 0}}}, "invalid gates"),
        ({"asvs_level": 3}, "not an implemented gate"),
    ],
)
def test_invalid_runtime_config_is_rejected(tmp_path, payload, message):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load(path)


def test_explicit_missing_config_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="configuration file does not exist"):
        load(tmp_path / "typo-config.json")


def test_omitted_missing_default_config_uses_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert load().gates == {}
