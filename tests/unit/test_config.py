import json

import pytest

from secure_code_audit import config
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
        # Each of the following had no test, so the loader could have started
        # accepting the value — and an accepted-but-unread setting is the
        # defect this whole table exists for: it reads as a decision that was
        # made and changes nothing.
        ({"gates": []}, "gates must be a JSON object"),
        ({"gates": {"fail_on_severity": ["urgent"]}}, "invalid gates.fail_on_severity"),
        # A string is truthy, so `fail_on_new: "false"` would turn the ratchet
        # *on* for an operator who wrote it to turn the ratchet off.
        ({"gates": {"fail_on_new": "false"}}, "fail_on_new must be a boolean"),
        ({"gates": {"max_unsuppressed": {"high": -1}}}, "non-negative integers"),
        ({"scanners": {"": {}}}, "scanner names must be non-empty"),
        ({"scanners": {"bandit": {"online": "yes"}}}, "online must be a boolean"),
        ({"scanners": {"bandit": {"mode": 2}}}, "mode must be a string"),
        ({"capabilities": {"": "a reason"}}, "capability names must be non-empty"),
        ({"category_overrides": {"B101": "authentication"}}, "invalid category override"),
        ({"severity_overrides": {"B101": 7}}, "severity_overrides must map"),
        ({"suppressions_file": ""}, "suppressions_file must be a non-empty string"),
        ({"loc_for_scoring": []}, "loc_for_scoring must be a JSON object"),
        ({"loc_for_scoring": {"value": 0, "reason": "r"}}, "value must be a positive integer"),
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


def test_a_config_that_is_not_json_names_the_file_it_could_not_read(tmp_path):
    """A trailing comma must not read as "no configuration".

    Falling back to defaults here would silently drop the operator's gates,
    their declared capabilities and their suppressions file — the audit would
    run, exit 0, and report against a policy nobody chose. The path is in the
    message because a run resolves a config it was not handed explicitly.
    """
    path = tmp_path / "config.json"
    path.write_text('{"version": 1,}', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON") as caught:
        load(path)

    assert str(path) in str(caught.value)


def test_omitted_missing_default_config_uses_defaults(tmp_path, monkeypatch):
    """With no config at all, the ratchet is the policy.

    This asserted `gates == {}` — no floor whatsoever, under which an
    absent gate cannot trip and every audit "passes". `fail_on_new` is the
    one gate measured to work (D15): severity-based defaults either catch
    nothing dangerous or fail half of well-maintained code.
    """
    monkeypatch.chdir(tmp_path)

    assert load().gates == {"fail_on_new": True}


def test_an_operator_gates_block_replaces_the_default_entirely(tmp_path, monkeypatch):
    """Choosing a policy means choosing it, not adding to ours.

    If the default merged in, an operator who deliberately configured only
    `fail_on_severity` would silently also get the ratchet, and could not
    turn it off at all.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secure-code-agent.json").write_text(
        json.dumps({"version": 1, "gates": {"fail_on_severity": ["critical"]}}),
        encoding="utf-8",
    )

    gates = load().gates

    assert gates == {"fail_on_severity": ["critical"]}
    assert "fail_on_new" not in gates


def test_an_explicitly_empty_gates_block_means_report_only(tmp_path, monkeypatch):
    """An operator can still ask for no floor — they just have to say so."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secure-code-agent.json").write_text(
        json.dumps({"version": 1, "gates": {}}), encoding="utf-8"
    )

    assert load().gates == {}


# ---------------------------------------------------------------------------
# Turning an output off
# ---------------------------------------------------------------------------


def _cfg(tmp_path, body: dict):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return config.load(path)


def test_null_disables_an_output(tmp_path):
    """The report and the work order are written on every run, so there has
    to be a way to say no.

    Without this the docstring promised a capability the loader rejected:
    `outputs.prompt_path must be a non-empty string`. The only way to
    silence the work order was to stop using the tool.
    """
    cfg = _cfg(tmp_path, {"version": 1, "outputs": {"prompt_path": None}})

    assert cfg.outputs["prompt_path"] is None


def test_every_output_can_be_disabled_independently(tmp_path):
    from secure_code_audit.config import DEFAULT_OUTPUTS

    for key in DEFAULT_OUTPUTS:
        cfg = _cfg(tmp_path, {"version": 1, "outputs": {key: None}})
        assert cfg.outputs[key] is None, key
        others = [k for k in DEFAULT_OUTPUTS if k != key]
        assert all(cfg.outputs[k] is not None for k in others), (
            f"disabling {key} disabled something else too"
        )


def test_an_empty_string_is_still_a_mistake(tmp_path):
    """`null` is an intention. `""` is a typo, and writing a report to the
    current directory because of one is worse than refusing."""
    with pytest.raises(ValueError, match="non-empty string"):
        _cfg(tmp_path, {"version": 1, "outputs": {"prompt_path": ""}})


def test_the_error_says_how_to_disable_it(tmp_path):
    """An operator who hits this should not have to read the source to find
    out that null is allowed."""
    with pytest.raises(ValueError, match="null to disable"):
        _cfg(tmp_path, {"version": 1, "outputs": {"markdown_path": ""}})
