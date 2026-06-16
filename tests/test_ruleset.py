from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import ruleset
from presidio_scoutsuite.errors import RulesetValidationError


def test_referenced_rules_reads_rule_keys(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"rules": {"a.json": [{"enabled": True}], "b.json": []}}))
    assert ruleset.referenced_rules(path) == {"a.json", "b.json"}


def test_referenced_rules_rejects_non_object_rules(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"rules": ["a.json"]}))
    with pytest.raises(RulesetValidationError, match="must be an object"):
        ruleset.referenced_rules(path)


@pytest.mark.parametrize("provider", ruleset.VALIDATED_PROVIDERS)
def test_bundled_baselines_validate_against_manifest(provider):
    # Every curated baseline must reference only rules in its shipped inventory.
    ruleset.validate_provider(provider, source="manifest")


def test_validate_all_passes_for_shipped_baselines():
    ruleset.validate_all(source="manifest")


@pytest.mark.parametrize("provider", ruleset.VALIDATED_PROVIDERS)
def test_manifest_is_superset_of_baseline(provider):
    referenced = ruleset.referenced_rules(ruleset.baseline_path(provider))
    manifest = ruleset.manifest_rules(provider)
    assert referenced <= manifest
    assert manifest, "manifest must not be empty"


def test_missing_rules_detects_unknown_reference(monkeypatch):
    monkeypatch.setattr(
        ruleset, "available_rules", lambda provider, source="manifest": {"known.json"}
    )
    monkeypatch.setattr(ruleset, "referenced_rules", lambda path: {"known.json", "typo-rule.json"})
    missing = ruleset.missing_rules("aws")
    assert missing == {"typo-rule.json"}


def test_validate_provider_raises_on_unknown_rule(monkeypatch):
    monkeypatch.setattr(ruleset, "missing_rules", lambda provider, source="manifest": {"typo.json"})
    with pytest.raises(RulesetValidationError, match="typo.json"):
        ruleset.validate_provider("aws")


def test_baseline_path_rejects_unknown_provider():
    with pytest.raises(RulesetValidationError, match="no curated baseline"):
        ruleset.baseline_path("digitalocean")


def test_manifest_rules_rejects_unknown_provider():
    with pytest.raises(RulesetValidationError, match="no rule manifest"):
        ruleset.manifest_rules("digitalocean")


def test_available_rules_rejects_unknown_source():
    with pytest.raises(RulesetValidationError, match="unknown rule source"):
        ruleset.available_rules("aws", source="telepathy")


def test_installed_rules_fails_closed_without_scoutsuite():
    # ScoutSuite is not installed in CI; discovery must raise, not return [].
    with pytest.raises(RulesetValidationError, match="ScoutSuite is not installed"):
        ruleset.installed_rules("aws")


def test_cli_main_reports_ok(capsys):
    rc = ruleset._main([])
    assert rc == 0
    out = capsys.readouterr().out
    for provider in ruleset.VALIDATED_PROVIDERS:
        assert f"ok   {provider}" in out


def test_cli_main_single_provider(capsys):
    rc = ruleset._main(["--provider", "aws"])
    assert rc == 0
    assert "ok   aws" in capsys.readouterr().out


def test_cli_main_fails_on_missing_rule(monkeypatch, capsys):
    def boom(provider, *, source="manifest"):
        raise RulesetValidationError(f"{provider}: bad rule")

    monkeypatch.setattr(ruleset, "validate_provider", boom)
    rc = ruleset._main(["--provider", "aws"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().err


# --- manifest regeneration (upgrade automation) ------------------------------


def test_render_manifest_is_sorted_and_parseable():
    text = ruleset.render_manifest("aws", {"b.json", "a.json", "c.json"})
    assert "aws-cis.json" in text  # header mentions the provider baseline
    body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    assert body == ["a.json", "b.json", "c.json"]  # sorted, deterministic
    assert ruleset._parse_manifest(text) == {"a.json", "b.json", "c.json"}


def test_regenerate_manifest_writes_installed_inventory(monkeypatch, tmp_path):
    target = tmp_path / "aws.rules.txt"
    target.write_text("# stale\nold-rule.json\n")
    monkeypatch.setattr(ruleset, "_policy_resource", lambda name: target)
    monkeypatch.setattr(ruleset, "installed_rules", lambda p: {"new-a.json", "new-b.json"})
    path = ruleset.regenerate_manifest("aws")
    assert path == target
    assert ruleset._parse_manifest(target.read_text()) == {"new-a.json", "new-b.json"}


def test_regenerate_manifest_unknown_provider():
    with pytest.raises(RulesetValidationError, match="no rule manifest"):
        ruleset.regenerate_manifest("neptune")


def test_cli_regenerate_requires_installed_source(capsys):
    assert ruleset._main(["--regenerate"]) == 2
    assert "requires --source installed" in capsys.readouterr().err


def test_cli_regenerate_runs(monkeypatch, capsys):
    written: list[str] = []

    def fake_regen(provider):
        written.append(provider)
        return f"/policy/{provider}.rules.txt"

    monkeypatch.setattr(ruleset, "regenerate_manifest", fake_regen)
    monkeypatch.setattr(ruleset, "manifest_rules", lambda p: {"x.json"})
    rc = ruleset._main(["--regenerate", "--source", "installed", "--provider", "aws"])
    assert rc == 0
    assert written == ["aws"]
    assert "regenerated aws" in capsys.readouterr().out


def test_cli_regenerate_fails_closed_without_scoutsuite(capsys):
    # No ScoutSuite installed -> installed_rules raises -> non-zero, nothing written.
    rc = ruleset._main(["--regenerate", "--source", "installed", "--provider", "aws"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().err
