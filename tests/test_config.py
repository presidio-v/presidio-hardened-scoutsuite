from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import config as C
from presidio_scoutsuite.errors import ConfigError

_GOOD = """
[defaults]
provider = "aws"
require-short-lived-creds = true
fail-on-secret = true
waivers = "w.json"

[profiles.nightly]
fail-on-finding = "danger"
sarif = "out.sarif"
"""


def _write(tmp_path, text, name=".presidio-scout.toml"):
    p = tmp_path / name
    p.write_text(text)
    return p


# --- validate ----------------------------------------------------------------


def test_validate_good(tmp_path):
    assert C.validate_file(_write(tmp_path, _GOOD)) == ["nightly"]


def test_unknown_top_level(tmp_path):
    with pytest.raises(ConfigError, match="unknown top-level"):
        C.validate_file(_write(tmp_path, "[nope]\nx = 1"))


def test_unknown_setting(tmp_path):
    with pytest.raises(ConfigError, match="unknown setting 'bogus'"):
        C.validate_file(_write(tmp_path, "[defaults]\nbogus = 1"))


def test_bad_provider(tmp_path):
    with pytest.raises(ConfigError, match="must be one of"):
        C.validate_file(_write(tmp_path, '[defaults]\nprovider = "neptune"'))


def test_bad_fail_on_finding(tmp_path):
    with pytest.raises(ConfigError, match="must be one of"):
        C.validate_file(_write(tmp_path, '[defaults]\nfail-on-finding = "meh"'))


def test_bad_bool_type(tmp_path):
    with pytest.raises(ConfigError, match="must be a boolean"):
        C.validate_file(_write(tmp_path, '[defaults]\nfail-on-secret = "yes"'))


def test_bad_num_type(tmp_path):
    with pytest.raises(ConfigError, match="must be a number"):
        C.validate_file(_write(tmp_path, "[defaults]\ntimeout = true"))


def test_bad_str_type(tmp_path):
    with pytest.raises(ConfigError, match="must be a string"):
        C.validate_file(_write(tmp_path, "[defaults]\nreport-dir = 5"))


def test_malformed_toml(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config"):
        C.validate_file(_write(tmp_path, "[defaults]\nx = "))


def test_profile_must_be_table(tmp_path):
    with pytest.raises(ConfigError, match=r"\[profiles.x\] must be a table"):
        C.validate_file(_write(tmp_path, "[profiles]\nx = 1"))


# --- resolve -----------------------------------------------------------------


def test_resolve_defaults_only(tmp_path):
    settings = C.resolve(_write(tmp_path, _GOOD))
    assert settings == {
        "provider": "aws",
        "require_short_lived_creds": True,
        "fail_on_secret": True,
        "waivers": "w.json",
    }


def test_resolve_with_profile_overlays(tmp_path):
    settings = C.resolve(_write(tmp_path, _GOOD), "nightly")
    assert settings["fail_on_finding"] == "danger"  # from profile
    assert settings["sarif"] == "out.sarif"
    assert settings["provider"] == "aws"  # inherited from defaults


def test_resolve_profile_overrides_default(tmp_path):
    text = '[defaults]\nfail-on-finding = "warning"\n[profiles.strict]\nfail-on-finding = "danger"'
    assert C.resolve(_write(tmp_path, text), "strict")["fail_on_finding"] == "danger"


def test_resolve_missing_profile(tmp_path):
    with pytest.raises(ConfigError, match="profile 'ghost' not found"):
        C.resolve(_write(tmp_path, _GOOD), "ghost")


def test_kebab_keys_normalized(tmp_path):
    settings = C.resolve(_write(tmp_path, '[defaults]\nreport-dir = "x"\nno-baseline = true'))
    assert settings["report_dir"] == "x"
    assert settings["no_baseline"] is True


# --- discovery / load_settings ----------------------------------------------


def test_find_config(tmp_path):
    assert C.find_config(tmp_path) is None
    _write(tmp_path, _GOOD)
    assert C.find_config(tmp_path) == tmp_path / ".presidio-scout.toml"


def test_load_settings_no_file_returns_empty(tmp_path):
    assert C.load_settings(cwd=tmp_path) == {}


def test_load_settings_profile_without_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="no .* found"):
        C.load_settings(cwd=tmp_path, profile="nightly")


def test_load_settings_explicit_path(tmp_path):
    cfg = _write(tmp_path, _GOOD)
    assert C.load_settings(config_path=cfg, profile="nightly")["fail_on_finding"] == "danger"


def test_load_settings_missing_explicit_path(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        C.load_settings(config_path=tmp_path / "nope.toml")


# --- policy CLI --------------------------------------------------------------


def test_cli_validate_ok(tmp_path, capsys):
    cfg = _write(tmp_path, _GOOD)
    assert C._main(["validate", "--config", str(cfg)]) == 0
    assert "valid" in capsys.readouterr().out


def test_cli_validate_error(tmp_path, capsys):
    cfg = _write(tmp_path, "[defaults]\nbogus = 1")
    assert C._main(["validate", "--config", str(cfg)]) == 2
    assert "unknown setting" in capsys.readouterr().err


def test_cli_show(tmp_path, capsys):
    cfg = _write(tmp_path, _GOOD)
    assert C._main(["show", "--config", str(cfg), "--profile", "nightly"]) == 0
    assert json.loads(capsys.readouterr().out)["fail_on_finding"] == "danger"


def test_validate_accepts_extensions(tmp_path):
    text = _GOOD + (
        '\n[redaction]\nextra-patterns = ["A-[0-9]{3}"]\n'
        '\n[baseline]\nbase = "aws"\n'
        '[baseline.set-level]\n"s3-bucket-no-logging.json" = "danger"\n'
    )
    assert C.validate_file(_write(tmp_path, text)) == ["nightly"]


def test_validate_rejects_bad_redaction(tmp_path):
    text = _GOOD + '\n[redaction]\nextra-patterns = ["("]\n'
    with pytest.raises(ConfigError, match="invalid regex"):
        C.validate_file(_write(tmp_path, text))


def test_validate_rejects_unknown_baseline_rule(tmp_path):
    text = _GOOD + '\n[baseline]\nbase = "aws"\n[baseline.set-level]\n"nope.json" = "danger"\n'
    with pytest.raises(ConfigError, match="not in the aws manifest"):
        C.validate_file(_write(tmp_path, text))


def test_sinks_section_is_allowed(tmp_path):
    # a [sinks.*] table must not trip the unknown-top-level-section guard
    text = _GOOD + '\n[sinks.prod]\ntype = "file"\npath = "x.json"\n'
    assert C.validate_file(_write(tmp_path, text)) == ["nightly"]


def test_cli_no_config(tmp_path, capsys):
    assert C._main(["validate", "--config", str(tmp_path / "nope.toml")]) == 2
