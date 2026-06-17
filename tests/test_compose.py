from __future__ import annotations

import pytest

from presidio_scoutsuite import compose, redact
from presidio_scoutsuite.errors import ConfigError

# --- redaction patterns ------------------------------------------------------


def test_no_redaction_section():
    assert compose.parse_redaction_patterns({}) == []


def test_redaction_string_and_table_forms():
    data = {
        "redaction": {
            "extra-patterns": [
                "INT-[A-Z0-9]{6}",
                {"name": "ghx", "pattern": "GHX-[a-z0-9]{4}"},
            ]
        }
    }
    pats = compose.parse_redaction_patterns(data)
    assert [n for n, _ in pats] == ["custom_1", "ghx"]
    # the compiled patterns actually work via redact.scan(extra=...)
    found = redact.scan("token INT-AB12CD and GHX-9z9z", extra=pats)
    assert "custom_1" in found and "ghx" in found


def test_redaction_extra_applied_in_redact_text():
    pats = compose.parse_redaction_patterns({"redaction": {"extra-patterns": ["SEKRIT-[0-9]{4}"]}})
    cleaned, findings = redact.redact_text("x SEKRIT-1234 y", extra=pats)
    assert "SEKRIT-1234" not in cleaned
    assert findings == ["custom_1"]


def test_redaction_bad_regex():
    with pytest.raises(ConfigError, match="invalid regex"):
        compose.parse_redaction_patterns({"redaction": {"extra-patterns": ["("]}})


def test_redaction_unknown_key():
    with pytest.raises(ConfigError, match="unknown key"):
        compose.parse_redaction_patterns({"redaction": {"patterns": []}})


def test_redaction_not_a_table():
    with pytest.raises(ConfigError, match=r"\[redaction\] must be a table"):
        compose.parse_redaction_patterns({"redaction": "x"})


def test_redaction_entries_not_array():
    with pytest.raises(ConfigError, match="must be an array"):
        compose.parse_redaction_patterns({"redaction": {"extra-patterns": "x"}})


def test_redaction_pattern_bad_type():
    with pytest.raises(ConfigError, match="must be a regex string or"):
        compose.parse_redaction_patterns({"redaction": {"extra-patterns": [5]}})


def test_redaction_pattern_table_unknown_key():
    with pytest.raises(ConfigError, match="unknown key"):
        compose.parse_redaction_patterns(
            {"redaction": {"extra-patterns": [{"pattern": "x", "extra": 1}]}}
        )


def test_redaction_pattern_table_missing_pattern():
    with pytest.raises(ConfigError, match="'pattern' must be a string"):
        compose.parse_redaction_patterns({"redaction": {"extra-patterns": [{"name": "x"}]}})


# --- baseline composition ----------------------------------------------------


def test_no_baseline_section():
    assert compose.compose_baseline({}) is None


def test_compose_set_level_and_disable():
    data = {
        "baseline": {
            "base": "aws",
            "set-level": {"s3-bucket-no-versioning.json": "danger"},
            "disable": {"rules": ["kms-cmk-rotation-disabled.json"]},
        }
    }
    composed = compose.compose_baseline(data)
    assert composed["rules"]["s3-bucket-no-versioning.json"] == [
        {"enabled": True, "level": "danger"}
    ]
    assert "kms-cmk-rotation-disabled.json" not in composed["rules"]
    assert "aws" in composed["about"]


def test_compose_add_rule_from_manifest():
    # ec2-ebs-volume-not-encrypted is in the aws manifest but not the base ruleset's
    # danger set; set-level can add it.
    data = {
        "baseline": {"base": "aws", "set-level": {"ec2-ebs-volume-not-encrypted.json": "danger"}}
    }
    composed = compose.compose_baseline(data)
    assert composed["rules"]["ec2-ebs-volume-not-encrypted.json"][0]["level"] == "danger"


def test_compose_unknown_base():
    with pytest.raises(ConfigError, match="base must be one of"):
        compose.compose_baseline({"baseline": {"base": "neptune"}})


def test_compose_unknown_rule_fails_closed():
    with pytest.raises(ConfigError, match="not in the aws manifest"):
        compose.compose_baseline(
            {"baseline": {"base": "aws", "set-level": {"made-up-rule.json": "danger"}}}
        )


def test_compose_bad_level():
    with pytest.raises(ConfigError, match="severity must be one of"):
        compose.compose_baseline(
            {"baseline": {"base": "aws", "set-level": {"s3-bucket-no-logging.json": "critical"}}}
        )


def test_compose_unknown_key():
    with pytest.raises(ConfigError, match="unknown key"):
        compose.compose_baseline({"baseline": {"base": "aws", "bogus": 1}})


def test_compose_disable_bad_shape():
    with pytest.raises(ConfigError, match="must be a list"):
        compose.compose_baseline({"baseline": {"base": "aws", "disable": {"rules": "x"}}})


def test_compose_disable_unknown_rule_fails_closed():
    with pytest.raises(ConfigError, match="not in the aws manifest"):
        compose.compose_baseline(
            {"baseline": {"base": "aws", "disable": {"rules": ["made-up-rule.json"]}}}
        )


def test_validate_extensions_ok():
    data = {
        "redaction": {"extra-patterns": ["A-[0-9]{3}"]},
        "baseline": {"base": "gcp", "set-level": {"iam-primitive-role-in-use.json": "danger"}},
    }
    compose.validate_extensions(data)  # no raise


def test_validate_extensions_propagates_error():
    with pytest.raises(ConfigError):
        compose.validate_extensions({"redaction": {"extra-patterns": ["("]}})
