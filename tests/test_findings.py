from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import findings as F
from presidio_scoutsuite.errors import FindingsError

_RESULTS = {
    "provider_code": "aws",
    "services": {
        "s3": {
            "findings": {
                "s3-world-acl.json": {
                    "level": "danger",
                    "flagged_items": 2,
                    "checked_items": 10,
                    "description": "world-readable",
                },
                "s3-mfa-delete.json": {"level": "warning", "flagged_items": 5},
                "s3-clean.json": {"level": "danger", "flagged_items": 0},
            }
        },
        "iam": {"findings": {"iam-no-mfa.json": {"level": "warning", "flagged_items": 1}}},
    },
}


def _write_results(report_dir, results=_RESULTS, name="scoutsuite_results_aws-1.js"):
    sub = report_dir / "scoutsuite-results"
    sub.mkdir(exist_ok=True)
    (sub / name).write_text("scoutsuite_results =\n" + json.dumps(results) + "\n")
    return sub


# --- parsing -----------------------------------------------------------------


def test_parse_strips_js_wrapper():
    obj = F._parse_results_js('scoutsuite_results =\n{"a": 1}\n')
    assert obj == {"a": 1}


def test_parse_ignores_trailing_content():
    obj = F._parse_results_js('x = {"a": 1};\nmore junk here')
    assert obj == {"a": 1}


def test_parse_no_object_raises():
    with pytest.raises(FindingsError, match="no JSON object"):
        F._parse_results_js("scoutsuite_results = ")


def test_parse_bad_json_raises():
    with pytest.raises(FindingsError, match="could not decode"):
        F._parse_results_js("results = {not json}")


# --- extraction --------------------------------------------------------------


def test_extract_only_flagged():
    findings = F.extract_findings(_RESULTS)
    keys = {f.key for f in findings}
    assert keys == {"s3-world-acl.json", "s3-mfa-delete.json", "iam-no-mfa.json"}
    assert "s3-clean.json" not in keys  # 0 flagged excluded


def test_extract_fields():
    findings = {f.key: f for f in F.extract_findings(_RESULTS)}
    world = findings["s3-world-acl.json"]
    assert world.service == "s3"
    assert world.level == "danger"
    assert world.flagged_items == 2
    assert world.checked_items == 10
    assert "world" in world.description
    assert world.items == ()  # absent in fixture -> empty


def test_extract_captures_items():
    results = {
        "services": {
            "s3": {
                "findings": {
                    "k.json": {"level": "danger", "flagged_items": 2, "items": ["a", "b"]},
                    "bad.json": {"level": "warning", "flagged_items": 1, "items": "not-a-list"},
                }
            }
        }
    }
    by_key = {f.key: f for f in F.extract_findings(results)}
    assert by_key["k.json"].items == ("a", "b")
    assert by_key["bad.json"].items == ()  # non-list ignored


def test_extract_tolerates_malformed_shapes():
    messy = {
        "services": {
            "ok": {"findings": {"k.json": {"level": "danger", "flagged_items": 1}}},
            "bad_service": "not a dict",
            "no_findings": {"other": {}},
            "bad_findings": {"findings": "nope"},
            "bad_finding": {"findings": {"x": "not a dict"}},
            "bad_flagged": {"findings": {"y": {"level": "danger", "flagged_items": "??"}}},
        }
    }
    findings = F.extract_findings(messy)
    assert [f.key for f in findings] == ["k.json"]


def test_extract_no_services():
    assert F.extract_findings({}) == []
    assert F.extract_findings({"services": "nope"}) == []


# --- file discovery ----------------------------------------------------------


def test_find_results_excludes_exceptions(tmp_path):
    sub = _write_results(tmp_path)
    (sub / "scoutsuite_results_aws-1-exceptions.js").write_text("x = {}")
    files = F.find_results_files(tmp_path)
    assert len(files) == 1
    assert "exceptions" not in files[0].name


# --- report + gate -----------------------------------------------------------


def test_load_report(tmp_path):
    _write_results(tmp_path)
    report = F.load_report(tmp_path)
    assert report.providers == ["aws"]
    assert len(report.findings) == 3
    assert report.counts == {"warning": 2, "danger": 1}


def test_load_report_no_results_raises(tmp_path):
    with pytest.raises(FindingsError, match="no ScoutSuite results data"):
        F.load_report(tmp_path)


def test_load_report_merges_multiple_files(tmp_path):
    _write_results(tmp_path, name="scoutsuite_results_aws-1.js")
    gcp = {
        "provider_code": "gcp",
        "services": {"x": {"findings": {"k": {"level": "danger", "flagged_items": 1}}}},
    }
    _write_results(tmp_path, results=gcp, name="scoutsuite_results_gcp-2.js")
    report = F.load_report(tmp_path)
    assert set(report.providers) == {"aws", "gcp"}
    assert len(report.findings) == 4


def test_at_or_above_threshold(tmp_path):
    _write_results(tmp_path)
    report = F.load_report(tmp_path)
    assert len(report.at_or_above("danger")) == 1
    assert len(report.at_or_above("warning")) == 3
    assert report.exceeds("danger")


def test_at_or_above_unknown_level_raises(tmp_path):
    _write_results(tmp_path)
    report = F.load_report(tmp_path)
    with pytest.raises(FindingsError, match="unknown severity level"):
        report.at_or_above("critical")


# --- CLI ---------------------------------------------------------------------


def test_cli_text(tmp_path, capsys):
    _write_results(tmp_path)
    rc = F._main([str(tmp_path)])
    assert rc == 0
    assert "3 flagged (danger=1, warning=2)" in capsys.readouterr().out


def test_cli_json(tmp_path, capsys):
    _write_results(tmp_path)
    rc = F._main([str(tmp_path), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_flagged"] == 3
    assert payload["counts"]["danger"] == 1


def test_cli_fail_on_danger_returns_4(tmp_path, capsys):
    _write_results(tmp_path)
    rc = F._main([str(tmp_path), "--fail-on", "danger"])
    assert rc == 4
    assert "at or above 'danger'" in capsys.readouterr().err


def test_cli_fail_on_warning_lists_all(tmp_path, capsys):
    _write_results(tmp_path)
    rc = F._main([str(tmp_path), "--fail-on", "warning"])
    assert rc == 4


def test_cli_fail_on_not_exceeded_returns_0(tmp_path):
    clean = {
        "provider_code": "aws",
        "services": {"s3": {"findings": {"w.json": {"level": "warning", "flagged_items": 1}}}},
    }
    _write_results(tmp_path, results=clean)
    assert F._main([str(tmp_path), "--fail-on", "danger"]) == 0


def test_cli_no_results_returns_2(tmp_path, capsys):
    rc = F._main([str(tmp_path)])
    assert rc == 2
    assert "no ScoutSuite results data" in capsys.readouterr().err
