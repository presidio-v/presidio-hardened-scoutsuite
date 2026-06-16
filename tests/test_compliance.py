from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import compliance as C
from presidio_scoutsuite.errors import ComplianceError
from presidio_scoutsuite.findings import Finding, FindingsReport

# --- a small report built from real, mapped rule keys ------------------------


def _report():
    return FindingsReport(
        findings=[
            Finding("s3", "s3-bucket-world-acl.json", "danger", 2, "world-readable"),
            Finding("iam", "iam-root-account-no-mfa.json", "danger", 1, "root no mfa"),
            Finding("ec2", "ec2-security-group-opens-known-port-to-all.json", "warning", 3),
            Finding("madeup", "not-a-real-rule.json", "warning", 1),
        ],
        providers=["aws"],
    )


# --- mapping load + fail-closed validation -----------------------------------


@pytest.mark.parametrize("provider", C.MAPPED_PROVIDERS)
def test_real_mappings_load_and_validate(provider):
    mapping = C.load_mapping(provider)
    assert mapping.provider == provider
    assert mapping.frameworks == C.FRAMEWORKS
    assert mapping.controls  # non-empty
    # Every mapped rule must exist in the pinned ScoutSuite's manifest inventory.
    C.validate_mapping(provider)


def test_load_mapping_unknown_provider():
    with pytest.raises(ComplianceError, match="no control mapping"):
        C.load_mapping("neptune")


def _patch_mapping(monkeypatch, tmp_path, payload):
    path = tmp_path / "aws.controls.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(C, "_policy_resource", lambda name: path)


def test_load_mapping_bad_controls_type(monkeypatch, tmp_path):
    _patch_mapping(monkeypatch, tmp_path, {"controls": []})
    with pytest.raises(ComplianceError, match="'controls' must be an object"):
        C.load_mapping("aws")


def test_load_mapping_bad_entry_type(monkeypatch, tmp_path):
    _patch_mapping(monkeypatch, tmp_path, {"controls": {"r.json": ["cis"]}})
    with pytest.raises(ComplianceError, match="must be an object of frameworks"):
        C.load_mapping("aws")


def test_load_mapping_undeclared_framework(monkeypatch, tmp_path):
    _patch_mapping(
        monkeypatch, tmp_path, {"frameworks": ["cis"], "controls": {"r.json": {"pci": ["1"]}}}
    )
    with pytest.raises(ComplianceError, match="undeclared framework 'pci'"):
        C.load_mapping("aws")


def test_load_mapping_bad_control_list(monkeypatch, tmp_path):
    _patch_mapping(monkeypatch, tmp_path, {"controls": {"r.json": {"cis": [1, 2]}}})
    with pytest.raises(ComplianceError, match="must be a list of control id strings"):
        C.load_mapping("aws")


def test_load_mapping_malformed_json(monkeypatch, tmp_path):
    path = tmp_path / "aws.controls.json"
    path.write_text("{not json")
    monkeypatch.setattr(C, "_policy_resource", lambda name: path)
    with pytest.raises(ComplianceError, match="cannot read control mapping"):
        C.load_mapping("aws")


def test_validate_mapping_unknown_rule(monkeypatch):
    monkeypatch.setattr(
        C,
        "load_mapping",
        lambda p: C.ComplianceMapping(p, C.FRAMEWORKS, {"ghost-rule.json": {"cis": ["1"]}}),
    )
    with pytest.raises(ComplianceError, match="absent from the manifest"):
        C.validate_mapping("aws")


# --- report building ---------------------------------------------------------


def test_build_report_maps_controls():
    report = C.build_report(_report())
    # s3-bucket-world-acl maps to CIS 2.1.5 with the s3 finding
    assert "2.1.5" in report.failing["cis"]
    assert report.failing["cis"]["2.1.5"] == ["s3/s3-bucket-world-acl"]
    # NIST AC-3 should appear (from s3 world-acl)
    assert "AC-3" in report.failing["nist-800-53"]
    # SOC2 CC6.6 from the security-group finding
    assert "ec2/ec2-security-group-opens-known-port-to-all" in report.failing["soc2"]["CC6.6"]


def test_build_report_collects_unmapped():
    report = C.build_report(_report())
    assert report.unmapped == ["madeup/not-a-real-rule"]


def test_build_report_framework_filter():
    report = C.build_report(_report(), frameworks=("cis",))
    assert set(report.failing) == {"cis"}


def test_build_report_defaults_to_all_providers_when_none():
    r = FindingsReport(findings=[], providers=[])
    report = C.build_report(r)
    assert report.providers == list(C.MAPPED_PROVIDERS)


def test_control_findings_are_sorted_and_deduped():
    rep = FindingsReport(
        findings=[
            Finding("s3", "s3-bucket-world-acl.json", "danger", 1),
            Finding("s3", "s3-bucket-world-acl.json", "danger", 1),
        ],
        providers=["aws"],
    )
    report = C.build_report(rep)
    assert report.failing["cis"]["2.1.5"] == ["s3/s3-bucket-world-acl"]


def test_related_requirements_formatting():
    reqs = C.related_requirements({"cis": ["1.4"], "nist-800-53": ["AC-6"], "soc2": ["CC6.1"]})
    assert reqs == ["CIS 1.4", "NIST.800-53.r5 AC-6", "SOC2 CC6.1"]


def test_to_dict_roundtrips():
    d = C.build_report(_report()).to_dict()
    assert d["providers"] == ["aws"]
    assert "failing_controls" in d and "unmapped_findings" in d


# --- CLI ---------------------------------------------------------------------


def _report_dir(tmp_path):
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir()
    results = {
        "provider_code": "aws",
        "services": {
            "s3": {
                "findings": {"s3-bucket-world-acl.json": {"level": "danger", "flagged_items": 2}}
            },
            "x": {"findings": {"not-a-real-rule.json": {"level": "warning", "flagged_items": 1}}},
        },
    }
    (sub / "scoutsuite_results_aws.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    return tmp_path


def test_cli_text(tmp_path, capsys):
    assert C._main([str(_report_dir(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "compliance [aws]" in out
    assert "2.1.5" in out


def test_cli_json(tmp_path, capsys):
    assert C._main([str(_report_dir(tmp_path)), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["failing_controls"]["cis"]["2.1.5"] == ["s3/s3-bucket-world-acl"]


def test_cli_framework_filter(tmp_path, capsys):
    assert C._main([str(_report_dir(tmp_path)), "--framework", "cis", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc["failing_controls"]) == {"cis"}


def test_cli_fail_on_unmapped(tmp_path, capsys):
    assert C._main([str(_report_dir(tmp_path)), "--fail-on-unmapped"]) == 4
    assert "no control mapping" in capsys.readouterr().err


def test_cli_bad_report_dir(tmp_path, capsys):
    assert C._main([str(tmp_path / "missing")]) == 2
    assert "error:" in capsys.readouterr().err
