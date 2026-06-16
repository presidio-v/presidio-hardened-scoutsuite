from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import remediation as R
from presidio_scoutsuite.errors import RemediationError


@pytest.mark.parametrize("provider", R.MAPPED_PROVIDERS)
def test_real_remediation_loads_and_validates(provider):
    mapping = R.load_remediation(provider)
    assert mapping
    R.validate_remediation(provider)
    # every entry is well-formed
    for rem in mapping.values():
        assert rem.summary and rem.steps


def test_load_unknown_provider():
    with pytest.raises(RemediationError, match="no remediation"):
        R.load_remediation("neptune")


def _patch(monkeypatch, tmp_path, payload):
    path = tmp_path / "aws.remediation.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(R, "_policy_resource", lambda name: path)


def test_bad_top_level(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, {"remediation": []})
    with pytest.raises(RemediationError, match="must be an object"):
        R.load_remediation("aws")


def test_missing_summary(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, {"remediation": {"r.json": {"steps": ["x"]}}})
    with pytest.raises(RemediationError, match="non-empty 'summary'"):
        R.load_remediation("aws")


def test_empty_steps(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, {"remediation": {"r.json": {"summary": "s", "steps": []}}})
    with pytest.raises(RemediationError, match="'steps' must be a non-empty list"):
        R.load_remediation("aws")


def test_bad_references(monkeypatch, tmp_path):
    _patch(
        monkeypatch,
        tmp_path,
        {"remediation": {"r.json": {"summary": "s", "steps": ["x"], "references": [1]}}},
    )
    with pytest.raises(RemediationError, match="'references' must be a list"):
        R.load_remediation("aws")


def test_malformed_json(monkeypatch, tmp_path):
    path = tmp_path / "aws.remediation.json"
    path.write_text("{not json")
    monkeypatch.setattr(R, "_policy_resource", lambda name: path)
    with pytest.raises(RemediationError, match="cannot read remediation"):
        R.load_remediation("aws")


def test_validate_unknown_rule(monkeypatch):
    monkeypatch.setattr(
        R,
        "load_remediation",
        lambda p: {"ghost.json": R.Remediation("s", ("x",), ())},
    )
    with pytest.raises(RemediationError, match="absent from the manifest"):
        R.validate_remediation("aws")


def test_remediation_for_suffix_insensitive():
    lookup = {"s3-bucket-world-acl.json": R.Remediation("fix", ("a",), ())}
    assert R.remediation_for("s3-bucket-world-acl", lookup).summary == "fix"
    assert R.remediation_for("s3-bucket-world-acl.json", lookup).summary == "fix"
    assert R.remediation_for("nope", lookup) is None


# --- CLI ---------------------------------------------------------------------


def _report_dir(tmp_path, rule="s3-bucket-world-acl.json", svc="s3"):
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir(exist_ok=True)
    results = {
        "provider_code": "aws",
        "services": {svc: {"findings": {rule: {"level": "danger", "flagged_items": 1}}}},
    }
    (sub / "scoutsuite_results.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    return tmp_path


def test_cli_text(tmp_path, capsys):
    assert R._main([str(_report_dir(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "fix:" in out
    assert "s3/s3-bucket-world-acl" in out


def test_cli_json(tmp_path, capsys):
    assert R._main([str(_report_dir(tmp_path)), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["remediation"]["summary"]


def test_cli_fail_on_unmapped(tmp_path, capsys):
    # an unknown rule has no remediation -> --fail-on-unmapped trips
    rd = _report_dir(tmp_path, rule="totally-made-up.json")
    assert R._main([str(rd), "--fail-on-unmapped"]) == 4
    assert "no remediation guidance" in capsys.readouterr().err


def test_cli_bad_report(tmp_path, capsys):
    assert R._main([str(tmp_path / "nope")]) == 2


def test_asff_includes_remediation(tmp_path):
    from presidio_scoutsuite import asff
    from presidio_scoutsuite.findings import Finding, FindingsReport

    rep = FindingsReport(
        findings=[Finding("s3", "s3-bucket-world-acl.json", "danger", 1)],
        providers=["aws"],
    )
    f = asff.to_asff(rep, account_id="123456789012", region="us-east-1")[0]
    rec = f["Remediation"]["Recommendation"]
    assert rec["Text"].startswith("Remove public ACL")
    assert rec["Url"].startswith("https://")
