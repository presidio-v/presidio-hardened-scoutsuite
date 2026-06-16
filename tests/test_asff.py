from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from presidio_scoutsuite import asff
from presidio_scoutsuite.errors import AsffError
from presidio_scoutsuite.findings import Finding, FindingsReport

_WHEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
_ACCOUNT = "123456789012"


def _report():
    return FindingsReport(
        findings=[
            Finding(
                "s3", "s3-bucket-world-acl.json", "danger", 2, "world-readable", items=("b1", "b2")
            ),
            Finding(
                "ec2",
                "ec2-security-group-opens-known-port-to-all.json",
                "warning",
                1,
                "open port",
            ),
        ],
        providers=["aws"],
    )


def _build(**kw):
    return asff.to_asff(_report(), account_id=_ACCOUNT, region="us-east-1", when=_WHEN, **kw)


def test_one_finding_per_resource():
    findings = _build()
    # 2 resources for the s3 finding + 1 for the ec2 finding
    assert len(findings) == 3


def test_required_fields_and_severity():
    f = _build()[0]
    assert f["SchemaVersion"] == asff.SCHEMA_VERSION
    assert f["AwsAccountId"] == _ACCOUNT
    assert f["ProductArn"].endswith(f"product/{_ACCOUNT}/default")
    assert f["Severity"] == {"Label": "HIGH", "Normalized": 70}
    assert f["CreatedAt"] == "2026-01-02T03:04:05.000Z"
    assert f["Resources"][0]["Region"] == "us-east-1"
    assert f["Compliance"]["Status"] == "FAILED"


def test_ids_are_unique_and_stable():
    ids = [f["Id"] for f in _build()]
    assert len(ids) == len(set(ids))
    assert ids[0] == "presidio-scout/aws/s3/s3-bucket-world-acl/b1"


def test_related_requirements_from_mapping():
    f = _build()[0]
    reqs = f["Compliance"]["RelatedRequirements"]
    assert "CIS 2.1.5" in reqs
    assert "NIST.800-53.r5 AC-3" in reqs


def test_warning_maps_to_medium():
    ec2 = [f for f in _build() if f["GeneratorId"].endswith("opens-known-port-to-all")][0]
    assert ec2["Severity"] == {"Label": "MEDIUM", "Normalized": 40}


def test_finding_without_items_gets_synthetic_resource():
    rep = FindingsReport(
        findings=[Finding("rds", "rds-instance-no-encryption.json", "danger", 1)],
        providers=["aws"],
    )
    f = asff.to_asff(rep, account_id=_ACCOUNT, region="eu-west-1", when=_WHEN)[0]
    assert f["Resources"][0]["Id"] == "aws:rds"


def test_bad_account_id_fails_closed():
    with pytest.raises(AsffError, match="12-digit"):
        asff.to_asff(_report(), account_id="123", region="us-east-1")


def test_missing_region_fails_closed():
    with pytest.raises(AsffError, match="region is required"):
        asff.to_asff(_report(), account_id=_ACCOUNT, region="")


# --- CLI ---------------------------------------------------------------------


def _report_dir(tmp_path):
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir()
    results = {
        "provider_code": "aws",
        "services": {
            "s3": {
                "findings": {"s3-bucket-world-acl.json": {"level": "danger", "flagged_items": 1}}
            }
        },
    }
    (sub / "scoutsuite_results_aws.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    return tmp_path


def test_cli_writes_file(tmp_path, capsys):
    out = tmp_path / "asff.json"
    rc = asff._main(
        [
            str(_report_dir(tmp_path)),
            "--aws-account-id",
            _ACCOUNT,
            "--aws-region",
            "us-east-1",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc[0]["AwsAccountId"] == _ACCOUNT
    assert "wrote 1 ASFF finding" in capsys.readouterr().err


def test_cli_stdout(tmp_path, capsys):
    rc = asff._main(
        [str(_report_dir(tmp_path)), "--aws-account-id", _ACCOUNT, "--aws-region", "us-east-1"]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)[0]["SchemaVersion"] == asff.SCHEMA_VERSION


def test_cli_bad_account(tmp_path, capsys):
    rc = asff._main(
        [str(_report_dir(tmp_path)), "--aws-account-id", "bad", "--aws-region", "us-east-1"]
    )
    assert rc == 2
    assert "12-digit" in capsys.readouterr().err


def test_cli_bad_report_dir(tmp_path, capsys):
    rc = asff._main(
        [str(tmp_path / "nope"), "--aws-account-id", _ACCOUNT, "--aws-region", "us-east-1"]
    )
    assert rc == 2
