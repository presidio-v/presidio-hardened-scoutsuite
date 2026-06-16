from __future__ import annotations

import json

from presidio_scoutsuite import sarif
from presidio_scoutsuite.findings import Finding, FindingsReport


def _report():
    return FindingsReport(
        providers=["aws"],
        findings=[
            Finding(
                service="s3",
                rule="s3-bucket-world-acl.json",
                level="danger",
                flagged_items=2,
                description="World-readable bucket",
                items=("s3.buckets.a", "s3.buckets.b"),
            ),
            Finding(
                service="iam",
                rule="iam-no-mfa.json",
                level="warning",
                flagged_items=1,
                description="No MFA",
            ),
        ],
    )


def test_envelope_shape():
    doc = sarif.to_sarif(_report())
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == sarif.SARIF_SCHEMA
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "presidio-hardened-scoutsuite"


def test_rules_deduplicated_and_sorted():
    doc = sarif.to_sarif(_report())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == sorted(ids)
    assert ids == ["iam/iam-no-mfa", "s3/s3-bucket-world-acl"]


def test_rule_id_strips_json_suffix():
    assert sarif._rule_id("s3", "s3-bucket-world-acl.json") == "s3/s3-bucket-world-acl"
    assert sarif._rule_id("iam", "no-ext") == "iam/no-ext"


def test_level_and_security_severity_mapping():
    rules = {r["id"]: r for r in sarif.to_sarif(_report())["runs"][0]["tool"]["driver"]["rules"]}
    danger = rules["s3/s3-bucket-world-acl"]
    warn = rules["iam/iam-no-mfa"]
    assert danger["defaultConfiguration"]["level"] == "error"
    assert danger["properties"]["security-severity"] == "8.0"
    assert warn["defaultConfiguration"]["level"] == "warning"
    assert warn["properties"]["security-severity"] == "4.0"
    assert "security" in danger["properties"]["tags"]


def test_result_per_resource_when_items_present():
    results = sarif.to_sarif(_report())["runs"][0]["results"]
    # 2 items for the danger finding + 1 for the warning finding (no items)
    assert len(results) == 3
    s3 = [r for r in results if r["ruleId"] == "s3/s3-bucket-world-acl"]
    assert len(s3) == 2
    assert s3[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "s3.buckets.a"
    assert "s3.buckets.a" in s3[0]["message"]["text"]


def test_finding_without_items_yields_one_result():
    results = sarif.to_sarif(_report())["runs"][0]["results"]
    iam = [r for r in results if r["ruleId"] == "iam/iam-no-mfa"]
    assert len(iam) == 1
    assert "logicalLocations" not in iam[0]["locations"][0]


def test_results_have_synthetic_physical_location():
    results = sarif.to_sarif(_report())["runs"][0]["results"]
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "aws/s3"
    assert loc["region"]["startLine"] == 1


def test_fingerprints_are_unique_and_stable():
    r1 = sarif.to_sarif(_report())["runs"][0]["results"]
    r2 = sarif.to_sarif(_report())["runs"][0]["results"]
    fp1 = [r["partialFingerprints"]["presidioScoutFinding/v1"] for r in r1]
    fp2 = [r["partialFingerprints"]["presidioScoutFinding/v1"] for r in r2]
    assert fp1 == fp2  # deterministic across runs
    assert len(set(fp1)) == len(fp1)  # unique per result


def test_empty_report():
    doc = sarif.to_sarif(FindingsReport())
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_unknown_level_maps_to_note():
    report = FindingsReport(
        providers=["gcp"],
        findings=[Finding(service="x", rule="k", level="info", flagged_items=1)],
    )
    doc = sarif.to_sarif(report)
    assert doc["runs"][0]["results"][0]["level"] == "note"
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "0.0"


# --- CLI ---------------------------------------------------------------------


def _write_results(report_dir):
    import json as _json

    sub = report_dir / "scoutsuite-results"
    sub.mkdir(parents=True, exist_ok=True)
    data = {
        "provider_code": "aws",
        "services": {
            "s3": {"findings": {"w.json": {"level": "danger", "flagged_items": 1, "items": ["b"]}}}
        },
    }
    (sub / "scoutsuite_results_aws-1.js").write_text("scoutsuite_results =\n" + _json.dumps(data))


def test_cli_stdout(tmp_path, capsys):
    _write_results(tmp_path)
    rc = sarif._main([str(tmp_path)])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1


def test_cli_output_file(tmp_path, capsys):
    _write_results(tmp_path)
    out = tmp_path / "out.sarif"
    rc = sarif._main([str(tmp_path), "--output", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert "wrote SARIF" in capsys.readouterr().err


def test_cli_no_results_returns_2(tmp_path, capsys):
    rc = sarif._main([str(tmp_path)])
    assert rc == 2
    assert "no ScoutSuite results data" in capsys.readouterr().err


def test_cli_waivers_exclude_from_sarif(tmp_path, capsys):
    _write_results(tmp_path)  # one danger finding w.json with item "b"
    waivers = tmp_path / "w.json"
    waivers.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "rule": "s3/w",
                        "justification": "accepted",
                        "owner": "o@x",
                        "expires": "2099-01-01",
                    }
                ]
            }
        )
    )
    rc = sarif._main([str(tmp_path), "--waivers", str(waivers)])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["runs"][0]["results"] == []  # waived finding excluded
