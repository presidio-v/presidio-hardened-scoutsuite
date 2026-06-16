from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import vuln as V
from presidio_scoutsuite.errors import VulnerabilityError

_TRIVY = {
    "Results": [
        {
            "Target": "image",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-CRIT",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.0",
                    "Severity": "CRITICAL",
                    "FixedVersion": "1.1",
                },
                {
                    "VulnerabilityID": "CVE-HIGH-UNFIXED",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2",
                    "Severity": "HIGH",
                    "FixedVersion": "",
                },
                {
                    "VulnerabilityID": "CVE-LOW",
                    "PkgName": "bash",
                    "InstalledVersion": "5",
                    "Severity": "LOW",
                    "FixedVersion": "5.1",
                },
            ],
        }
    ]
}

_GRYPE = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-crit",
                "severity": "Critical",
                "fix": {"state": "fixed", "versions": ["2.0"]},
            },
            "artifact": {"name": "requests", "version": "1.0"},
        },
        {
            "vulnerability": {"id": "GHSA-high", "severity": "High", "fix": {"state": "not-fixed"}},
            "artifact": {"name": "urllib3", "version": "1.0"},
        },
    ]
}


# --- parsing -----------------------------------------------------------------


def test_parse_trivy():
    vulns = V.parse_report(json.dumps(_TRIVY))
    assert {v.id for v in vulns} == {"CVE-CRIT", "CVE-HIGH-UNFIXED", "CVE-LOW"}
    crit = next(v for v in vulns if v.id == "CVE-CRIT")
    assert crit.severity == "critical"
    assert crit.fixed_version == "1.1"
    assert crit.fixable


def test_parse_trivy_unfixed():
    vulns = {v.id: v for v in V.parse_report(json.dumps(_TRIVY))}
    assert vulns["CVE-HIGH-UNFIXED"].fixed_version is None
    assert not vulns["CVE-HIGH-UNFIXED"].fixable


def test_parse_grype():
    vulns = {v.id: v for v in V.parse_report(json.dumps(_GRYPE))}
    assert vulns["GHSA-crit"].severity == "critical"
    assert vulns["GHSA-crit"].fixable
    assert vulns["GHSA-crit"].fixed_version == "2.0"
    assert not vulns["GHSA-high"].fixable


def test_parse_invalid_json():
    with pytest.raises(VulnerabilityError, match="not valid JSON"):
        V.parse_report("{nope")


def test_parse_unknown_format():
    with pytest.raises(VulnerabilityError, match="unrecognized report format"):
        V.parse_report(json.dumps({"something": "else"}))


def test_parse_tolerates_empty():
    assert V.parse_report(json.dumps({"Results": []})) == []
    assert V.parse_report(json.dumps({"matches": []})) == []


# --- gating ------------------------------------------------------------------


def test_counts():
    rep = V.VulnReport(vulns=V.parse_report(json.dumps(_TRIVY)))
    assert rep.counts == {"negligible": 0, "low": 1, "medium": 0, "high": 1, "critical": 1}


def test_at_or_above():
    rep = V.VulnReport(vulns=V.parse_report(json.dumps(_TRIVY)))
    assert {v.id for v in rep.at_or_above("critical")} == {"CVE-CRIT"}
    assert {v.id for v in rep.at_or_above("high")} == {"CVE-CRIT", "CVE-HIGH-UNFIXED"}
    assert {v.id for v in rep.at_or_above("low")} == {"CVE-CRIT", "CVE-HIGH-UNFIXED", "CVE-LOW"}


def test_at_or_above_fixable_only():
    rep = V.VulnReport(vulns=V.parse_report(json.dumps(_TRIVY)))
    # the high one is unfixed -> excluded when fixable_only
    assert {v.id for v in rep.at_or_above("high", fixable_only=True)} == {"CVE-CRIT"}


def test_at_or_above_unknown_severity():
    rep = V.VulnReport(vulns=[])
    with pytest.raises(VulnerabilityError, match="unknown severity"):
        rep.at_or_above("apocalyptic")


def test_load_report_missing(tmp_path):
    with pytest.raises(VulnerabilityError, match="cannot read"):
        V.load_report(tmp_path / "nope.json")


# --- CLI ---------------------------------------------------------------------


def _report_file(tmp_path, obj):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(obj))
    return str(p)


def test_cli_fail_on_critical(tmp_path, capsys):
    rc = V._main([_report_file(tmp_path, _TRIVY), "--fail-on", "critical"])
    assert rc == 4
    err = capsys.readouterr().err
    assert "at or above 'critical'" in err
    assert "CVE-CRIT" in err


def test_cli_ignore_unfixed_passes_when_only_unfixed(tmp_path, capsys):
    only_unfixed = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-X",
                        "PkgName": "p",
                        "InstalledVersion": "1",
                        "Severity": "CRITICAL",
                        "FixedVersion": "",
                    }
                ]
            }
        ]
    }
    rc = V._main(
        [_report_file(tmp_path, only_unfixed), "--fail-on", "critical", "--ignore-unfixed"]
    )
    assert rc == 0  # the only critical has no fix


def test_cli_clean_report(tmp_path, capsys):
    rc = V._main([_report_file(tmp_path, {"Results": []}), "--fail-on", "low"])
    assert rc == 0
    assert "vulnerabilities:" in capsys.readouterr().out


def test_cli_json_output(tmp_path, capsys):
    rc = V._main([_report_file(tmp_path, _TRIVY), "--fail-on", "critical", "--format", "json"])
    assert rc == 4
    # summary still printed to stdout
    assert json.loads(capsys.readouterr().out)["offending"] == 1


def test_cli_bad_report_returns_2(tmp_path, capsys):
    rc = V._main([_report_file(tmp_path, {"x": 1})])
    assert rc == 2
    assert "unrecognized report format" in capsys.readouterr().err
