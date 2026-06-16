from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import assertions as A
from presidio_scoutsuite.errors import PolicyError
from presidio_scoutsuite.findings import Finding, FindingsReport

_POLICY = """
[[assert]]
name = "no public s3"
rules = ["s3-bucket-world-acl", "s3-bucket-allowing-cleartext"]
max = 0

[[assert]]
name = "no danger in iam"
service = "iam"
min_level = "danger"
max = 0

[[assert]]
name = "few warnings"
min_level = "warning"
max = 5
"""


def _write(tmp_path, text, name="policy.toml"):
    p = tmp_path / name
    p.write_text(text)
    return p


def _report():
    return FindingsReport(
        findings=[
            Finding("s3", "s3-bucket-world-acl.json", "danger", 1),
            Finding("iam", "iam-root-account-no-mfa.json", "danger", 1),
            Finding("ec2", "ec2-default-security-group-in-use.json", "warning", 1),
        ],
        providers=["aws"],
    )


# --- load / validate ---------------------------------------------------------


def test_load_good(tmp_path):
    policy = A.load_policy(_write(tmp_path, _POLICY))
    assert [a.name for a in policy] == ["no public s3", "no danger in iam", "few warnings"]
    assert policy[0].rules == ("s3-bucket-world-acl", "s3-bucket-allowing-cleartext")
    assert policy[1].service == "iam" and policy[1].min_level == "danger"


def test_empty_policy(tmp_path):
    with pytest.raises(PolicyError, match="non-empty"):
        A.load_policy(_write(tmp_path, "# no assertions here\n"))


def test_unknown_top_level(tmp_path):
    with pytest.raises(PolicyError, match="unknown top-level"):
        A.load_policy(_write(tmp_path, '[[assert]]\nname="a"\n[other]\nx=1'))


def test_missing_name(tmp_path):
    with pytest.raises(PolicyError, match="non-empty 'name'"):
        A.load_policy(_write(tmp_path, "[[assert]]\nmax = 0"))


def test_unknown_key(tmp_path):
    with pytest.raises(PolicyError, match="unknown key"):
        A.load_policy(_write(tmp_path, '[[assert]]\nname="a"\nbogus=1'))


def test_bad_level(tmp_path):
    with pytest.raises(PolicyError, match="min_level' must be one of"):
        A.load_policy(_write(tmp_path, '[[assert]]\nname="a"\nmin_level="critical"'))


def test_bad_max(tmp_path):
    with pytest.raises(PolicyError, match="non-negative integer"):
        A.load_policy(_write(tmp_path, '[[assert]]\nname="a"\nmax=-1'))


def test_bad_rules(tmp_path):
    with pytest.raises(PolicyError, match="'rules' must be a list"):
        A.load_policy(_write(tmp_path, '[[assert]]\nname="a"\nrules="x"'))


def test_duplicate_name(tmp_path):
    text = '[[assert]]\nname="a"\n[[assert]]\nname="a"'
    with pytest.raises(PolicyError, match="duplicate assertion name"):
        A.load_policy(_write(tmp_path, text))


def test_malformed_toml(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        A.load_policy(_write(tmp_path, "[[assert]]\nname = "))


# --- evaluate ----------------------------------------------------------------


def test_evaluate(tmp_path):
    policy = A.load_policy(_write(tmp_path, _POLICY))
    outcome = A.evaluate(_report(), policy)
    by_name = {r.assertion.name: r for r in outcome.results}
    assert not by_name["no public s3"].passed  # s3-bucket-world-acl matched
    assert by_name["no public s3"].matched == ["s3/s3-bucket-world-acl"]
    assert not by_name["no danger in iam"].passed  # iam danger matched
    assert by_name["few warnings"].passed  # only 1 warning <= 5 (counts >=warning incl danger)
    assert not outcome.ok
    assert len(outcome.failed) == 2


def test_min_level_includes_higher():
    # min_level=warning matches danger too (danger outranks warning)
    a = A.Assertion("x", min_level="warning", max=0)
    assert a.matches("s3", "r.json", "danger") is True
    assert a.matches("s3", "r.json", "warning") is True


def test_rule_glob_matching():
    a = A.Assertion("x", rules=["s3-*"], max=0)
    assert a.matches("s3", "s3-bucket-world-acl.json", "danger") is True
    assert a.matches("iam", "iam-root.json", "danger") is False


def test_service_filter():
    a = A.Assertion("x", service="iam", max=0)
    assert a.matches("iam", "r.json", "danger") is True
    assert a.matches("s3", "r.json", "danger") is False


def test_to_dict(tmp_path):
    outcome = A.evaluate(_report(), A.load_policy(_write(tmp_path, _POLICY)))
    d = outcome.to_dict()
    assert d["ok"] is False
    assert any(a["name"] == "no danger in iam" and not a["passed"] for a in d["assertions"])


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
    (sub / "scoutsuite_results.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    return tmp_path


def test_cli_fail(tmp_path, capsys):
    pol = _write(tmp_path, '[[assert]]\nname="no public s3"\nrules=["s3-bucket-world-acl"]\nmax=0')
    rc = A._main([str(_report_dir(tmp_path)), "--policy", str(pol)])
    assert rc == 4
    out = capsys.readouterr().out
    assert "FAIL no public s3" in out


def test_cli_pass_json(tmp_path, capsys):
    pol = _write(tmp_path, '[[assert]]\nname="no rds public"\nrules=["rds-*"]\nmax=0')
    rc = A._main([str(_report_dir(tmp_path)), "--policy", str(pol), "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_bad_report(tmp_path, capsys):
    pol = _write(tmp_path, '[[assert]]\nname="a"\nmax=0')
    assert A._main([str(tmp_path / "nope"), "--policy", str(pol)]) == 2


def test_cli_bad_policy(tmp_path, capsys):
    assert A._main([str(_report_dir(tmp_path)), "--policy", str(tmp_path / "nope.toml")]) == 2
