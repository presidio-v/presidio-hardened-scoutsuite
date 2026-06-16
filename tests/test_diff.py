from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import diff as D
from presidio_scoutsuite.errors import FindingsError, PresidioScoutError
from presidio_scoutsuite.findings import Finding, FindingsReport


def _old():
    return FindingsReport(
        providers=["aws"],
        findings=[
            Finding("s3", "world.json", "danger", 2, items=("b.a", "b.b")),
            Finding("iam", "old.json", "warning", 1),
        ],
    )


def _new():
    return FindingsReport(
        providers=["aws"],
        findings=[
            Finding("s3", "world.json", "danger", 2, items=("b.a", "b.c")),  # b.b->b.c
            Finding("ec2", "newsg.json", "danger", 1, items=("sg.x",)),  # brand new
        ],
    )


def _results(*findings):
    """Build a ScoutSuite results doc from (service, key, level, items) tuples."""

    services: dict = {}
    for service, key, level, items in findings:
        entry = {"level": level, "flagged_items": len(items) or 1, "items": list(items)}
        services.setdefault(service, {"findings": {}})["findings"][key] = entry
    return {"provider_code": "aws", "services": services}


def _write_report(tmp_path, results):
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir(parents=True, exist_ok=True)
    (sub / "scoutsuite_results_aws-1.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    return tmp_path


# --- diff_reports ------------------------------------------------------------


def test_new_finding_detected():
    r = D.diff_reports(_old(), _new())
    assert r.new_findings == [("ec2", "newsg.json")]


def test_new_resource_on_existing_finding():
    r = D.diff_reports(_old(), _new())
    nr = r.new_resources
    assert [(c.service, c.key, c.item) for c in nr] == [("s3", "world.json", "b.c")]
    assert all(not c.whole_finding for c in nr)


def test_resolved_finding_and_resource():
    r = D.diff_reports(_old(), _new())
    assert r.resolved_findings == [("iam", "old.json")]
    removed = {(c.key, c.item, c.whole_finding) for c in r.removed}
    assert ("world.json", "b.b", False) in removed  # resource removed
    assert ("old.json", None, True) in removed  # whole finding resolved


def test_no_change_is_empty():
    r = D.diff_reports(_new(), _new())
    assert r.added == []
    assert r.removed == []
    assert r.new_findings == []


def test_added_at_or_above():
    r = D.diff_reports(_old(), _new())
    assert len(r.added_at_or_above("danger")) == 2  # s3 b.c + ec2 sg.x (both danger)
    assert len(r.added_at_or_above("any")) == 2
    # a warning-only new finding shouldn't trip a danger threshold
    old = FindingsReport(findings=[])
    new = FindingsReport(findings=[Finding("iam", "w.json", "warning", 1)])
    r2 = D.diff_reports(old, new)
    assert r2.added_at_or_above("danger") == []
    assert len(r2.added_at_or_above("warning")) == 1


def test_added_at_or_above_unknown_threshold():
    with pytest.raises(PresidioScoutError, match="unknown threshold"):
        D.diff_reports(_old(), _new()).added_at_or_above("critical")


def test_count_only_finding_new_and_resolved():
    old = FindingsReport(findings=[Finding("iam", "a.json", "warning", 1)])
    new = FindingsReport(findings=[Finding("iam", "b.json", "danger", 1)])
    r = D.diff_reports(old, new)
    assert ("iam", "b.json") in r.new_findings
    assert ("iam", "a.json") in r.resolved_findings


def test_providers_union():
    old = FindingsReport(providers=["aws"], findings=[])
    new = FindingsReport(providers=["gcp"], findings=[])
    assert D.diff_reports(old, new).providers == ["aws", "gcp"]


# --- load_and_diff -----------------------------------------------------------


def test_load_and_diff(tmp_path):
    old = _write_report(tmp_path / "old", _results(("s3", "w.json", "danger", ["a"])))
    new = _write_report(
        tmp_path / "new",
        _results(("s3", "w.json", "danger", ["a"]), ("ec2", "sg.json", "danger", ["x"])),
    )
    r = D.load_and_diff(old, new)
    assert r.new_findings == [("ec2", "sg.json")]


def test_load_and_diff_missing_report(tmp_path):
    with pytest.raises(FindingsError):
        D.load_and_diff(tmp_path / "nope", tmp_path / "alsono")


# --- CLI ---------------------------------------------------------------------


def _cli_reports(tmp_path):
    old = _write_report(tmp_path / "old", _results(("s3", "w.json", "danger", ["a"])))
    new = _write_report(
        tmp_path / "new",
        _results(("s3", "w.json", "danger", ["a"]), ("ec2", "sg.json", "danger", ["x"])),
    )
    return old, new


def test_cli_text(tmp_path, capsys):
    old, new = _cli_reports(tmp_path)
    rc = D._main([str(old), str(new)])
    assert rc == 0
    assert "1 new finding" in capsys.readouterr().out


def test_cli_json(tmp_path, capsys):
    old, new = _cli_reports(tmp_path)
    rc = D._main([str(old), str(new), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["newFindings"] == ["ec2/sg.json"]


def test_cli_fail_on_new_danger(tmp_path, capsys):
    old, new = _cli_reports(tmp_path)
    rc = D._main([str(old), str(new), "--fail-on-new-finding", "danger"])
    assert rc == 4
    assert "newly flagged occurrence" in capsys.readouterr().err


def test_cli_fail_on_new_no_change(tmp_path):
    _, new = _cli_reports(tmp_path)
    assert D._main([str(new), str(new), "--fail-on-new-finding", "any"]) == 0


def test_cli_missing_report_returns_2(tmp_path, capsys):
    rc = D._main([str(tmp_path / "nope"), str(tmp_path / "no2")])
    assert rc == 2
    assert "error" in capsys.readouterr().err
