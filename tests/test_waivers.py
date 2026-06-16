from __future__ import annotations

import json
from datetime import date

import pytest

from presidio_scoutsuite import waivers as W
from presidio_scoutsuite.errors import WaiverError
from presidio_scoutsuite.findings import Finding, FindingsReport

TODAY = date(2026, 6, 16)
FUTURE = "2099-01-01"
PAST = "2000-01-01"


def _report():
    return FindingsReport(
        providers=["aws"],
        findings=[
            Finding("s3", "s3-world-acl.json", "danger", 2, items=("s3.b.a", "s3.b.b")),
            Finding("iam", "iam-no-mfa.json", "warning", 1),
            Finding("ec2", "ec2-open-sg.json", "danger", 1, items=("ec2.sg.x",)),
        ],
    )


def _waiver(rule, expires=FUTURE, resource=None):
    return W.Waiver(
        rule=rule,
        justification="accepted",
        owner="sec@example.com",
        expires=date.fromisoformat(expires),
        resource=resource,
    )


# --- loading / validation ----------------------------------------------------


def _write(tmp_path, obj):
    p = tmp_path / "waivers.json"
    p.write_text(json.dumps(obj))
    return p


def test_load_ok(tmp_path):
    p = _write(
        tmp_path,
        {
            "waivers": [
                {
                    "rule": "s3/s3-world-acl",
                    "resource": "s3.b.a",
                    "justification": "public assets",
                    "owner": "web@x",
                    "expires": FUTURE,
                }
            ]
        },
    )
    waivers = W.load_waivers(p)
    assert len(waivers) == 1
    assert waivers[0].rule == "s3/s3-world-acl"
    assert waivers[0].resource == "s3.b.a"
    assert waivers[0].expires == date(2099, 1, 1)


def test_load_missing_file(tmp_path):
    with pytest.raises(WaiverError, match="cannot read"):
        W.load_waivers(tmp_path / "nope.json")


def test_load_bad_json(tmp_path):
    p = tmp_path / "w.json"
    p.write_text("{not json")
    with pytest.raises(WaiverError, match="cannot read"):
        W.load_waivers(p)


def test_load_wrong_shape(tmp_path):
    p = _write(tmp_path, {"nope": []})
    with pytest.raises(WaiverError, match="'waivers' array"):
        W.load_waivers(p)


def test_load_missing_required_field(tmp_path):
    p = _write(tmp_path, {"waivers": [{"rule": "s3/x", "owner": "o", "expires": FUTURE}]})
    with pytest.raises(WaiverError, match="missing required field.*justification"):
        W.load_waivers(p)


def test_load_invalid_expiry(tmp_path):
    p = _write(
        tmp_path,
        {"waivers": [{"rule": "s3/x", "justification": "j", "owner": "o", "expires": "soon"}]},
    )
    with pytest.raises(WaiverError, match="invalid expiry"):
        W.load_waivers(p)


# --- matching ----------------------------------------------------------------


def test_rule_matches_variants():
    f = Finding("s3", "s3-world-acl.json", "danger", 1)
    assert _waiver("s3/s3-world-acl").matches_rule(f)
    assert _waiver("s3/s3-world-acl.json").matches_rule(f)
    assert _waiver("s3-world-acl.json").matches_rule(f)
    assert _waiver("s3-world-acl").matches_rule(f)
    assert not _waiver("iam/other").matches_rule(f)


def test_resource_glob():
    w = _waiver("s3/x", resource="s3.b.*")
    assert w.matches_resource("s3.b.anything")
    assert not w.matches_resource("s3.c.x")


# --- apply -------------------------------------------------------------------


def test_finding_level_suppression():
    out = W.apply_waivers(_report(), [_waiver("iam/iam-no-mfa")], today=TODAY)
    keys = {f.rule for f in out.kept.findings}
    assert "iam-no-mfa.json" not in keys
    assert len(out.suppressed) == 1


def test_resource_level_reduces_count():
    out = W.apply_waivers(_report(), [_waiver("s3/s3-world-acl", resource="s3.b.a")], today=TODAY)
    s3 = next(f for f in out.kept.findings if f.rule == "s3-world-acl.json")
    assert s3.flagged_items == 1
    assert s3.items == ("s3.b.b",)
    assert out.suppressed == []


def test_resource_level_all_items_waived_suppresses():
    out = W.apply_waivers(_report(), [_waiver("s3/s3-world-acl", resource="s3.b.*")], today=TODAY)
    assert all(f.rule != "s3-world-acl.json" for f in out.kept.findings)
    assert any(f.rule == "s3-world-acl.json" for f, _ in out.suppressed)


def test_expired_waiver_does_not_suppress():
    out = W.apply_waivers(_report(), [_waiver("iam/iam-no-mfa", expires=PAST)], today=TODAY)
    assert any(f.rule == "iam-no-mfa.json" for f in out.kept.findings)
    assert len(out.expired) == 1
    assert out.suppressed == []


def test_unused_waiver_reported():
    out = W.apply_waivers(_report(), [_waiver("does/not-exist")], today=TODAY)
    assert len(out.unused) == 1
    assert out.suppressed == []


def test_expired_not_in_unused():
    # An expired waiver that matches is "expired", not "unused".
    out = W.apply_waivers(_report(), [_waiver("iam/iam-no-mfa", expires=PAST)], today=TODAY)
    assert out.unused == []
    assert len(out.expired) == 1


def test_count_only_finding_not_touched_by_resource_waiver():
    # iam finding has no items; a resource-scoped waiver must not suppress it.
    out = W.apply_waivers(_report(), [_waiver("iam/iam-no-mfa", resource="anything")], today=TODAY)
    assert any(f.rule == "iam-no-mfa.json" for f in out.kept.findings)


def test_gate_after_waivers():
    # The danger ec2 finding remains; waiving it clears the danger gate.
    rep = _report()
    assert rep.exceeds("danger")
    out = W.apply_waivers(
        rep,
        [_waiver("ec2/ec2-open-sg"), _waiver("s3/s3-world-acl", resource="s3.b.*")],
        today=TODAY,
    )
    assert not out.kept.exceeds("danger")  # both danger findings waived
    assert out.kept.exceeds("warning")  # iam warning remains


def test_summarize_outcome():
    out = W.apply_waivers(
        _report(),
        [
            _waiver("iam/iam-no-mfa"),
            _waiver("ec2/ec2-open-sg", expires=PAST),
            _waiver("stale/x"),
        ],
        today=TODAY,
    )
    lines = W.summarize_outcome(out)
    assert any("suppressed 1" in line for line in lines)
    assert any("expired waiver" in line for line in lines)
    assert any("matched no current finding" in line for line in lines)
