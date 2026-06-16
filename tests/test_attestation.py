from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from presidio_scoutsuite import attestation as A
from presidio_scoutsuite import report_guard
from presidio_scoutsuite.errors import AttestationError

WHEN = datetime(2026, 6, 16, tzinfo=timezone.utc)


def _guarded(tmp_path):
    (tmp_path / "report.html").write_text("<html><head></head><body>ok</body></html>")
    (tmp_path / "data.js").write_text("var x = 1;")
    report_guard.guard_report(tmp_path)
    return tmp_path


def _ruleset(tmp_path):
    p = tmp_path / "aws-cis.json"
    p.write_text('{"rules": {}}')
    return p


# --- build -------------------------------------------------------------------


def test_attest_report_shape(tmp_path):
    _guarded(tmp_path)
    stmt = A.attest_report(
        tmp_path,
        provider="aws",
        scoutsuite_version="5.14.0",
        ruleset_path=_ruleset(tmp_path),
        findings={"danger": 1, "warning": 2},
        created=WHEN,
    )
    assert stmt["_type"] == A.STATEMENT_TYPE
    assert stmt["predicateType"] == A.PREDICATE_TYPE
    assert stmt["subject"][0]["name"] == "presidio-report-manifest.json"
    assert len(stmt["subject"][0]["digest"]["sha256"]) == 64
    pred = stmt["predicate"]
    assert pred["provider"] == "aws"
    assert pred["scoutsuiteVersion"] == "5.14.0"
    assert pred["ruleset"]["name"] == "aws-cis.json"
    assert len(pred["ruleset"]["sha256"]) == 64
    assert pred["findings"] == {"danger": 1, "warning": 2}
    assert pred["createdAt"] == "2026-06-16T00:00:00Z"


def test_attest_records_manifest_content_digest(tmp_path):
    _guarded(tmp_path)
    manifest_doc = json.loads((tmp_path / "presidio-report-manifest.json").read_text())
    stmt = A.attest_report(tmp_path, provider="aws", created=WHEN)
    assert stmt["predicate"]["reportManifest"]["contentDigest"] == manifest_doc["content_digest"]


def test_attest_no_ruleset_or_findings(tmp_path):
    _guarded(tmp_path)
    stmt = A.attest_report(tmp_path, provider="gcp", created=WHEN)
    assert stmt["predicate"]["ruleset"] is None
    assert "findings" not in stmt["predicate"]
    assert stmt["predicate"]["scoutsuiteVersion"] is None


def test_attest_missing_manifest_raises(tmp_path):
    (tmp_path / "report.html").write_text("<html></html>")  # not guarded
    with pytest.raises(AttestationError, match="no integrity manifest"):
        A.attest_report(tmp_path, provider="aws")


def test_attest_malformed_manifest_raises(tmp_path):
    (tmp_path / "presidio-report-manifest.json").write_text("{ not json")
    with pytest.raises(AttestationError, match="cannot read manifest"):
        A.attest_report(tmp_path, provider="aws")


def test_build_attestation_missing_ruleset_file(tmp_path):
    _guarded(tmp_path)
    manifest_path = tmp_path / "presidio-report-manifest.json"
    doc = json.loads(manifest_path.read_text())
    with pytest.raises(AttestationError, match="ruleset .* does not exist"):
        A.build_attestation(
            manifest_path=manifest_path,
            manifest_document=doc,
            provider="aws",
            scoutsuite_version="5.14.0",
            ruleset_path=tmp_path / "nope.json",
        )


# --- verify ------------------------------------------------------------------


def test_verify_ok(tmp_path):
    _guarded(tmp_path)
    stmt = A.attest_report(tmp_path, provider="aws", scoutsuite_version="5.14.0", created=WHEN)
    result = A.verify_attestation(tmp_path, stmt)
    assert result.ok
    assert result.provider == "aws"
    assert result.scoutsuite_version == "5.14.0"


def test_verify_detects_report_change(tmp_path):
    _guarded(tmp_path)
    stmt = A.attest_report(tmp_path, provider="aws", created=WHEN)
    # Change the report and re-guard -> manifest digest changes -> attestation stale.
    (tmp_path / "data.js").write_text("var x = 999;")
    report_guard.guard_report(tmp_path)
    result = A.verify_attestation(tmp_path, stmt)
    assert not result.ok
    assert any("subject digest" in e for e in result.errors)
    assert any("content digest" in e for e in result.errors)


def test_verify_wrong_predicate_type(tmp_path):
    _guarded(tmp_path)
    stmt = A.attest_report(tmp_path, provider="aws", created=WHEN)
    stmt["predicateType"] = "https://example.com/other"
    result = A.verify_attestation(tmp_path, stmt)
    assert not result.ok
    assert any("predicate type" in e for e in result.errors)


def test_verify_missing_manifest(tmp_path):
    stmt = {
        "predicateType": A.PREDICATE_TYPE,
        "subject": [{"name": "m", "digest": {"sha256": "x"}}],
        "predicate": {"provider": "aws", "reportManifest": {"contentDigest": "y"}},
    }
    result = A.verify_attestation(tmp_path, stmt)
    assert not result.ok
    assert any("no integrity manifest" in e for e in result.errors)


# --- CLI ---------------------------------------------------------------------


def test_cli_generate_and_verify(tmp_path, capsys):
    _guarded(tmp_path)
    out = tmp_path / "att.json"
    rc = A._main(["generate", str(tmp_path), "--provider", "aws", "-o", str(out)])
    assert rc == 0
    assert "wrote run attestation" in capsys.readouterr().err
    statement = json.loads(out.read_text())
    assert statement["predicateType"] == A.PREDICATE_TYPE

    rc = A._main(["verify", str(tmp_path), str(out)])
    assert rc == 0
    assert "verified" in capsys.readouterr().out


def test_cli_generate_stdout(tmp_path, capsys):
    _guarded(tmp_path)
    rc = A._main(["generate", str(tmp_path), "--provider", "aws"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["predicateType"] == A.PREDICATE_TYPE


def test_cli_generate_missing_manifest_returns_2(tmp_path, capsys):
    rc = A._main(["generate", str(tmp_path), "--provider", "aws"])
    assert rc == 2
    assert "no integrity manifest" in capsys.readouterr().err


def test_cli_verify_failure_returns_3(tmp_path, capsys):
    _guarded(tmp_path)
    stmt = A.attest_report(tmp_path, provider="aws", created=WHEN)
    stmt["predicateType"] = "https://example.com/x"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(stmt))
    rc = A._main(["verify", str(tmp_path), str(bad)])
    assert rc == 3
    assert "FAIL" in capsys.readouterr().err


def test_cli_verify_bad_json_returns_2(tmp_path, capsys):
    _guarded(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    rc = A._main(["verify", str(tmp_path), str(bad)])
    assert rc == 2
    assert "not valid JSON" in capsys.readouterr().err
