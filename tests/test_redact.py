from __future__ import annotations

import pytest

from presidio_scoutsuite import redact
from presidio_scoutsuite.errors import RedactionError


def test_scan_detects_aws_access_key():
    findings = redact.scan("key is AKIAIOSFODNN7EXAMPLE here")
    assert "aws_access_key_id" in findings


def test_redact_replaces_access_key():
    cleaned, findings = redact.redact_text("AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" not in cleaned
    assert redact.PLACEHOLDER in cleaned
    assert findings == ["aws_access_key_id"]


def test_redact_private_key_block():
    blob = "-----BEGIN RSA PRIVATE KEY-----\nMIIBderp\nmore\n-----END RSA PRIVATE KEY-----"
    cleaned, findings = redact.redact_text(blob)
    assert "PRIVATE KEY" not in cleaned
    assert "private_key_block" in findings


def test_redact_authorization_header_keeps_prefix():
    cleaned, findings = redact.redact_text('"authorization": "Bearer abc.def.ghijklmnop"')
    assert "authorization" in cleaned
    assert redact.PLACEHOLDER in cleaned
    assert "abc.def" not in cleaned
    assert "authorization_header" in findings


def test_redact_gcp_and_azure_keys():
    text = '"private_key": "-----stuff-----" AccountKey=abcdefghijklmnop12345=='
    cleaned, findings = redact.redact_text(text)
    assert "gcp_service_account_key" in findings
    assert "azure_account_key" in findings
    assert "abcdefghijklmnop12345" not in cleaned


def test_assert_clean_passes_on_clean_text():
    redact.assert_clean("nothing secret here")


def test_assert_clean_raises_and_hides_secret():
    with pytest.raises(RedactionError) as exc:
        redact.assert_clean("AKIAIOSFODNN7EXAMPLE", where="report.js")
    assert "report.js" in str(exc.value)
    assert "AKIA" not in str(exc.value)


def test_redact_file_rewrites_in_place(tmp_path):
    f = tmp_path / "data.json"
    f.write_text('{"k": "AKIAIOSFODNN7EXAMPLE"}')
    findings = redact.redact_file(f)
    assert findings == ["aws_access_key_id"]
    assert "AKIA" not in f.read_text()


def test_redact_file_skips_binary(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\xff\xfe\x00\x01")
    assert redact.redact_file(f) == []


def test_redact_report_dir_reports_only_dirty_files(tmp_path):
    (tmp_path / "clean.js").write_text("var x = 1;")
    (tmp_path / "dirty.json").write_text('{"key":"AKIAIOSFODNN7EXAMPLE"}')
    sub = tmp_path / "inc"
    sub.mkdir()
    (sub / "nested.html").write_text("AccountKey=abcdefghijklmnop1234==")
    results = redact.redact_report_dir(tmp_path)
    assert "dirty.json" in results
    assert "clean.js" not in results
    assert "inc/nested.html" in results
