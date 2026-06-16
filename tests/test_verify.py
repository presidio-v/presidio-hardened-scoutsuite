from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import manifest, report_guard, verify
from presidio_scoutsuite.errors import ReportVerificationError


def _guarded_report(tmp_path, *, sign_key=None):
    (tmp_path / "report.html").write_text("<html><head></head><body>ok</body></html>")
    (tmp_path / "data.js").write_text("var x = 1;")
    report_guard.guard_report(tmp_path, sign_key=sign_key)
    return tmp_path


def test_verify_clean_report(tmp_path):
    _guarded_report(tmp_path)
    result = verify.verify_report(tmp_path)
    assert result.ok
    assert result.signature == verify.SIG_ABSENT
    assert result.verified_count == 2
    assert result.content_digest_ok


def test_verify_detects_modified_file(tmp_path):
    _guarded_report(tmp_path)
    (tmp_path / "data.js").write_text("var x = 2;")
    result = verify.verify_report(tmp_path)
    assert not result.ok
    assert result.modified == ["data.js"]


def test_verify_detects_missing_and_added(tmp_path):
    _guarded_report(tmp_path)
    (tmp_path / "data.js").unlink()
    (tmp_path / "extra.js").write_text("new")
    result = verify.verify_report(tmp_path)
    assert result.missing == ["data.js"]
    assert result.added == ["extra.js"]
    assert not result.ok


def test_verify_signature_ok_with_key(tmp_path):
    _guarded_report(tmp_path, sign_key=b"key")
    result = verify.verify_report(tmp_path, key=b"key")
    assert result.ok
    assert result.signature == verify.SIG_OK


def test_verify_signature_unverified_without_key(tmp_path):
    _guarded_report(tmp_path, sign_key=b"key")
    result = verify.verify_report(tmp_path)  # no key supplied
    assert result.signature == verify.SIG_UNVERIFIED
    assert result.ok  # hashes still confirm integrity


def test_verify_signature_bad_with_wrong_key(tmp_path):
    _guarded_report(tmp_path, sign_key=b"key")
    result = verify.verify_report(tmp_path, key=b"wrong")
    assert result.signature == verify.SIG_BAD
    assert not result.ok


def test_verify_env_key(tmp_path, monkeypatch):
    _guarded_report(tmp_path, sign_key=b"envkey")
    monkeypatch.setenv(manifest.HMAC_ENV_VAR, "envkey")
    result = verify.verify_report(tmp_path)
    assert result.signature == verify.SIG_OK


def test_verify_detects_edited_manifest_hashes(tmp_path):
    _guarded_report(tmp_path)
    path = tmp_path / manifest.MANIFEST_FILENAME
    doc = json.loads(path.read_text())
    doc["files"]["data.js"] = "0" * 64
    path.write_text(json.dumps(doc))
    result = verify.verify_report(tmp_path)
    assert not result.content_digest_ok
    assert not result.ok


def test_verify_missing_manifest_raises(tmp_path):
    (tmp_path / "data.js").write_text("x")
    with pytest.raises(ReportVerificationError, match="no integrity manifest"):
        verify.verify_report(tmp_path)


def test_verify_malformed_manifest_raises(tmp_path):
    (tmp_path / manifest.MANIFEST_FILENAME).write_text("{ not json")
    with pytest.raises(ReportVerificationError, match="cannot read manifest"):
        verify.verify_report(tmp_path)


def test_verify_wrong_shape_raises(tmp_path):
    (tmp_path / manifest.MANIFEST_FILENAME).write_text(json.dumps({"files": "nope"}))
    with pytest.raises(ReportVerificationError, match="malformed"):
        verify.verify_report(tmp_path)


def test_verify_unsupported_algorithm_raises(tmp_path):
    (tmp_path / manifest.MANIFEST_FILENAME).write_text(
        json.dumps({"algorithm": "md5", "files": {}})
    )
    with pytest.raises(ReportVerificationError, match="unsupported hash algorithm"):
        verify.verify_report(tmp_path)


def test_verify_nonexistent_dir_raises(tmp_path):
    with pytest.raises(ReportVerificationError, match="does not exist"):
        verify.verify_report(tmp_path / "nope")


# --- CLI ---------------------------------------------------------------------


def test_cli_verify_ok(tmp_path, capsys):
    _guarded_report(tmp_path)
    rc = verify._main([str(tmp_path)])
    assert rc == 0
    assert "ok" in capsys.readouterr().out


def test_cli_verify_signed_ok_note(tmp_path, capsys, monkeypatch):
    _guarded_report(tmp_path, sign_key=b"k")
    monkeypatch.setenv(manifest.HMAC_ENV_VAR, "k")
    rc = verify._main([str(tmp_path)])
    assert rc == 0
    assert "signature verified" in capsys.readouterr().out


def test_cli_verify_unverified_note(tmp_path, capsys):
    _guarded_report(tmp_path, sign_key=b"k")
    rc = verify._main([str(tmp_path)])
    assert rc == 0
    assert "unverified" in capsys.readouterr().out


def test_cli_verify_tampered_returns_3(tmp_path, capsys):
    _guarded_report(tmp_path)
    (tmp_path / "data.js").write_text("tampered")
    rc = verify._main([str(tmp_path)])
    assert rc == 3
    assert "modified" in capsys.readouterr().err


def test_cli_verify_bad_signature_returns_3(tmp_path, capsys, monkeypatch):
    _guarded_report(tmp_path, sign_key=b"k")
    monkeypatch.setenv(manifest.HMAC_ENV_VAR, "wrong")
    rc = verify._main([str(tmp_path)])
    assert rc == 3
    assert "signature does not match" in capsys.readouterr().err


def test_cli_verify_no_manifest_returns_2(tmp_path, capsys):
    rc = verify._main([str(tmp_path)])
    assert rc == 2
    assert "error" in capsys.readouterr().err
