from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import manifest, report_guard
from presidio_scoutsuite.errors import ReportGuardError


def test_inject_csp_adds_meta_after_head():
    html = "<html><head><title>r</title></head><body>x</body></html>"
    out, changed = report_guard.inject_csp(html)
    assert changed
    assert "Content-Security-Policy" in out
    assert out.index("Content-Security-Policy") > out.index("<head>")


def test_inject_csp_idempotent():
    html = "<html><head><title>r</title></head></html>"
    once, _ = report_guard.inject_csp(html)
    twice, changed = report_guard.inject_csp(once)
    assert not changed
    assert twice == once


def test_inject_csp_noop_without_head():
    html = "<html><body>no head</body></html>"
    out, changed = report_guard.inject_csp(html)
    assert not changed
    assert out == html


def test_guard_report_hardens_html_and_builds_manifest(tmp_path):
    (tmp_path / "report.html").write_text("<html><head></head><body>ok</body></html>")
    (tmp_path / "data.js").write_text("var x = 1;")
    result = report_guard.guard_report(tmp_path)
    assert "report.html" in result.html_hardened
    assert set(result.manifest) == {"report.html", "data.js"}
    assert "Content-Security-Policy" in (tmp_path / "report.html").read_text()
    assert not result.has_secrets


def test_guard_report_flags_secret(tmp_path):
    (tmp_path / "leak.js").write_text('token="AKIAIOSFODNN7EXAMPLE"')
    result = report_guard.guard_report(tmp_path)
    assert result.has_secrets
    assert "leak.js" in result.secret_findings


def test_guard_report_fail_on_secret_raises(tmp_path):
    (tmp_path / "leak.js").write_text("AKIAIOSFODNN7EXAMPLE")
    with pytest.raises(ReportGuardError, match="secrets present"):
        report_guard.guard_report(tmp_path, fail_on_secret=True)


def test_guard_report_missing_dir(tmp_path):
    with pytest.raises(ReportGuardError, match="does not exist"):
        report_guard.guard_report(tmp_path / "nope")


# --- Subresource Integrity ---------------------------------------------------


def _report_with_assets(tmp_path):
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "app.js").write_text("var x = 1;")
    (tmp_path / "inc" / "style.css").write_text("body{}")
    (tmp_path / "report.html").write_text(
        "<html><head></head><body>"
        '<link rel="stylesheet" href="inc/style.css">'
        '<script src="inc/app.js"></script>'
        "</body></html>"
    )


def test_inject_sri_pins_local_script_and_stylesheet(tmp_path):
    _report_with_assets(tmp_path)
    html = (tmp_path / "report.html").read_text()
    out, pinned, remote = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    assert sorted(pinned) == ["inc/app.js", "inc/style.css"]
    assert remote == []
    assert out.count('integrity="sha384-') == 2
    assert 'crossorigin="anonymous"' in out


def test_inject_sri_is_idempotent(tmp_path):
    _report_with_assets(tmp_path)
    html = (tmp_path / "report.html").read_text()
    once, _, _ = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    twice, pinned, _ = report_guard.inject_sri(once, base_dir=tmp_path, root=tmp_path)
    assert pinned == []
    assert twice == once


def test_inject_sri_flags_remote_and_skips_missing(tmp_path):
    (tmp_path / "report.html").write_text(
        "<html><head></head><body>"
        '<script src="https://cdn.example/x.js"></script>'
        '<script src="//cdn.example/y.js"></script>'
        '<script src="gone.js"></script>'
        "</body></html>"
    )
    html = (tmp_path / "report.html").read_text()
    out, pinned, remote = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    assert pinned == []  # remote not pinned, missing local skipped
    assert remote == ["https://cdn.example/x.js", "//cdn.example/y.js"]
    assert "integrity=" not in out


def test_inject_sri_ignores_non_stylesheet_link(tmp_path):
    (tmp_path / "favicon.ico").write_text("x")
    (tmp_path / "report.html").write_text(
        '<html><head><link rel="icon" href="favicon.ico"></head><body></body></html>'
    )
    html = (tmp_path / "report.html").read_text()
    out, pinned, _ = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    assert pinned == []
    assert "integrity=" not in out


def test_inject_sri_self_closing_link(tmp_path):
    (tmp_path / "style.css").write_text("body{}")
    html = '<html><head><link rel="stylesheet" href="style.css"/></head></html>'
    out, pinned, _ = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    assert pinned == ["style.css"]
    assert 'integrity="sha384-' in out
    assert out.endswith("/></head></html>")


def test_inject_sri_skips_empty_path(tmp_path):
    html = '<html><head></head><body><script src="?only=query"></script></body></html>'
    out, pinned, _ = report_guard.inject_sri(html, base_dir=tmp_path, root=tmp_path)
    assert pinned == []
    assert "integrity=" not in out


def test_inject_sri_rejects_path_traversal(tmp_path):
    (tmp_path.parent / "outside.js").write_text("secret")
    sub = tmp_path / "report"
    sub.mkdir()
    (sub / "report.html").write_text(
        '<html><head></head><body><script src="../outside.js"></script></body></html>'
    )
    html = (sub / "report.html").read_text()
    out, pinned, _ = report_guard.inject_sri(html, base_dir=sub, root=sub)
    assert pinned == []
    assert "integrity=" not in out


# --- Manifest persistence ----------------------------------------------------


def test_guard_report_writes_manifest(tmp_path):
    _report_with_assets(tmp_path)
    result = report_guard.guard_report(tmp_path)
    assert result.manifest_path == tmp_path / manifest.MANIFEST_FILENAME
    assert result.manifest_path.exists()
    doc = json.loads(result.manifest_path.read_text())
    # the manifest excludes itself from the inventory it records
    assert manifest.MANIFEST_FILENAME not in doc["files"]
    assert set(doc["files"]) == {"report.html", "inc/app.js", "inc/style.css"}
    assert doc["content_digest"] == manifest.content_digest("sha256", doc["files"])
    assert result.sri_hardened == ["report.html"]


def test_guard_report_no_write_manifest(tmp_path):
    (tmp_path / "data.js").write_text("var x = 1;")
    result = report_guard.guard_report(tmp_path, write_manifest=False)
    assert result.manifest_path is None
    assert not (tmp_path / manifest.MANIFEST_FILENAME).exists()
    assert result.manifest_document["files"] == {"data.js": result.manifest["data.js"]}


def test_guard_report_signs_manifest_with_env_key(tmp_path, monkeypatch):
    (tmp_path / "data.js").write_text("var x = 1;")
    monkeypatch.setenv(manifest.HMAC_ENV_VAR, "pipeline-key")
    result = report_guard.guard_report(tmp_path)
    assert result.manifest_document["signature"]["algorithm"] == manifest.SIGNATURE_ALGORITHM


def test_guard_report_fail_on_remote_ref(tmp_path):
    (tmp_path / "report.html").write_text(
        '<html><head></head><body><script src="https://cdn.example/x.js"></script></body></html>'
    )
    with pytest.raises(ReportGuardError, match="remote resources"):
        report_guard.guard_report(tmp_path, fail_on_remote_ref=True)


def test_guard_report_rerun_excludes_prior_manifest(tmp_path):
    (tmp_path / "data.js").write_text("var x = 1;")
    first = report_guard.guard_report(tmp_path)
    second = report_guard.guard_report(tmp_path)
    assert set(first.manifest) == set(second.manifest) == {"data.js"}
