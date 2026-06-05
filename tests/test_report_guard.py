from __future__ import annotations

import pytest

from presidio_scoutsuite import report_guard
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
