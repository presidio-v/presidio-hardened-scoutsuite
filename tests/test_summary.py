from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import summary as S


def _report(tmp_path, name="r", services=None):
    d = tmp_path / name
    sub = d / "scoutsuite-results"
    sub.mkdir(parents=True)
    services = services or {
        "s3": {
            "findings": {
                "s3-bucket-world-acl.json": {
                    "level": "danger",
                    "flagged_items": 2,
                    "description": "world readable <bucket>",
                },
                "s3-bucket-no-logging.json": {"level": "warning", "flagged_items": 1},
            }
        }
    }
    (sub / "scoutsuite_results.js").write_text(
        "scoutsuite_results =\n" + json.dumps({"provider_code": "aws", "services": services})
    )
    return d


# --- build -------------------------------------------------------------------


def test_build(tmp_path):
    s = S.build(_report(tmp_path))
    assert s["providers"] == ["aws"]
    assert s["totals"] == {"warning": 1, "danger": 1}
    assert s["total_flagged"] == 2
    assert s["top"][0]["level"] == "danger"
    assert s["compliance"]["cis"] >= 1  # s3-bucket-world-acl maps to a CIS control


def test_build_fails_closed(tmp_path):
    from presidio_scoutsuite.errors import FindingsError

    with pytest.raises(FindingsError):
        S.build(tmp_path / "nope")


# --- renderers ---------------------------------------------------------------


def test_render_markdown(tmp_path):
    md = S.render_markdown(S.build(_report(tmp_path)))
    assert "# Cloud audit summary" in md
    assert "s3/s3-bucket-world-acl" in md
    assert "danger=1" in md


def test_render_html_escapes(tmp_path):
    # a description containing markup must be escaped in the HTML output
    html = S.render_html(S.build(_report(tmp_path)))
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert "<script" not in html
    # the resource/rule appears; angle brackets from data are escaped
    assert "s3/s3-bucket-world-acl" in html
    assert "&lt;" in html or "world readable" not in html  # any raw description is escaped


def test_render_csv(tmp_path):
    csv_text = S.render_csv(_report(tmp_path))
    lines = csv_text.strip().splitlines()
    assert lines[0] == "service,rule,level,flagged_items,description"
    assert any("s3-bucket-world-acl" in ln for ln in lines[1:])


# --- fleet -------------------------------------------------------------------


def test_discover_and_build_fleet(tmp_path):
    base = tmp_path / "fleet"
    base.mkdir()
    _report(base, "prod")
    _report(base, "staging")
    (base / "not-a-report").mkdir()  # ignored (no results)
    targets = S.discover_fleet(base)
    assert set(targets) == {"prod", "staging"}
    fleet = S.build_fleet(targets)
    assert fleet["target_count"] == 2
    assert fleet["total_flagged"] == 4
    assert fleet["totals"] == {"warning": 2, "danger": 2}
    md = S.render_fleet_markdown(fleet)
    assert "Fleet audit summary" in md
    assert "prod" in md and "staging" in md


def test_discover_fleet_missing(tmp_path):
    assert S.discover_fleet(tmp_path / "nope") == {}


# --- CLI ---------------------------------------------------------------------


def test_cli_markdown(tmp_path, capsys):
    assert S._main([str(_report(tmp_path))]) == 0
    assert "Cloud audit summary" in capsys.readouterr().out


def test_cli_html_to_file(tmp_path, capsys):
    out = tmp_path / "s.html"
    assert S._main([str(_report(tmp_path)), "--format", "html", "-o", str(out)]) == 0
    assert out.read_text().startswith("<!doctype html>")


def test_cli_csv(tmp_path, capsys):
    assert S._main([str(_report(tmp_path)), "--format", "csv"]) == 0
    assert "service,rule,level" in capsys.readouterr().out


def test_cli_json(tmp_path, capsys):
    assert S._main([str(_report(tmp_path)), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["total_flagged"] == 2


def test_cli_fleet(tmp_path, capsys):
    base = tmp_path / "fleet"
    base.mkdir()
    _report(base, "prod")
    assert S._main([str(base), "--fleet"]) == 0
    assert "Fleet audit summary" in capsys.readouterr().out


def test_cli_fleet_json(tmp_path, capsys):
    base = tmp_path / "fleet"
    base.mkdir()
    _report(base, "prod")
    assert S._main([str(base), "--fleet", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["target_count"] == 1


def test_cli_fleet_empty(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert S._main([str(tmp_path / "empty"), "--fleet"]) == 2
    assert "no per-target reports" in capsys.readouterr().err


def test_cli_bad_report(tmp_path, capsys):
    assert S._main([str(tmp_path / "nope")]) == 2
