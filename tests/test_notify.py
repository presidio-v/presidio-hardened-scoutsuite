from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import notify as N
from presidio_scoutsuite.errors import NotificationError, RedactionError


def _report_dir(tmp_path, services=None):
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir(exist_ok=True)
    services = services or {
        "s3": {
            "findings": {
                "s3-bucket-world-acl.json": {
                    "level": "danger",
                    "flagged_items": 2,
                    "description": "world readable",
                },
                "s3-bucket-no-logging.json": {"level": "warning", "flagged_items": 1},
            }
        }
    }
    (sub / "scoutsuite_results_aws.js").write_text(
        "scoutsuite_results =\n" + json.dumps({"provider_code": "aws", "services": services})
    )
    return tmp_path


# --- summary / render --------------------------------------------------------


def test_build_summary(tmp_path):
    s = N.build_summary(_report_dir(tmp_path))
    assert s["providers"] == ["aws"]
    # counts are findings *per level* (one danger finding, one warning finding)
    assert s["totals"] == {"warning": 1, "danger": 1}
    assert s["total_flagged"] == 2
    # top sorted by severity: danger first, key has .json stripped
    assert s["top"][0]["level"] == "danger"
    assert s["top"][0]["key"] == "s3-bucket-world-acl"


def test_summary_top_cap(tmp_path):
    s = N.build_summary(_report_dir(tmp_path), top=1)
    assert len(s["top"]) == 1


def test_build_summary_fails_closed_no_results(tmp_path):
    from presidio_scoutsuite.errors import FindingsError

    with pytest.raises(FindingsError):
        N.build_summary(tmp_path / "empty")


def test_render_text(tmp_path):
    text = N.render_text(N.build_summary(_report_dir(tmp_path)))
    assert "Presidio ScoutSuite audit" in text
    assert "s3/s3-bucket-world-acl" in text
    assert "danger=1" in text


def test_render_json(tmp_path):
    doc = json.loads(N.render_json(N.build_summary(_report_dir(tmp_path))))
    assert doc["total_flagged"] == 2


# --- deliver: file -----------------------------------------------------------


def test_deliver_file(tmp_path):
    out = tmp_path / "n.json"
    msg = N.deliver(sink_type="file", text='{"ok": true}', path=str(out))
    assert out.read_text() == '{"ok": true}'
    assert "wrote notification" in msg


def test_deliver_file_requires_path():
    with pytest.raises(NotificationError, match="file sink requires a path"):
        N.deliver(sink_type="file", text="{}")


# --- deliver: webhook/slack (injected sender) --------------------------------


def test_deliver_webhook_ok():
    captured = {}

    def sender(url, data):
        captured["url"] = url
        captured["data"] = data
        return 200

    msg = N.deliver(sink_type="webhook", text='{"x":1}', url="https://h/x", sender=sender)
    assert captured["url"] == "https://h/x"
    assert captured["data"] == b'{"x":1}'
    assert "HTTP 200" in msg


def test_deliver_webhook_non_2xx_fails_closed():
    with pytest.raises(NotificationError, match="returned HTTP 500"):
        N.deliver(sink_type="webhook", text="{}", url="https://h", sender=lambda u, d: 500)


def test_deliver_webhook_requires_url():
    with pytest.raises(NotificationError, match="requires a url"):
        N.deliver(sink_type="webhook", text="{}", sender=lambda u, d: 200)


def test_deliver_unknown_sink():
    with pytest.raises(NotificationError, match="unknown sink type"):
        N.deliver(sink_type="carrier-pigeon", text="{}")


def test_deliver_refuses_secret_payload():
    # Fail-closed: a secret in the outgoing payload must not be transmitted.
    secret = "AKIAIOSFODNN7EXAMPLE"
    with pytest.raises(RedactionError):
        N.deliver(
            sink_type="webhook",
            text=f'{{"x":"{secret}"}}',
            url="https://h",
            sender=lambda u, d: 200,
        )


# --- resolve_sink ------------------------------------------------------------


def test_resolve_sink(tmp_path):
    cfg = tmp_path / ".presidio-scout.toml"
    cfg.write_text('[sinks.prod]\ntype = "slack"\nurl = "https://hooks/x"\n')
    sink = N.resolve_sink(cfg, "prod")
    assert sink["type"] == "slack"
    assert sink["url"] == "https://hooks/x"


def test_resolve_sink_missing(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[sinks.other]\ntype = "file"\n')
    with pytest.raises(NotificationError, match="no \\[sinks.prod\\]"):
        N.resolve_sink(cfg, "prod")


def test_resolve_sink_bad_type(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[sinks.prod]\ntype = "smoke-signal"\n')
    with pytest.raises(NotificationError, match="needs a 'type'"):
        N.resolve_sink(cfg, "prod")


def test_resolve_sink_malformed(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[sinks.prod\n")
    with pytest.raises(NotificationError, match="cannot read config"):
        N.resolve_sink(cfg, "prod")


# --- _http_post scheme guard -------------------------------------------------


def test_http_post_rejects_non_http():
    with pytest.raises(NotificationError, match="non-HTTP"):
        N._http_post("file:///etc/passwd", b"{}")


# --- CLI ---------------------------------------------------------------------


def test_cli_file_sink(tmp_path, capsys):
    out = tmp_path / "n.json"
    rc = N._main([str(_report_dir(tmp_path)), "--sink", "file", "--path", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["total_flagged"] == 2


def test_cli_file_sink_text(tmp_path):
    out = tmp_path / "n.txt"
    rc = N._main(
        [str(_report_dir(tmp_path)), "--sink", "file", "--path", str(out), "--format", "text"]
    )
    assert rc == 0
    assert "Presidio ScoutSuite audit" in out.read_text()


def test_cli_webhook_via_monkeypatched_post(tmp_path, monkeypatch, capsys):
    posted = {}

    def fake_post(url, data):
        posted["u"] = url
        return 200

    monkeypatch.setattr(N, "_http_post", fake_post)
    rc = N._main([str(_report_dir(tmp_path)), "--sink", "webhook", "--url", "https://h/x"])
    assert rc == 0
    assert posted["u"] == "https://h/x"


def test_cli_slack_posts_text_block(tmp_path, monkeypatch):
    captured = {}

    def fake_post(url, data):
        captured["data"] = data
        return 200

    monkeypatch.setattr(N, "_http_post", fake_post)
    rc = N._main([str(_report_dir(tmp_path)), "--sink", "slack", "--url", "https://hooks/x"])
    assert rc == 0
    assert "text" in json.loads(captured["data"].decode())


def test_cli_no_sink(tmp_path, capsys):
    rc = N._main([str(_report_dir(tmp_path))])
    assert rc == 2
    assert "a sink is required" in capsys.readouterr().err


def test_cli_sink_name_requires_config(tmp_path, capsys):
    rc = N._main([str(_report_dir(tmp_path)), "--sink-name", "prod"])
    assert rc == 2
    assert "requires --config" in capsys.readouterr().err


def test_cli_sink_name_from_config(tmp_path, monkeypatch):
    cfg = tmp_path / ".presidio-scout.toml"
    cfg.write_text('[sinks.prod]\ntype = "webhook"\nurl = "https://hooks/cfg"\n')
    captured = {}

    def fake_post(url, data):
        captured["u"] = url
        return 200

    monkeypatch.setattr(N, "_http_post", fake_post)
    rc = N._main([str(_report_dir(tmp_path)), "--sink-name", "prod", "--config", str(cfg)])
    assert rc == 0
    assert captured["u"] == "https://hooks/cfg"


def test_cli_only_if_skips_when_clean(tmp_path, capsys):
    clean = _report_dir(
        tmp_path,
        services={"s3": {"findings": {"x.json": {"level": "warning", "flagged_items": 1}}}},
    )
    rc = N._main(
        [str(clean), "--sink", "file", "--path", str(tmp_path / "n"), "--only-if", "danger"]
    )
    assert rc == 0
    assert "not sending" in capsys.readouterr().err
    assert not (tmp_path / "n").exists()


def test_cli_bad_report_dir(tmp_path, capsys):
    rc = N._main([str(tmp_path / "nope"), "--sink", "file", "--path", str(tmp_path / "n")])
    assert rc == 2
