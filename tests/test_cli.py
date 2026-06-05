from __future__ import annotations

import subprocess

from presidio_scoutsuite import cli, launcher


def test_dry_run_prints_hardened_command(tmp_path, capsys):
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scout aws" in out
    assert "--no-browser" in out
    assert "--ruleset" in out  # bundled AWS baseline applied by default


def test_no_baseline_omits_ruleset(tmp_path, capsys):
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--no-baseline", "--dry-run"])
    assert rc == 0
    assert "--ruleset" not in capsys.readouterr().out


def test_invalid_passthrough_returns_2(tmp_path, capsys):
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--", "--evil-flag"])
    assert rc == 2
    assert "not on the hardened pass-through" in capsys.readouterr().err


def test_warns_when_no_bundled_ruleset(tmp_path, capsys):
    rc = cli.main(["gcp", "--report-dir", str(tmp_path / "out"), "--dry-run"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "no bundled baseline ruleset" in err


def test_full_run_with_monkeypatched_launcher(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"

    def fake_run(plan, timeout=None):
        # Simulate ScoutSuite writing a report containing a secret.
        (plan.report_dir / "report.html").write_text(
            "<html><head></head><body>AKIAIOSFODNN7EXAMPLE</body></html>"
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir)])
    assert rc == 0
    # secret was redacted out of the report, and CSP was injected
    body = (report_dir / "report.html").read_text()
    assert "AKIA" not in body
    assert "Content-Security-Policy" in body
    out = capsys.readouterr().out
    assert "report ready" in out


def test_fail_on_secret_when_redaction_disabled(tmp_path, monkeypatch):
    report_dir = tmp_path / "out"

    def fake_run(plan, timeout=None):
        (plan.report_dir / "leak.js").write_text("AKIAIOSFODNN7EXAMPLE")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--no-redact", "--fail-on-secret"])
    assert rc == 3


def test_missing_scout_binary_returns_2(tmp_path, monkeypatch, capsys):
    def boom(plan, timeout=None):
        raise FileNotFoundError("scout")

    monkeypatch.setattr(launcher, "run", boom)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out")])
    assert rc == 2
    assert "not found on PATH" in capsys.readouterr().err
