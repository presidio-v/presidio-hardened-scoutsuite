from __future__ import annotations

import subprocess

from presidio_scoutsuite import cli, launcher, scout_integrity


def _verify_ok(monkeypatch):
    """Make the integrity preflight pass without executing a real scout."""

    monkeypatch.setattr(
        scout_integrity,
        "verify_scout",
        lambda *a, **k: scout_integrity.ScoutIntegrityResult(
            "scout", "/usr/bin/scout", "5.14.0", "5.14.0"
        ),
    )


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


def test_azure_and_gcp_apply_bundled_baseline(tmp_path, capsys):
    for provider in ("azure", "gcp"):
        rc = cli.main([provider, "--report-dir", str(tmp_path / provider), "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert f"scout {provider}" in out
        assert "--ruleset" in out  # bundled baseline applied by default


def test_warns_when_no_bundled_ruleset(tmp_path, capsys):
    # oci ships no curated baseline yet → falls back to ScoutSuite's default.
    rc = cli.main(["oci", "--report-dir", str(tmp_path / "out"), "--dry-run"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "no bundled baseline ruleset" in err


def test_full_run_with_monkeypatched_launcher(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

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
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "leak.js").write_text("AKIAIOSFODNN7EXAMPLE")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--no-redact", "--fail-on-secret"])
    assert rc == 3


def test_full_run_writes_verifiable_manifest(tmp_path, monkeypatch, capsys):
    from presidio_scoutsuite import manifest, verify

    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>clean</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir)])
    assert rc == 0
    assert "integrity manifest" in capsys.readouterr().out
    assert (report_dir / manifest.MANIFEST_FILENAME).exists()
    # the freshly written report verifies against its own manifest
    assert verify.verify_report(report_dir).ok


def test_fail_on_remote_ref(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text(
            '<html><head></head><body><script src="https://cdn.example/x.js"></script>'
            "</body></html>"
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--fail-on-remote-ref"])
    assert rc == 3
    assert "remote resources" in capsys.readouterr().err


def test_integrity_gate_blocks_unverified_scout(tmp_path, monkeypatch, capsys):
    # scout not resolvable -> preflight fails closed before anything runs.
    monkeypatch.setattr(scout_integrity.shutil, "which", lambda b: None)
    called = {"run": False}
    monkeypatch.setattr(launcher, "run", lambda *a, **k: called.__setitem__("run", True))
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found on PATH" in err
    assert "--allow-unverified-scout" in err
    assert called["run"] is False  # never reached the subprocess


def test_integrity_gate_version_mismatch_blocks(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scout_integrity.shutil, "which", lambda b: "/usr/bin/scout")
    monkeypatch.setattr(
        scout_integrity,
        "detect_version",
        lambda *a, **k: "5.13.0",
    )
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out")])
    assert rc == 2
    assert "does not match the pinned" in capsys.readouterr().err


def test_allow_unverified_scout_warns_and_continues(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scout_integrity.shutil, "which", lambda b: None)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--allow-unverified-scout"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "running unverified ScoutSuite" in err


def test_allow_unverified_then_missing_scout_returns_2(tmp_path, monkeypatch, capsys):
    # With the gate bypassed, a scout that still isn't runnable falls through to
    # the launcher's FileNotFoundError handler.
    monkeypatch.setattr(scout_integrity.shutil, "which", lambda b: None)

    def boom(plan, timeout=None):
        raise FileNotFoundError("scout")

    monkeypatch.setattr(launcher, "run", boom)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--allow-unverified-scout"])
    assert rc == 2
    assert "not found on PATH" in capsys.readouterr().err


def _write_results(report_dir, results):
    import json

    sub = report_dir / "scoutsuite-results"
    sub.mkdir(parents=True, exist_ok=True)
    (sub / "scoutsuite_results_aws-1.js").write_text("scoutsuite_results =\n" + json.dumps(results))


def test_fail_on_finding_danger_returns_4(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"world.json": {"level": "danger", "flagged_items": 2}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--fail-on-finding", "danger"])
    assert rc == 4
    out = capsys.readouterr()
    assert "findings: 1 flagged" in out.out
    assert "at or above 'danger'" in out.err


def test_fail_on_finding_under_threshold_returns_0(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"warn.json": {"level": "warning", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--fail-on-finding", "danger"])
    assert rc == 0


def test_asff_export_written(tmp_path, monkeypatch, capsys):
    import json

    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)
    out = tmp_path / "asff.json"

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {
                        "findings": {
                            "s3-bucket-world-acl.json": {"level": "danger", "flagged_items": 1}
                        }
                    }
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--asff",
            str(out),
            "--aws-account-id",
            "123456789012",
            "--aws-region",
            "us-east-1",
        ]
    )
    assert rc == 0
    assert "ASFF written" in capsys.readouterr().out
    doc = json.loads(out.read_text())
    assert doc[0]["AwsAccountId"] == "123456789012"
    assert "CIS 2.1.5" in doc[0]["Compliance"]["RelatedRequirements"]


def test_asff_requires_account_and_region(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"world.json": {"level": "danger", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--asff", str(tmp_path / "a.json")])
    assert rc == 2
    assert "requires --aws-account-id and --aws-region" in capsys.readouterr().err


def test_fail_on_finding_no_results_fails_closed(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--fail-on-finding", "warning"])
    assert rc == 2
    assert "cannot read findings" in capsys.readouterr().err


def test_sarif_written_during_run(tmp_path, monkeypatch, capsys):
    import json

    report_dir = tmp_path / "out"
    sarif_path = tmp_path / "results.sarif"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"w.json": {"level": "warning", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--sarif", str(sarif_path)])
    assert rc == 0
    assert "SARIF written" in capsys.readouterr().out
    doc = json.loads(sarif_path.read_text())
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1


def test_sarif_and_fail_on_finding_together(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    sarif_path = tmp_path / "r.sarif"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"w.json": {"level": "danger", "flagged_items": 3}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--sarif",
            str(sarif_path),
            "--fail-on-finding",
            "danger",
        ]
    )
    # SARIF is still written even though the gate trips (exit 4).
    assert rc == 4
    assert sarif_path.exists()


def test_waiver_suppresses_gate(tmp_path, monkeypatch, capsys):
    import json

    report_dir = tmp_path / "out"
    waivers_file = tmp_path / "waivers.json"
    waivers_file.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "rule": "s3/world",
                        "justification": "accepted public bucket",
                        "owner": "web@example.com",
                        "expires": "2099-01-01",
                    }
                ]
            }
        )
    )
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"world.json": {"level": "danger", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--fail-on-finding",
            "danger",
            "--waivers",
            str(waivers_file),
        ]
    )
    # The only danger finding is waived -> gate passes.
    assert rc == 0
    assert "suppressed 1" in capsys.readouterr().err


def test_bad_waiver_file_fails_closed(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {"provider_code": "aws", "services": {}},
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--fail-on-finding",
            "warning",
            "--waivers",
            str(tmp_path / "missing.json"),
        ]
    )
    assert rc == 2
    assert "cannot read findings" in capsys.readouterr().err


def test_attest_written_during_run(tmp_path, monkeypatch, capsys):
    import json

    from presidio_scoutsuite import attestation

    report_dir = tmp_path / "out"
    attest_path = tmp_path / "run.intoto.json"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(report_dir), "--attest", str(attest_path)])
    assert rc == 0
    assert "run attestation" in capsys.readouterr().out
    statement = json.loads(attest_path.read_text())
    assert statement["predicateType"] == attestation.PREDICATE_TYPE
    assert statement["predicate"]["provider"] == "aws"
    # The freshly written attestation verifies against the report it describes.
    assert attestation.verify_attestation(report_dir, statement).ok


def test_attest_written_even_when_gate_trips(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    attest_path = tmp_path / "run.intoto.json"
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"w.json": {"level": "danger", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--fail-on-finding",
            "danger",
            "--attest",
            str(attest_path),
        ]
    )
    # Gate trips (exit 4) but the attestation is still written.
    assert rc == 4
    assert attest_path.exists()


def test_require_short_lived_creds_blocks_static_key(tmp_path, monkeypatch, capsys):
    _verify_ok(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    def fake_run(plan, timeout=None):  # should never be reached
        raise AssertionError("must not run with static credentials under the strict gate")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--require-short-lived-creds"])
    assert rc == 2
    assert "long-lived access key" in capsys.readouterr().err


def test_static_key_warns_by_default(tmp_path, monkeypatch, capsys):
    _verify_ok(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out")])
    assert rc == 0
    assert "prefer short-lived credentials" in capsys.readouterr().err


def test_short_lived_creds_pass_silently(tmp_path, monkeypatch, capsys):
    _verify_ok(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "tok")

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--require-short-lived-creds"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "credentials" not in err  # no warning/error for short-lived creds


def test_config_provides_provider_and_defaults(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    cfg = tmp_path / ".presidio-scout.toml"
    cfg.write_text(f'[defaults]\nprovider = "aws"\nreport-dir = "{report_dir}"\n')
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        assert plan.provider == "aws"  # provider came from the config
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["--config", str(cfg)])  # no provider on the CLI
    assert rc == 0
    assert "report ready" in capsys.readouterr().out


def test_config_profile_gate_trips(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    cfg = tmp_path / ".presidio-scout.toml"
    cfg.write_text(
        f'[defaults]\nprovider = "aws"\nreport-dir = "{report_dir}"\n'
        '[profiles.nightly]\nfail-on-finding = "danger"\n'
    )
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        _write_results(
            plan.report_dir,
            {
                "provider_code": "aws",
                "services": {
                    "s3": {"findings": {"w.json": {"level": "danger", "flagged_items": 1}}}
                },
            },
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(["--config", str(cfg), "--profile", "nightly"])
    assert rc == 4  # the profile's fail-on-finding danger gate trips


def test_cli_flag_overrides_config(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    cfg = tmp_path / ".presidio-scout.toml"
    # config says gcp, but the CLI passes aws explicitly -> aws wins
    cfg.write_text(f'[defaults]\nprovider = "gcp"\nreport-dir = "{report_dir}"\n')
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        assert plan.provider == "aws"
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    assert cli.main(["aws", "--config", str(cfg)]) == 0


def test_missing_provider_no_config_returns_2(tmp_path, monkeypatch, capsys):
    # run from an empty dir so no .presidio-scout.toml is auto-discovered
    monkeypatch.chdir(tmp_path)
    rc = cli.main([])
    assert rc == 2
    assert "no provider given" in capsys.readouterr().err


def test_bad_config_returns_2(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / ".presidio-scout.toml"
    cfg.write_text("[defaults]\nbogus = 1")
    rc = cli.main(["aws", "--config", str(cfg)])
    assert rc == 2
    assert "unknown setting" in capsys.readouterr().err


def test_dry_run_skips_integrity_gate(tmp_path, monkeypatch, capsys):
    # --dry-run runs nothing, so it must not require a verified scout.
    def boom(*a, **k):
        raise AssertionError("integrity gate should not run during --dry-run")

    monkeypatch.setattr(scout_integrity, "verify_scout", boom)
    rc = cli.main(["aws", "--report-dir", str(tmp_path / "out"), "--dry-run"])
    assert rc == 0
