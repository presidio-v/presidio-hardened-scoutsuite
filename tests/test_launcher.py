from __future__ import annotations

import os
import stat

import pytest

from presidio_scoutsuite import launcher
from presidio_scoutsuite.errors import LauncherError


def test_build_plan_forces_hardened_flags(tmp_path):
    plan = launcher.build_plan("aws", tmp_path / "out", ruleset="r.json")
    assert plan.argv[:2] == ["scout", "aws"]
    assert "--no-browser" in plan.argv
    assert "--report-dir" in plan.argv
    assert "--ruleset" in plan.argv
    assert plan.report_dir.exists()


def test_build_plan_rejects_unknown_provider(tmp_path):
    with pytest.raises(LauncherError, match="unknown provider"):
        launcher.build_plan("digitalocean", tmp_path / "out")


def test_passthrough_allowlist_accepts_known_flags():
    args = launcher.validate_passthrough(["--profile", "audit", "--all-regions"])
    assert args == ["--profile", "audit", "--all-regions"]


def test_passthrough_rejects_unknown_flag():
    with pytest.raises(LauncherError, match="not on the hardened pass-through"):
        launcher.validate_passthrough(["--definitely-not-a-flag"])


def test_passthrough_rejects_launcher_owned_flag():
    with pytest.raises(LauncherError, match="managed by the hardened launcher"):
        launcher.validate_passthrough(["--report-dir", "/tmp/evil"])


def test_passthrough_value_flag_requires_value():
    with pytest.raises(LauncherError, match="requires a value"):
        launcher.validate_passthrough(["--profile"])


def test_passthrough_value_flag_rejects_flag_as_value():
    with pytest.raises(LauncherError, match="requires a value"):
        launcher.validate_passthrough(["--profile", "--all-regions"])


def test_passthrough_rejects_bare_positional():
    with pytest.raises(LauncherError, match="unexpected positional"):
        launcher.validate_passthrough(["surprise"])


def test_scrub_env_keeps_cloud_and_essentials_drops_rest():
    base = {
        "AWS_ACCESS_KEY_ID": "AKIA...",
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "ghp_secret",
        "MY_DB_PASSWORD": "hunter2",
        "AZURE_CLIENT_SECRET": "shh",
    }
    scrubbed = launcher.scrub_env(base)
    assert scrubbed["AWS_ACCESS_KEY_ID"] == "AKIA..."
    assert scrubbed["AZURE_CLIENT_SECRET"] == "shh"
    assert scrubbed["PATH"] == "/usr/bin"
    assert "GITHUB_TOKEN" not in scrubbed
    assert "MY_DB_PASSWORD" not in scrubbed


def test_scrub_env_keeps_managed_identity_endpoints():
    # Keyless / managed-identity vars aren't cloud-prefixed but must reach the
    # child so federated auth works without any long-lived secret.
    base = {
        "IDENTITY_ENDPOINT": "http://169.254.169.254/...",
        "IDENTITY_HEADER": "hdr",
        "MSI_ENDPOINT": "http://...",
        "MSI_SECRET": "x",
        "UNRELATED": "drop",
    }
    scrubbed = launcher.scrub_env(base)
    assert set(scrubbed) == {"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "MSI_ENDPOINT", "MSI_SECRET"}


def test_harden_report_dir_sets_0700(tmp_path):
    target = tmp_path / "report"
    path = launcher.harden_report_dir(target)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o700


def test_harden_report_dir_rejects_file(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    with pytest.raises(LauncherError, match="not a directory"):
        launcher.harden_report_dir(f)


def test_run_uses_injected_runner_and_scrubbed_env(tmp_path):
    plan = launcher.build_plan("aws", tmp_path / "out")
    captured = {}

    def fake_runner(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        captured["umask"] = os.umask(0o022)  # observe current umask, then restore below
        os.umask(captured["umask"])
        import subprocess

        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    result = launcher.run(plan, runner=fake_runner)
    assert result.returncode == 0
    assert captured["argv"] == plan.argv
    assert "PATH" in captured["env"]
    # umask was tightened to 0o077 inside run()
    assert captured["umask"] == 0o077
