from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import orchestrate as O
from presidio_scoutsuite.errors import OrchestrationError

_GOOD = """
[[targets]]
name = "prod-aws"
provider = "aws"
env = { AWS_PROFILE = "prod-audit", AWS_DEFAULT_REGION = "us-east-1" }
args = ["--fail-on-finding", "danger"]

[[targets]]
name = "analytics-gcp"
provider = "gcp"
env = { CLOUDSDK_CORE_PROJECT = "analytics-123" }
"""


def _write(tmp_path, text, name=".presidio-scout-targets.toml"):
    p = tmp_path / name
    p.write_text(text)
    return p


# --- load / validate ---------------------------------------------------------


def test_load_good(tmp_path):
    targets = O.load_targets(_write(tmp_path, _GOOD))
    assert [t.name for t in targets] == ["prod-aws", "analytics-gcp"]
    assert targets[0].provider == "aws"
    assert targets[0].env["AWS_PROFILE"] == "prod-audit"
    assert targets[0].args == ("--fail-on-finding", "danger")


def test_empty_targets(tmp_path):
    with pytest.raises(OrchestrationError, match="non-empty"):
        O.load_targets(_write(tmp_path, "x = 1"))


def test_duplicate_name(tmp_path):
    text = '[[targets]]\nname="a"\nprovider="aws"\n[[targets]]\nname="a"\nprovider="gcp"'
    with pytest.raises(OrchestrationError, match="duplicate target name"):
        O.load_targets(_write(tmp_path, text))


def test_unknown_provider(tmp_path):
    with pytest.raises(OrchestrationError, match="unknown provider"):
        O.load_targets(_write(tmp_path, '[[targets]]\nname="a"\nprovider="neptune"'))


def test_unknown_key(tmp_path):
    with pytest.raises(OrchestrationError, match="unknown key"):
        O.load_targets(_write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"\nbogus=1'))


def test_missing_name(tmp_path):
    with pytest.raises(OrchestrationError, match="non-empty 'name'"):
        O.load_targets(_write(tmp_path, '[[targets]]\nprovider="aws"'))


def test_bad_env_shape(tmp_path):
    with pytest.raises(OrchestrationError, match="'env' must be a table of strings"):
        O.load_targets(_write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"\nenv={x=1}'))


def test_non_credential_env_rejected(tmp_path):
    with pytest.raises(OrchestrationError, match="non-credential key"):
        O.load_targets(
            _write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"\nenv={PATH="/tmp/bin"}')
        )


def test_bad_args_shape(tmp_path):
    with pytest.raises(OrchestrationError, match="'args' must be a list"):
        O.load_targets(_write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"\nargs="x"'))


def test_malformed_toml(tmp_path):
    with pytest.raises(OrchestrationError, match="cannot read targets file"):
        O.load_targets(_write(tmp_path, "[[targets]]\nname = "))


def test_find_targets(tmp_path):
    assert O.find_targets(tmp_path) is None
    _write(tmp_path, _GOOD)
    assert O.find_targets(tmp_path) == tmp_path / ".presidio-scout-targets.toml"


# --- run_target / run_all (injected runner) ----------------------------------


def _results_writer(counts_by_name):
    """Build a fake runner that writes a results file per target and returns 0."""

    def runner(argv, env, timeout):
        # argv = [cmd, provider, "--report-dir", <dir>, ...]
        report_dir = argv[argv.index("--report-dir") + 1]
        name = report_dir.rsplit("/", 1)[-1]
        sub = __import__("pathlib").Path(report_dir) / "scoutsuite-results"
        sub.mkdir(parents=True, exist_ok=True)
        lvl, n = counts_by_name[name]
        services = {"s3": {"findings": {f"{name}.json": {"level": lvl, "flagged_items": n}}}}
        results = {"provider_code": "aws", "services": services}
        (sub / "scoutsuite_results.js").write_text("scoutsuite_results =\n" + json.dumps(results))
        return 0

    return runner


def test_run_target_passes_env_and_args(tmp_path):
    captured = {}

    def runner(argv, env, timeout):
        captured["argv"] = argv
        captured["env"] = env
        (tmp_path / "out" / "prod-aws" / "scoutsuite-results").mkdir(parents=True)
        (tmp_path / "out" / "prod-aws" / "scoutsuite-results" / "scoutsuite_results.js").write_text(
            'scoutsuite_results =\n{"provider_code":"aws","services":{}}'
        )
        return 0

    target = O.Target("prod-aws", "aws", {"AWS_PROFILE": "p"}, ("--no-baseline",))
    result = O.run_target(
        target,
        base_report_dir=tmp_path / "out",
        base_env={"PATH": "/usr/bin", "GITHUB_TOKEN": "ghp_secret"},
        extra_args=["--require-short-lived-creds"],
        runner=runner,
    )
    assert result.ok
    assert captured["argv"][:2] == ["presidio-scout", "aws"]
    assert "--no-baseline" in captured["argv"]
    assert "--require-short-lived-creds" in captured["argv"]
    assert captured["env"]["AWS_PROFILE"] == "p"
    assert captured["env"]["PATH"] == "/usr/bin"
    assert "GITHUB_TOKEN" not in captured["env"]


def test_run_target_rejects_non_credential_env(tmp_path):
    target = O.Target("prod-aws", "aws", {"PYTHONPATH": "/tmp"})
    with pytest.raises(OrchestrationError, match="non-credential key"):
        O.run_target(target, base_report_dir=tmp_path / "out", base_env={}, runner=lambda *a: 0)


def test_run_target_runner_oserror_fails_closed(tmp_path):
    def boom(argv, env, timeout):
        raise OSError("no exec")

    result = O.run_target(O.Target("t", "aws"), base_report_dir=tmp_path, base_env={}, runner=boom)
    assert not result.ok
    assert result.exit_code == 2
    assert "run failed" in result.error


def test_run_target_missing_results_records_error(tmp_path):
    result = O.run_target(
        O.Target("t", "aws"),
        base_report_dir=tmp_path,
        base_env={},
        runner=lambda *a: 0,
    )
    assert result.exit_code == 0
    assert result.counts is None
    assert "could not read findings" in result.error


def test_run_all_and_totals(tmp_path):
    targets = [O.Target("a", "aws"), O.Target("b", "aws")]
    runner = _results_writer({"a": ("danger", 2), "b": ("warning", 3)})
    report = O.run_all(targets, base_report_dir=tmp_path, base_env={}, runner=runner)
    # counts are *findings* per level; each target writes one flagged finding.
    assert report.totals == {"warning": 1, "danger": 1}
    assert report.failed == []


def test_gate_breaches(tmp_path):
    targets = [O.Target("a", "aws"), O.Target("b", "aws")]
    runner = _results_writer({"a": ("danger", 1), "b": ("warning", 1)})
    report = O.run_all(targets, base_report_dir=tmp_path, base_env={}, runner=runner)
    danger = report.gate_breaches("danger")
    assert [r.name for r in danger] == ["a"]
    assert {r.name for r in report.gate_breaches("warning")} == {"a", "b"}


def test_gate_unreadable_results_is_a_breach(tmp_path):
    # A target whose results can't be read must not pass the gate (fail-closed).
    report = O.run_all(
        [O.Target("a", "aws")], base_report_dir=tmp_path, base_env={}, runner=lambda *a: 0
    )
    assert [r.name for r in report.gate_breaches("danger")] == ["a"]


def test_gate_bad_level(tmp_path):
    report = O.OrchestrationReport([])
    with pytest.raises(OrchestrationError, match="unknown severity"):
        report.gate_breaches("nope")


# --- CLI ---------------------------------------------------------------------


def test_cli_no_targets_file(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert O._main(["--report-dir", str(tmp_path / "f")]) == 2
    assert "no targets file" in capsys.readouterr().err


def test_cli_run_ok(tmp_path, capsys, monkeypatch):
    cfg = _write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"')
    monkeypatch.setattr(O, "_default_runner", lambda *a: 0)
    runner = _results_writer({"a": ("warning", 1)})
    monkeypatch.setattr(
        O,
        "run_all",
        lambda targets, **kw: O.OrchestrationReport(
            [
                O.run_target(
                    targets[0], runner=runner, **{k: v for k, v in kw.items() if k != "runner"}
                )
            ]
        ),
    )
    rc = O._main(["--targets", str(cfg), "--report-dir", str(tmp_path / "f"), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["totals"]["warning"] == 1


def test_cli_failed_target_returns_2(tmp_path, capsys, monkeypatch):
    cfg = _write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"')

    def fake_run_all(targets, **kw):
        return O.OrchestrationReport(
            [O.TargetResult("a", "aws", 2, str(tmp_path / "f" / "a"), error="run failed: boom")]
        )

    monkeypatch.setattr(O, "run_all", fake_run_all)
    rc = O._main(["--targets", str(cfg), "--report-dir", str(tmp_path / "f")])
    assert rc == 2
    assert "did not complete" in capsys.readouterr().err


def test_cli_fail_on_finding_gate(tmp_path, capsys, monkeypatch):
    cfg = _write(tmp_path, '[[targets]]\nname="a"\nprovider="aws"')
    runner = _results_writer({"a": ("danger", 1)})

    def fake_run_all(targets, **kw):
        kw.pop("runner", None)
        return O.OrchestrationReport([O.run_target(targets[0], runner=runner, **kw)])

    monkeypatch.setattr(O, "run_all", fake_run_all)
    rc = O._main(
        ["--targets", str(cfg), "--report-dir", str(tmp_path / "f"), "--fail-on-finding", "danger"]
    )
    assert rc == 4
    assert "at or above 'danger'" in capsys.readouterr().err
