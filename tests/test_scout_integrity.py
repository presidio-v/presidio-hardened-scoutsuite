from __future__ import annotations

import subprocess

import pytest

from presidio_scoutsuite import scout_integrity as si
from presidio_scoutsuite.errors import ScoutIntegrityError


def _runner(stdout="", stderr="", *, raises=None):
    def run(args, **kwargs):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr=stderr)

    return run


def test_pinned_version_matches_the_dependency_group():
    import re
    from pathlib import Path

    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    group = re.search(r"(?ms)^\[dependency-groups\].*?ScoutSuite==([0-9][^\"]*)", pyproject)
    assert group and si.pinned_version() == group.group(1) == "5.14.0"


def test_no_published_extra_pulls_scoutsuite():
    # The pin is a dependency group (unpublished); a [scoutsuite] extra would let a PyPI
    # install pull stock ScoutSuite with azure-identity 1.5.0 and protobuf 3.20.3.
    from pathlib import Path

    tomllib = pytest.importorskip("tomllib")
    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    extras = data["project"].get("optional-dependencies", {})
    assert "scoutsuite" not in extras
    assert not any("scoutsuite" in req.lower() for reqs in extras.values() for req in reqs)


def test_detect_version_parses_first_token():
    assert si.detect_version("scout", runner=_runner(stdout="Scout Suite 5.14.0")) == "5.14.0"


def test_detect_version_reads_stderr_too():
    assert si.detect_version("scout", runner=_runner(stderr="scout 5.14.0")) == "5.14.0"


def test_detect_version_none_when_no_version():
    assert si.detect_version("scout", runner=_runner(stdout="no version here")) is None


def test_detect_version_none_when_missing_executable():
    assert si.detect_version("scout", runner=_runner(raises=FileNotFoundError())) is None


def test_verify_ok(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: "/usr/bin/scout")
    result = si.verify_scout(runner=_runner(stdout="Scout Suite 5.14.0"))
    assert result.ok
    assert result.reason == "ok"
    assert result.resolved_path == "/usr/bin/scout"


def test_verify_version_mismatch_raises(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: "/usr/bin/scout")
    with pytest.raises(ScoutIntegrityError, match="does not match the pinned"):
        si.verify_scout(runner=_runner(stdout="Scout Suite 5.13.0"))


def test_verify_not_found_raises(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: None)
    with pytest.raises(ScoutIntegrityError, match="not found on PATH"):
        si.verify_scout()


def test_verify_undeterminable_version_raises(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: "/usr/bin/scout")
    with pytest.raises(ScoutIntegrityError, match="could not determine the version"):
        si.verify_scout(runner=_runner(stdout="banner with no number"))


def test_verify_require_false_does_not_raise(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: None)
    result = si.verify_scout(require=False)
    assert not result.ok
    assert not result.found
    assert "not found" in result.reason


def test_verify_explicit_expected_version(monkeypatch):
    monkeypatch.setattr(si.shutil, "which", lambda b: "/usr/bin/scout")
    result = si.verify_scout(expected_version="5.13.0", runner=_runner(stdout="scout 5.13.0"))
    assert result.ok
