from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import upgrade as U
from presidio_scoutsuite.errors import UpgradeError

_PYPROJECT = """\
[project]
name = "presidio-hardened-scoutsuite"

[project.optional-dependencies]
scoutsuite = ["ScoutSuite==5.14.0"]
"""

_LOCK = """\
# header
aiohttp==3.14.1 \\
    --hash=sha256:deadbeef
scoutsuite==5.14.0 \\
    --hash=sha256:450f06f55dccadcc \\
    --hash=sha256:b021ad340196865
    # via presidio-hardened-scoutsuite (pyproject.toml)
six==1.17.0 \\
    --hash=sha256:cafef00d
"""

_INTEGRITY = '''\
"""scout integrity."""

PINNED_SCOUTSUITE_VERSION = "5.14.0"

_OWN = "presidio-hardened-scoutsuite"
'''


def _repo(tmp_path, *, pyproject=_PYPROJECT, lock=_LOCK, integrity=_INTEGRITY):
    (tmp_path / "pyproject.toml").write_text(pyproject)
    (tmp_path / "requirements.lock").write_text(lock)
    pkg = tmp_path / "src" / "presidio_scoutsuite"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "scout_integrity.py").write_text(integrity)
    return tmp_path


# --- parse_version -----------------------------------------------------------


@pytest.mark.parametrize("good", ["5.14.0", "5.14", "1.2.3.4", "10.0.0"])
def test_parse_version_good(good):
    assert isinstance(U.parse_version(good), tuple)


@pytest.mark.parametrize("bad", ["5", "5.x", "5.14.0rc1", "v5.14.0", "", "5.14.*"])
def test_parse_version_bad(bad):
    with pytest.raises(UpgradeError, match="malformed version"):
        U.parse_version(bad)


def test_version_ordering():
    assert U.parse_version("5.14.1") > U.parse_version("5.14.0")
    assert U.parse_version("5.14.0") < U.parse_version("6.0.0")


# --- discovery / coherence ---------------------------------------------------


def test_discover_pins(tmp_path):
    pins = U.discover_pins(_repo(tmp_path))
    assert [p.version for p in pins] == ["5.14.0", "5.14.0", "5.14.0"]
    assert [p.rewritable for p in pins] == [True, False, True]


def test_coherent(tmp_path):
    report = U.check_coherence(_repo(tmp_path))
    assert report.ok
    assert report.version == "5.14.0"
    assert U.assert_coherent(_repo(tmp_path)) == "5.14.0"


def test_drift_in_lock(tmp_path):
    repo = _repo(tmp_path, lock=_LOCK.replace("scoutsuite==5.14.0", "scoutsuite==5.13.0"))
    report = U.check_coherence(repo)
    assert not report.ok
    assert any("requirements.lock" in p and "5.13.0" in p for p in report.problems)
    with pytest.raises(UpgradeError, match="incoherent"):
        U.assert_coherent(repo)


def test_drift_in_constant(tmp_path):
    repo = _repo(tmp_path, integrity=_INTEGRITY.replace('"5.14.0"', '"5.12.0"'))
    assert not U.check_coherence(repo).ok


def test_missing_pin_in_extra(tmp_path):
    repo = _repo(tmp_path, pyproject="[project]\nname = 'x'\n")
    report = U.check_coherence(repo)
    assert not report.ok
    assert any("source of truth" in p for p in report.problems)


def test_authoritative_version_missing_raises(tmp_path):
    repo = _repo(tmp_path, pyproject="[project]\nname = 'x'\n")
    with pytest.raises(UpgradeError, match="no 'ScoutSuite=='"):
        U.authoritative_version(repo)


def test_find_root(tmp_path):
    repo = _repo(tmp_path)
    nested = repo / "src" / "presidio_scoutsuite"
    assert U.find_root(nested) == repo


def test_find_root_missing(tmp_path):
    with pytest.raises(UpgradeError, match="could not find pyproject"):
        U.find_root(tmp_path)


def test_read_missing_file(tmp_path):
    repo = _repo(tmp_path)
    (repo / "requirements.lock").unlink()
    with pytest.raises(UpgradeError, match="cannot read"):
        U.discover_pins(repo)


# --- planning ----------------------------------------------------------------


def test_plan(tmp_path):
    plan = U.plan_upgrade("5.15.0", root=_repo(tmp_path))
    assert plan.current == "5.14.0"
    assert plan.target == "5.15.0"
    kinds = [s.kind for s in plan.steps]
    assert kinds[:2] == ["edit", "edit"]
    assert "regenerate" in kinds and "verify" in kinds
    assert sum(s.automatable for s in plan.steps) == 2
    # lock regen command is surfaced verbatim
    assert any("pip-compile" in (s.command or "") for s in plan.steps)


def test_plan_to_dict_roundtrips(tmp_path):
    plan = U.plan_upgrade("5.15.0", root=_repo(tmp_path))
    d = plan.to_dict()
    assert d["current"] == "5.14.0"
    assert d["steps"][0]["automatable"] is True


def test_plan_rejects_downgrade(tmp_path):
    with pytest.raises(UpgradeError, match="not newer"):
        U.plan_upgrade("5.13.0", root=_repo(tmp_path))


def test_plan_rejects_same(tmp_path):
    with pytest.raises(UpgradeError, match="not newer"):
        U.plan_upgrade("5.14.0", root=_repo(tmp_path))


def test_plan_rejects_incoherent_base(tmp_path):
    repo = _repo(tmp_path, integrity=_INTEGRITY.replace('"5.14.0"', '"5.0.0"'))
    with pytest.raises(UpgradeError, match="incoherent"):
        U.plan_upgrade("6.0.0", root=repo)


# --- applying ----------------------------------------------------------------


def test_apply_text_pins(tmp_path):
    repo = _repo(tmp_path)
    changed = U.apply_text_pins("5.15.0", root=repo)
    assert {p.name for p in changed} == {"pyproject.toml", "scout_integrity.py"}
    pins = U.discover_pins(repo)
    by_name = {p.name: p.version for p in pins}
    assert by_name["scoutsuite extra (pyproject.toml)"] == "5.15.0"
    assert by_name["PINNED_SCOUTSUITE_VERSION (scout_integrity.py)"] == "5.15.0"
    # lock intentionally left stale -> now incoherent until regenerated
    assert by_name["requirements.lock"] == "5.14.0"
    assert not U.check_coherence(repo).ok


def test_apply_rejects_downgrade(tmp_path):
    with pytest.raises(UpgradeError, match="not newer"):
        U.apply_text_pins("5.13.0", root=_repo(tmp_path))


def test_apply_rejects_malformed_target(tmp_path):
    with pytest.raises(UpgradeError, match="malformed version"):
        U.apply_text_pins("nope", root=_repo(tmp_path))


# --- CLI ---------------------------------------------------------------------


def test_cli_check_ok(tmp_path, capsys):
    assert U._main(["--root", str(_repo(tmp_path)), "check"]) == 0
    assert "coherent" in capsys.readouterr().out


def test_cli_check_drift(tmp_path, capsys):
    repo = _repo(tmp_path, lock=_LOCK.replace("scoutsuite==5.14.0", "scoutsuite==5.0.0"))
    assert U._main(["--root", str(repo), "check"]) == 4
    assert "FAIL" in capsys.readouterr().err


def test_cli_current(tmp_path, capsys):
    assert U._main(["--root", str(_repo(tmp_path)), "current"]) == 0
    assert capsys.readouterr().out.strip() == "5.14.0"


def test_cli_plan_text(tmp_path, capsys):
    assert U._main(["--root", str(_repo(tmp_path)), "plan", "--to", "5.15.0"]) == 0
    out = capsys.readouterr().out
    assert "5.14.0 -> 5.15.0" in out
    assert "pip-compile" in out


def test_cli_plan_json(tmp_path, capsys):
    assert U._main(["--root", str(_repo(tmp_path)), "plan", "--to", "5.15.0", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["target"] == "5.15.0"


def test_cli_plan_bad_target(tmp_path, capsys):
    assert U._main(["--root", str(_repo(tmp_path)), "plan", "--to", "1.0.0"]) == 2
    assert "not newer" in capsys.readouterr().err


def test_cli_apply(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert U._main(["--root", str(repo), "apply", "--to", "5.15.0"]) == 0
    out = capsys.readouterr().out
    assert "edited" in out
    assert "pip-compile" in out
    assert U.authoritative_version(repo) == "5.15.0"


def test_cli_apply_incoherent(tmp_path, capsys):
    repo = _repo(tmp_path, lock=_LOCK.replace("scoutsuite==5.14.0", "scoutsuite==5.0.0"))
    assert U._main(["--root", str(repo), "apply", "--to", "6.0.0"]) == 2
    assert "incoherent" in capsys.readouterr().err


def test_real_repo_is_coherent():
    """The checked-in repository's own pins must agree."""
    report = U.check_coherence(U.find_root())
    assert report.ok, report.problems
