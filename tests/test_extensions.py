from __future__ import annotations

import re

import pytest

from presidio_scoutsuite import extensions as E
from presidio_scoutsuite.errors import ExtensionError

# --- load_object -------------------------------------------------------------


def test_load_object_ok():
    obj = E.load_object("presidio_scoutsuite.version:__version__")
    assert isinstance(obj, str)


def test_load_object_bad_ref():
    for ref in ["nocolon", "a:b:c", "mod:", ":attr"]:
        with pytest.raises(ExtensionError, match="module:attr"):
            E.load_object(ref)


def test_load_object_bad_module():
    with pytest.raises(ExtensionError, match="cannot import"):
        E.load_object("presidio_scoutsuite.does_not_exist:x")


def test_load_object_bad_attr():
    with pytest.raises(ExtensionError, match="has no attribute"):
        E.load_object("presidio_scoutsuite.version:nope")


# --- discover (entry points monkeypatched) -----------------------------------


class _EP:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


def _patch_eps(monkeypatch, mapping):
    def fake(group):
        return mapping.get(group, [])

    monkeypatch.setattr(E, "_entry_points", fake)


def test_discover_unknown_group():
    with pytest.raises(ExtensionError, match="unknown extension group"):
        E.discover("bogus.group")


def test_discover_loads(monkeypatch):
    sentinel = object()
    _patch_eps(monkeypatch, {E.EXPORTER_GROUP: [_EP("x", lambda: sentinel)]})
    assert E.discover(E.EXPORTER_GROUP) == {"x": sentinel}


def test_discover_failing_plugin_fails_closed(monkeypatch):
    def boom():
        raise RuntimeError("broken")

    _patch_eps(monkeypatch, {E.REDACTOR_GROUP: [_EP("bad", boom)]})
    with pytest.raises(ExtensionError, match="failed to load extension 'bad'"):
        E.discover(E.REDACTOR_GROUP)


# --- redactor_patterns -------------------------------------------------------


class _Redactor:
    def __init__(self, pats):
        self._pats = pats

    def patterns(self):
        return self._pats


def test_redactor_patterns_string_and_compiled():
    reds = {
        "a": _Redactor([("tok", "INT-[0-9]{4}")]),
        "b": _Redactor([("c", re.compile("X+"))]),
    }
    pats = E.redactor_patterns(reds)
    assert {n for n, _ in pats} == {"tok", "c"}
    assert all(isinstance(p, re.Pattern) for _, p in pats)


def test_redactor_patterns_bad_shapes():
    with pytest.raises(ExtensionError, match="must return a list"):
        E.redactor_patterns({"a": _Redactor("nope")})
    with pytest.raises(ExtensionError, match="\\(name, pattern\\) pair"):
        E.redactor_patterns({"a": _Redactor([("only",)])})
    with pytest.raises(ExtensionError, match="name must be"):
        E.redactor_patterns({"a": _Redactor([("", "x")])})
    with pytest.raises(ExtensionError, match="invalid regex"):
        E.redactor_patterns({"a": _Redactor([("n", "(")])})
    with pytest.raises(ExtensionError, match="regex string or compiled"):
        E.redactor_patterns({"a": _Redactor([("n", 5)])})


def test_redactor_patterns_no_callable():
    with pytest.raises(ExtensionError, match="no callable patterns"):
        E.redactor_patterns({"a": object()})


def test_installed_redactor_patterns_empty(monkeypatch):
    _patch_eps(monkeypatch, {})
    assert E.installed_redactor_patterns() == []


# --- CLI ---------------------------------------------------------------------


def test_cli_list(monkeypatch, capsys):
    _patch_eps(monkeypatch, {E.REDACTOR_GROUP: [_EP("myred", lambda: object())]})
    assert E._main(["list"]) == 0
    out = capsys.readouterr().out
    assert "redactors: myred" in out
    assert "exporters: (none)" in out


def test_cli_list_failing(monkeypatch, capsys):
    def boom():
        raise RuntimeError("x")

    _patch_eps(monkeypatch, {E.SINK_GROUP: [_EP("bad", boom)]})
    assert E._main(["list"]) == 2
    assert "error:" in capsys.readouterr().err
