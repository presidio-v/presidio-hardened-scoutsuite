from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from presidio_scoutsuite import trend as T
from presidio_scoutsuite.errors import TrendError

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_T1 = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _report(tmp_path, name, findings):
    d = tmp_path / name
    sub = d / "scoutsuite-results"
    sub.mkdir(parents=True)
    svc = {"s3": {"findings": findings}}
    (sub / "scoutsuite_results.js").write_text(
        "scoutsuite_results =\n" + json.dumps({"provider_code": "aws", "services": svc})
    )
    return d


# --- snapshot ----------------------------------------------------------------


def test_snapshot(tmp_path):
    r = _report(tmp_path, "r1", {"world.json": {"level": "danger", "flagged_items": 2}})
    snap = T.snapshot(r, when=_T0)
    assert snap.at == "2026-01-01T00:00:00Z"
    assert snap.providers == ("aws",)
    assert snap.findings == {"s3/world": "danger"}
    assert snap.counts["danger"] == 1


def test_snapshot_fails_closed(tmp_path):
    from presidio_scoutsuite.errors import FindingsError

    with pytest.raises(FindingsError):
        T.snapshot(tmp_path / "nope")


# --- append / load -----------------------------------------------------------


def test_append_and_load(tmp_path):
    store = tmp_path / "h.jsonl"
    assert T.load_history(store) == []
    r = _report(tmp_path, "r1", {"world.json": {"level": "danger", "flagged_items": 1}})
    T.append(store, T.snapshot(r, when=_T0))
    T.append(store, T.snapshot(r, when=_T1))
    history = T.load_history(store)
    assert [s.at for s in history] == ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"]


def test_load_malformed(tmp_path):
    store = tmp_path / "h.jsonl"
    store.write_text('{"at":"x","counts":{},"findings":{}}\nnot json\n')
    with pytest.raises(TrendError, match="h.jsonl:2"):
        T.load_history(store)


def test_load_malformed_record(tmp_path):
    store = tmp_path / "h.jsonl"
    store.write_text('{"at":"x"}\n')  # missing findings/counts
    with pytest.raises(TrendError):
        T.load_history(store)


# --- compare -----------------------------------------------------------------


def test_compare_new_and_resolved():
    prev = T.Snapshot("t0", ("aws",), {"danger": 1}, {"s3/a": "danger", "s3/b": "warning"})
    cur = T.Snapshot("t1", ("aws",), {"danger": 1}, {"s3/a": "danger", "s3/c": "danger"})
    cmp = T.compare(prev, cur)
    assert cmp.new == {"s3/c": "danger"}
    assert cmp.resolved == {"s3/b": "warning"}


def test_compare_no_previous():
    cur = T.Snapshot("t1", ("aws",), {}, {"s3/a": "danger"})
    cmp = T.compare(None, cur)
    assert cmp.new == {"s3/a": "danger"}
    assert cmp.resolved == {}


def test_regression_gate():
    prev = T.Snapshot("t0", (), {}, {"s3/a": "warning"})
    cur = T.Snapshot("t1", (), {}, {"s3/a": "warning", "s3/b": "danger", "s3/c": "warning"})
    cmp = T.compare(prev, cur)
    assert cmp.regressed("danger") is True
    assert set(cmp.new_at_or_above("warning")) == {"s3/b", "s3/c"}
    assert set(cmp.new_at_or_above("danger")) == {"s3/b"}


def test_regression_bad_level():
    cmp = T.compare(None, T.Snapshot("t", (), {}, {}))
    with pytest.raises(TrendError, match="unknown severity"):
        cmp.new_at_or_above("nope")


# --- record ------------------------------------------------------------------


def test_record_appends_and_compares(tmp_path):
    store = tmp_path / "h.jsonl"
    r1 = _report(tmp_path, "r1", {"a.json": {"level": "danger", "flagged_items": 1}})
    cmp1 = T.record(r1, store, when=_T0)
    assert cmp1.previous is None
    assert set(cmp1.new) == {"s3/a"}
    r2 = _report(
        tmp_path,
        "r2",
        {
            "a.json": {"level": "danger", "flagged_items": 1},
            "b.json": {"level": "danger", "flagged_items": 1},
        },
    )
    cmp2 = T.record(r2, store, when=_T1)
    assert cmp2.previous.at == "2026-01-01T00:00:00Z"
    assert set(cmp2.new) == {"s3/b"}
    assert len(T.load_history(store)) == 2


# --- CLI ---------------------------------------------------------------------


def test_cli_record_and_gate(tmp_path, capsys):
    store = tmp_path / "h.jsonl"
    r1 = _report(tmp_path, "r1", {"a.json": {"level": "warning", "flagged_items": 1}})
    assert T._main(["record", str(r1), "--store", str(store)]) == 0
    # second run introduces a new danger -> regression gate trips
    r2 = _report(
        tmp_path,
        "r2",
        {
            "a.json": {"level": "warning", "flagged_items": 1},
            "b.json": {"level": "danger", "flagged_items": 1},
        },
    )
    rc = T._main(["record", str(r2), "--store", str(store), "--fail-on-regression", "danger"])
    assert rc == 4
    assert "posture regressed" in capsys.readouterr().err


def test_cli_record_no_regression(tmp_path, capsys):
    store = tmp_path / "h.jsonl"
    r1 = _report(tmp_path, "r1", {"a.json": {"level": "danger", "flagged_items": 1}})
    T._main(["record", str(r1), "--store", str(store)])
    rc = T._main(["record", str(r1), "--store", str(store), "--fail-on-regression", "danger"])
    assert rc == 0


def test_cli_show(tmp_path, capsys):
    store = tmp_path / "h.jsonl"
    r1 = _report(tmp_path, "r1", {"a.json": {"level": "danger", "flagged_items": 1}})
    T._main(["record", str(r1), "--store", str(store)])
    capsys.readouterr()  # discard the record output
    assert T._main(["show", "--store", str(store), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert "current_at" in doc


def test_cli_show_empty(tmp_path, capsys):
    assert T._main(["show", "--store", str(tmp_path / "none.jsonl")]) == 2
    assert "no history" in capsys.readouterr().err


def test_cli_record_bad_report(tmp_path, capsys):
    assert T._main(["record", str(tmp_path / "x"), "--store", str(tmp_path / "h")]) == 2
