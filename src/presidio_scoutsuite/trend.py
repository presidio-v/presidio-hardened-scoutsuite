"""Track cloud-posture over time and gate on regression.

A single audit is a point in time; assurance is about the *trend*. This module
keeps an append-only history of run snapshots (one JSON object per line) and
compares the latest run against the previous one to surface **new** and
**resolved** findings and to gate a pipeline when posture *worsens* — a new
finding at or above a chosen severity.

Unlike :mod:`presidio_scoutsuite.diff` (which compares two report directories on
disk), the history persists across runs, so a scheduled audit can answer "did we
regress since last time?" without keeping every old report around. Pure stdlib,
deterministic (the clock is injectable), fail-closed (a run that can't be read is
never silently recorded as clean), and never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import PresidioScoutError, TrendError
from .findings import _RANK, LEVELS, load_report


def _finding_id(service: str, rule: str) -> str:
    return f"{service}/{rule[:-5] if rule.endswith('.json') else rule}"


@dataclass(frozen=True)
class Snapshot:
    """One recorded audit: when, what providers, counts, and finding identities."""

    at: str
    providers: tuple[str, ...]
    counts: dict[str, int]
    #: ``{finding-id: level}`` for every flagged finding (for new/resolved diffs).
    findings: dict[str, str] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.findings)

    def to_json(self) -> dict:
        return {
            "at": self.at,
            "providers": list(self.providers),
            "counts": self.counts,
            "findings": self.findings,
        }

    @classmethod
    def from_json(cls, obj: object) -> Snapshot:
        if not isinstance(obj, dict):
            raise TrendError("history record is not an object")
        try:
            findings = obj["findings"]
            counts = obj["counts"]
            if not isinstance(findings, dict) or not isinstance(counts, dict):
                raise TrendError("history record has malformed 'findings'/'counts'")
            return cls(
                at=str(obj["at"]),
                providers=tuple(obj.get("providers", [])),
                counts={str(k): int(v) for k, v in counts.items()},
                findings={str(k): str(v) for k, v in findings.items()},
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TrendError(f"malformed history record: {exc}") from exc


def snapshot(report_dir: str | Path, *, when: datetime | None = None) -> Snapshot:
    """Build a :class:`Snapshot` from a finished report (fail-closed if unreadable)."""

    report = load_report(report_dir)
    stamp = (
        (when or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    findings = {_finding_id(f.service, f.rule): f.level for f in report.findings}
    return Snapshot(stamp, tuple(report.providers), dict(report.counts), findings)


def load_history(store_path: str | Path) -> list[Snapshot]:
    """Read every snapshot from the JSONL store (``[]`` if it doesn't exist)."""

    path = Path(store_path)
    if not path.exists():
        return []
    out: list[Snapshot] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrendError(f"cannot read history store {path}: {exc}") from exc
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(Snapshot.from_json(json.loads(line)))
        except (ValueError, TrendError) as exc:
            raise TrendError(f"{path}:{i}: {exc}") from exc
    return out


def append(store_path: str | Path, snap: Snapshot) -> None:
    """Append a snapshot to the JSONL store (creating it if needed)."""

    path = Path(store_path)
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(snap.to_json(), sort_keys=True) + "\n")
    except OSError as exc:
        raise TrendError(f"cannot write history store {path}: {exc}") from exc


@dataclass
class Comparison:
    """Difference between a previous and a current snapshot."""

    previous: Snapshot | None
    current: Snapshot
    new: dict[str, str] = field(default_factory=dict)
    resolved: dict[str, str] = field(default_factory=dict)

    def new_at_or_above(self, level: str) -> dict[str, str]:
        threshold = _RANK.get(level.lower())
        if threshold is None:
            raise TrendError(f"unknown severity level {level!r}; expected one of {LEVELS}")
        return {fid: lvl for fid, lvl in self.new.items() if _RANK.get(lvl, 0) >= threshold}

    def regressed(self, level: str) -> bool:
        return bool(self.new_at_or_above(level))

    def to_json(self) -> dict:
        return {
            "previous_at": self.previous.at if self.previous else None,
            "current_at": self.current.at,
            "new": self.new,
            "resolved": self.resolved,
            "counts": self.current.counts,
        }


def compare(previous: Snapshot | None, current: Snapshot) -> Comparison:
    """New = flagged now but not before; resolved = flagged before but not now."""

    prev = previous.findings if previous else {}
    new = {fid: lvl for fid, lvl in current.findings.items() if fid not in prev}
    resolved = {fid: lvl for fid, lvl in prev.items() if fid not in current.findings}
    return Comparison(previous, current, new, resolved)


def record(
    report_dir: str | Path,
    store_path: str | Path,
    *,
    when: datetime | None = None,
) -> Comparison:
    """Snapshot a report, compare it to the previous record, then append it.

    Returns the comparison against the prior snapshot (the appended one becomes
    the new latest). Fail-closed via :func:`snapshot` / :func:`load_history`.
    """

    history = load_history(store_path)
    current = snapshot(report_dir, when=when)
    comparison = compare(history[-1] if history else None, current)
    append(store_path, current)
    return comparison


def _format_text(cmp: Comparison) -> str:
    counts = cmp.current.counts
    parts = ", ".join(f"{lvl}={counts.get(lvl, 0)}" for lvl in reversed(LEVELS))
    base = cmp.previous.at if cmp.previous else "none"
    lines = [
        f"posture @ {cmp.current.at} ({parts}); vs previous {base}: "
        f"+{len(cmp.new)} new, -{len(cmp.resolved)} resolved"
    ]
    for fid, lvl in sorted(cmp.new.items()):
        lines.append(f"  NEW      {lvl:<7} {fid}")
    for fid, lvl in sorted(cmp.resolved.items()):
        lines.append(f"  RESOLVED {lvl:<7} {fid}")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-trend",
        description=(
            "Track cloud posture across runs in an append-only history and gate on "
            "regression (new findings vs the previous run). Offline; no ScoutSuite."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="snapshot a report, compare to the last, append it")
    rec.add_argument("report_dir", help="path to a finished report directory")
    rec.add_argument("--store", required=True, metavar="PATH", help="JSONL history store")
    rec.add_argument(
        "--fail-on-regression",
        choices=LEVELS,
        help="exit non-zero (4) if a new finding at or above this level appeared",
    )
    rec.add_argument("--format", choices=("text", "json"), default="text")

    show = sub.add_parser("show", help="print the trend (latest vs previous)")
    show.add_argument("--store", required=True, metavar="PATH", help="JSONL history store")
    show.add_argument("--format", choices=("text", "json"), default="text")

    args = parser.parse_args(argv)

    try:
        if args.command == "record":
            cmp = record(args.report_dir, args.store)
        else:
            history = load_history(args.store)
            if not history:
                print(f"error: no history in {args.store}", file=sys.stderr)
                return 2
            previous = history[-2] if len(history) > 1 else None
            cmp = compare(previous, history[-1])
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(cmp.to_json(), indent=2, sort_keys=True))
    else:
        print(_format_text(cmp))

    if getattr(args, "fail_on_regression", None) and cmp.regressed(args.fail_on_regression):
        offending = cmp.new_at_or_above(args.fail_on_regression)
        print(
            f"FAIL posture regressed: {len(offending)} new finding(s) at or above "
            f"{args.fail_on_regression!r}",
            file=sys.stderr,
        )
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
