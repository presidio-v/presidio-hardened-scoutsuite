"""Diff two audit runs to surface drift — newly-introduced vs resolved findings.

A single audit is a snapshot; what a team usually wants to gate on is *change*:
"did this run introduce anything the last known-good run didn't have?" This
module compares two :class:`~presidio_scoutsuite.findings.FindingsReport`\\ s (or
two report directories) at **resource granularity** and classifies every
difference as:

* a **new finding** — a ``service/rule`` that wasn't flagged before at all;
* a **new resource** — an existing finding now flagging an additional resource
  (a regression within a known issue);
* a **resolved finding** — a ``service/rule`` no longer flagged;
* a **resolved resource** — fewer resources flagged on a still-open finding.

``presidio-scout-diff … --fail-on-new-finding danger`` exits non-zero (4) when
any *newly* flagged occurrence is at or above the chosen severity, so a pipeline
can block regressions while ignoring pre-existing, already-triaged findings.
Pure stdlib, deterministic, offline-testable.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PresidioScoutError
from .findings import LEVELS, FindingsReport, load_report

#: Threshold names accepted by the gate (``any`` = any severity).
THRESHOLDS: tuple[str, ...] = ("any", *LEVELS)
_RANK: dict[str, int] = {level: i for i, level in enumerate(LEVELS, start=1)}
_THRESHOLD_RANK: dict[str, int] = {"any": 0, **_RANK}


def _rank(level: str) -> int:
    return _RANK.get(level.lower(), 0)


@dataclass(frozen=True)
class FindingChange:
    """One added or removed finding occurrence.

    ``item`` is the specific flagged resource, or ``None`` for a count-only
    finding. ``whole_finding`` is true when the entire ``service/key`` crossed
    the boundary (a brand-new finding when added, fully resolved when removed),
    as opposed to a single resource changing on an otherwise-unchanged finding.
    """

    service: str
    key: str
    level: str
    item: str | None
    whole_finding: bool


def _occurrences(
    report: FindingsReport,
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], set[str | None]]]:
    levels: dict[tuple[str, str], str] = {}
    occ: dict[tuple[str, str], set[str | None]] = {}
    for finding in report.findings:
        key = (finding.service, finding.rule)
        levels[key] = finding.level
        items: set[str | None] = set(finding.items) if finding.items else {None}
        occ.setdefault(key, set()).update(items)
    return levels, occ


def _item_sort_key(item: str | None) -> tuple[bool, str]:
    return (item is not None, item or "")


@dataclass
class DiffResult:
    """Outcome of :func:`diff_reports`."""

    added: list[FindingChange] = field(default_factory=list)
    removed: list[FindingChange] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    @property
    def new_findings(self) -> list[tuple[str, str]]:
        """Distinct ``(service, key)`` that are entirely new."""

        return sorted({(c.service, c.key) for c in self.added if c.whole_finding})

    @property
    def resolved_findings(self) -> list[tuple[str, str]]:
        """Distinct ``(service, key)`` that are entirely resolved."""

        return sorted({(c.service, c.key) for c in self.removed if c.whole_finding})

    @property
    def new_resources(self) -> list[FindingChange]:
        """Added occurrences on findings that already existed (regressions)."""

        return [c for c in self.added if not c.whole_finding]

    def added_at_or_above(self, threshold: str) -> list[FindingChange]:
        """Added occurrences whose finding level is at or above ``threshold``."""

        rank = _THRESHOLD_RANK.get(threshold.lower())
        if rank is None:
            raise PresidioScoutError(
                f"unknown threshold {threshold!r}; expected one of {THRESHOLDS}"
            )
        return [c for c in self.added if _rank(c.level) >= rank]


def diff_reports(old: FindingsReport, new: FindingsReport) -> DiffResult:
    """Compare two findings reports (``old`` baseline vs ``new``)."""

    old_levels, old_occ = _occurrences(old)
    new_levels, new_occ = _occurrences(new)
    result = DiffResult(providers=sorted({*old.providers, *new.providers}))

    for key in old_occ.keys() | new_occ.keys():
        service, rule = key
        before = old_occ.get(key, set())
        after = new_occ.get(key, set())
        added_new_finding = key not in old_occ
        removed_whole = key not in new_occ
        level = new_levels.get(key) or old_levels.get(key) or ""

        for item in sorted(after - before, key=_item_sort_key):
            result.added.append(FindingChange(service, rule, level, item, added_new_finding))
        for item in sorted(before - after, key=_item_sort_key):
            result.removed.append(
                FindingChange(service, rule, old_levels.get(key, level), item, removed_whole)
            )
    return result


def load_and_diff(old_dir: str | Path, new_dir: str | Path) -> DiffResult:
    """Load two report directories and diff their findings."""

    return diff_reports(load_report(old_dir), load_report(new_dir))


def summarize(result: DiffResult) -> str:
    resolved_resources = sum(1 for c in result.removed if not c.whole_finding)
    return (
        f"drift: +{len(result.new_findings)} new finding(s), "
        f"+{len(result.new_resources)} new resource(s); "
        f"-{len(result.resolved_findings)} resolved finding(s), "
        f"-{resolved_resources} resolved resource(s)"
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-diff",
        description=(
            "Diff two ScoutSuite report directories (baseline vs new) and surface "
            "drift — new vs resolved findings. Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("baseline", help="path to the baseline (older) report directory")
    parser.add_argument("current", help="path to the current (newer) report directory")
    parser.add_argument(
        "--fail-on-new-finding",
        choices=THRESHOLDS,
        help="exit non-zero (4) if a newly flagged finding/resource is at or above "
        "this severity (any|warning|danger)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)

    try:
        result = load_and_diff(args.baseline, args.current)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(
            json.dumps(
                {
                    "providers": result.providers,
                    "newFindings": [f"{s}/{k}" for s, k in result.new_findings],
                    "resolvedFindings": [f"{s}/{k}" for s, k in result.resolved_findings],
                    "added": [
                        {
                            "service": c.service,
                            "key": c.key,
                            "level": c.level,
                            "item": c.item,
                            "wholeFinding": c.whole_finding,
                        }
                        for c in result.added
                    ],
                    "removed": [
                        {
                            "service": c.service,
                            "key": c.key,
                            "level": c.level,
                            "item": c.item,
                            "wholeFinding": c.whole_finding,
                        }
                        for c in result.removed
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(summarize(result))
        for service, key in result.new_findings:
            print(f"  + NEW      {service}/{key}", file=sys.stderr)
        for change in result.new_resources:
            print(f"  + resource {change.service}/{change.key} :: {change.item}", file=sys.stderr)

    if args.fail_on_new_finding:
        offending = result.added_at_or_above(args.fail_on_new_finding)
        if offending:
            print(
                f"FAIL {len(offending)} newly flagged occurrence(s) at or above "
                f"{args.fail_on_new_finding!r}",
                file=sys.stderr,
            )
            return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
