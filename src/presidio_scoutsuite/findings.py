"""Parse ScoutSuite's results data into a findings model and gate on severity.

ScoutSuite writes its machine-readable results next to the HTML report as a
JavaScript file, ``scoutsuite_results*.js``, of the form::

    scoutsuite_results =
    { "provider_code": "aws", "services": { "<svc>": { "findings": {
        "<rule-filename>": { "level": "danger", "flagged_items": 3,
                             "description": "...", "checked_items": 120, ... } } } } }

We read that data **off disk** (it's data, not ScoutSuite code — the wrapper
still never imports ScoutSuite), strip the ``scoutsuite_results =`` JS wrapper,
and turn the flagged findings into a deterministic model. A finding "fires" only
when ``flagged_items > 0``; its ``level`` is ``warning`` or ``danger``.

This powers a CI gate: ``presidio-scout --fail-on-finding danger`` (or the
standalone ``presidio-scout-findings``) exits non-zero when any flagged finding
is at or above the chosen severity, so an audit can block a pipeline. Pure
stdlib, deterministic, offline-testable.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import FindingsError

#: Severity levels in ascending order; rank used for threshold comparisons.
LEVELS: tuple[str, ...] = ("warning", "danger")
_RANK: dict[str, int] = {level: i for i, level in enumerate(LEVELS, start=1)}

#: Glob for the results data file(s) ScoutSuite writes under the report dir.
_RESULTS_GLOB = "scoutsuite_results*.js"


def _rank(level: str) -> int:
    return _RANK.get(level.lower(), 0)


@dataclass(frozen=True)
class Finding:
    """A single ScoutSuite finding that flagged at least one resource."""

    service: str
    key: str
    level: str
    flagged_items: int
    description: str = ""
    checked_items: int | None = None
    items: tuple[str, ...] = ()


def _parse_results_js(text: str) -> dict:
    """Decode the JSON object embedded in a ``scoutsuite_results*.js`` file."""

    start = text.find("{")
    if start == -1:
        raise FindingsError("results file contains no JSON object")
    try:
        # Anchoring at the first '{' guarantees a JSON object (dict) or a decode
        # error — no need to re-check the type.
        obj, _ = json.JSONDecoder().raw_decode(text, start)
    except ValueError as exc:
        raise FindingsError(f"could not decode results JSON: {exc}") from exc
    return obj


def find_results_files(report_dir: str | Path) -> list[Path]:
    """Return the ScoutSuite results data files under ``report_dir`` (sorted)."""

    root = Path(report_dir)
    return sorted(
        p for p in root.rglob(_RESULTS_GLOB) if p.is_file() and "exceptions" not in p.name.lower()
    )


def extract_findings(results: dict) -> list[Finding]:
    """Flatten a parsed results object into the list of *flagged* findings."""

    out: list[Finding] = []
    services = results.get("services")
    if not isinstance(services, dict):
        return out
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        findings = service.get("findings")
        if not isinstance(findings, dict):
            continue
        for key, finding in findings.items():
            if not isinstance(finding, dict):
                continue
            try:
                flagged = int(finding.get("flagged_items", 0) or 0)
            except (TypeError, ValueError):
                flagged = 0
            if flagged <= 0:
                continue
            checked = finding.get("checked_items")
            raw_items = finding.get("items")
            items = tuple(str(i) for i in raw_items) if isinstance(raw_items, list) else ()
            out.append(
                Finding(
                    service=str(service_name),
                    key=str(key),
                    level=str(finding.get("level", "")).lower(),
                    flagged_items=flagged,
                    description=str(finding.get("description", "")),
                    checked_items=int(checked) if isinstance(checked, (int, float)) else None,
                    items=items,
                )
            )
    return out


@dataclass
class FindingsReport:
    """The flagged findings from one or more results files, plus a summary."""

    findings: list[Finding] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        """Number of flagged findings per level (known levels only)."""

        counts = {level: 0 for level in LEVELS}
        for finding in self.findings:
            if finding.level in counts:
                counts[finding.level] += 1
        return counts

    def at_or_above(self, level: str) -> list[Finding]:
        """Flagged findings whose level is at or above ``level``."""

        threshold = _RANK.get(level.lower())
        if threshold is None:
            raise FindingsError(f"unknown severity level {level!r}; expected one of {LEVELS}")
        return [f for f in self.findings if _rank(f.level) >= threshold]

    def exceeds(self, level: str) -> bool:
        return bool(self.at_or_above(level))


def load_report(report_dir: str | Path) -> FindingsReport:
    """Build a :class:`FindingsReport` from the results data under ``report_dir``.

    Raises :class:`FindingsError` if no results file is present, so a gate can't
    pass on a report it never evaluated.
    """

    files = find_results_files(report_dir)
    if not files:
        raise FindingsError(
            f"no ScoutSuite results data ({_RESULTS_GLOB}) found under {report_dir}"
        )
    report = FindingsReport()
    for path in files:
        results = _parse_results_js(path.read_text(encoding="utf-8", errors="replace"))
        provider = results.get("provider_code")
        if isinstance(provider, str) and provider and provider not in report.providers:
            report.providers.append(provider)
        report.findings.extend(extract_findings(results))
    return report


def _format_text(report: FindingsReport) -> str:
    counts = report.counts
    provider = ", ".join(report.providers) or "unknown"
    parts = ", ".join(f"{level}={counts[level]}" for level in reversed(LEVELS))
    return f"findings [{provider}]: {len(report.findings)} flagged ({parts})"


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-findings",
        description=(
            "Summarize the flagged findings in a ScoutSuite report and optionally "
            "gate on severity. Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument(
        "--fail-on",
        choices=LEVELS,
        help="exit non-zero (4) if any flagged finding is at or above this level",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)

    try:
        report = load_report(args.report_dir)
    except FindingsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = {
            "providers": report.providers,
            "counts": report.counts,
            "total_flagged": len(report.findings),
            "findings": [
                {
                    "service": f.service,
                    "key": f.key,
                    "level": f.level,
                    "flagged_items": f.flagged_items,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_text(report))

    if args.fail_on and report.exceeds(args.fail_on):
        offending = report.at_or_above(args.fail_on)
        print(
            f"FAIL {len(offending)} finding(s) at or above {args.fail_on!r}:",
            file=sys.stderr,
        )
        for finding in sorted(offending, key=lambda f: (-_rank(f.level), f.service, f.key)):
            print(
                f"  {finding.level:<7} {finding.service}/{finding.key} "
                f"({finding.flagged_items} flagged)",
                file=sys.stderr,
            )
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
