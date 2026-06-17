"""Executive & multi-format reporting over a ScoutSuite report (or a fleet).

The raw ScoutSuite HTML report is for an engineer mid-investigation; a security
lead or auditor wants a one-page rollup. This module builds a compact summary
(providers, per-level counts, top findings, failing-control counts per framework)
from a finished report — or aggregates many reports from a fleet run — and renders
it as **Markdown**, a **self-contained HTML** page, or **CSV**.

The HTML is deliberately self-contained (inline styles, no remote/inline scripts)
and **HTML-escapes every dynamic value**, because finding strings can echo
attacker-influenced resource names/tags — the same untrusted-output stance the
report guard takes. Pure stdlib, deterministic, offline-testable; never imports
ScoutSuite.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import sys
from pathlib import Path

from . import compliance
from .errors import PresidioScoutError
from .findings import _RANK, LEVELS, FindingsReport, find_results_files, load_report
from .version import __version__


def _rule(rule: str) -> str:
    return rule[:-5] if rule.endswith(".json") else rule


def build(report_dir: str | Path, *, top: int = 20) -> dict:
    """Build an executive summary dict from a finished report (fail-closed)."""

    report = load_report(report_dir)
    return _summarize(report, top=top)


def _summarize(report: FindingsReport, *, top: int) -> dict:
    ranked = sorted(report.findings, key=lambda f: (-_RANK.get(f.level, 0), f.service, f.rule))
    comp = compliance.build_report(report)
    return {
        "tool_version": __version__,
        "providers": list(report.providers),
        "totals": report.counts,
        "total_flagged": len(report.findings),
        "compliance": {fw: comp.control_count(fw) for fw in comp.frameworks},
        "top": [
            {
                "level": f.level,
                "service": f.service,
                "rule": _rule(f.rule),
                "flagged_items": f.flagged_items,
                "description": f.description,
            }
            for f in ranked[: max(0, top)]
        ],
    }


def discover_fleet(base_dir: str | Path) -> dict[str, Path]:
    """Find per-target report sub-directories under ``base_dir`` (orchestrate layout)."""

    base = Path(base_dir)
    out: dict[str, Path] = {}
    if not base.is_dir():
        return out
    for child in sorted(base.iterdir()):
        if child.is_dir() and find_results_files(child):
            out[child.name] = child
    return out


def build_fleet(targets: dict[str, Path], *, top: int = 10) -> dict:
    """Aggregate per-target summaries into one fleet rollup (fail-closed per target)."""

    rows = []
    totals = {level: 0 for level in LEVELS}
    total_flagged = 0
    for name, path in targets.items():
        summary = build(path, top=top)
        rows.append({"name": name, **summary})
        for level in LEVELS:
            totals[level] += summary["totals"].get(level, 0)
        total_flagged += summary["total_flagged"]
    return {
        "tool_version": __version__,
        "target_count": len(rows),
        "totals": totals,
        "total_flagged": total_flagged,
        "targets": rows,
    }


# --- renderers ---------------------------------------------------------------


def render_markdown(summary: dict) -> str:
    providers = ", ".join(summary.get("providers") or ["unknown"])
    totals = summary.get("totals", {})
    parts = ", ".join(f"{lvl}={totals.get(lvl, 0)}" for lvl in reversed(LEVELS))
    lines = [
        "# Cloud audit summary",
        "",
        f"- **Providers:** {providers}",
        f"- **Flagged findings:** {summary.get('total_flagged', 0)} ({parts})",
    ]
    comp = summary.get("compliance") or {}
    if comp:
        c = ", ".join(f"{fw}={n}" for fw, n in comp.items())
        lines.append(f"- **Failing controls:** {c}")
    top = summary.get("top") or []
    if top:
        lines += ["", "## Top findings", "", "| Severity | Resource | Flagged |", "|---|---|---|"]
        for f in top:
            lines.append(f"| {f['level']} | {f['service']}/{f['rule']} | {f['flagged_items']} |")
    return "\n".join(lines) + "\n"


_HTML_STYLE = (
    "body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}"
    "table{border-collapse:collapse;margin-top:1rem}"
    "th,td{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}"
    ".danger{color:#b00020;font-weight:bold}.warning{color:#a06000}"
)


def render_html(summary: dict) -> str:
    """Self-contained HTML; every dynamic value is HTML-escaped."""

    def esc(value: object) -> str:
        return html.escape(str(value))

    providers = esc(", ".join(summary.get("providers") or ["unknown"]))
    totals = summary.get("totals", {})
    parts = esc(", ".join(f"{lvl}={totals.get(lvl, 0)}" for lvl in reversed(LEVELS)))
    rows = []
    for f in summary.get("top") or []:
        lvl = esc(f["level"])
        cls = lvl if lvl in LEVELS else ""
        rows.append(
            f"<tr><td class='{cls}'>{lvl}</td>"
            f"<td>{esc(f['service'])}/{esc(f['rule'])}</td>"
            f"<td>{esc(f['flagged_items'])}</td></tr>"
        )
    table = (
        "<table><tr><th>Severity</th><th>Resource</th><th>Flagged</th></tr>"
        + "".join(rows)
        + "</table>"
        if rows
        else "<p>No flagged findings.</p>"
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Cloud audit summary</title>"
        f"<style>{_HTML_STYLE}</style></head><body>"
        "<h1>Cloud audit summary</h1>"
        f"<p><b>Providers:</b> {providers}</p>"
        f"<p><b>Flagged findings:</b> {esc(summary.get('total_flagged', 0))} ({parts})</p>"
        f"{table}</body></html>\n"
    )


def render_csv(report_dir: str | Path) -> str:
    """One CSV row per flagged finding (service, rule, level, flagged_items, description)."""

    report = load_report(report_dir)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["service", "rule", "level", "flagged_items", "description"])
    for f in sorted(report.findings, key=lambda f: (-_RANK.get(f.level, 0), f.service, f.rule)):
        writer.writerow([f.service, _rule(f.rule), f.level, f.flagged_items, f.description])
    return buf.getvalue()


def render_fleet_markdown(fleet: dict) -> str:
    totals = fleet.get("totals", {})
    parts = ", ".join(f"{lvl}={totals.get(lvl, 0)}" for lvl in reversed(LEVELS))
    lines = [
        "# Fleet audit summary",
        "",
        f"- **Targets:** {fleet.get('target_count', 0)}",
        f"- **Flagged findings (all targets):** {fleet.get('total_flagged', 0)} ({parts})",
        "",
        "| Target | Providers | Flagged | danger | warning |",
        "|---|---|---|---|---|",
    ]
    for t in fleet.get("targets", []):
        tt = t.get("totals", {})
        provs = ", ".join(t.get("providers") or [])
        lines.append(
            f"| {t['name']} | {provs} | {t['total_flagged']} | "
            f"{tt.get('danger', 0)} | {tt.get('warning', 0)} |"
        )
    return "\n".join(lines) + "\n"


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-summary",
        description=(
            "Render an executive summary of a ScoutSuite report (or a fleet of "
            "reports) as Markdown, self-contained HTML, CSV, or JSON. Offline."
        ),
    )
    parser.add_argument("path", help="a report directory, or a fleet base dir with --fleet")
    parser.add_argument(
        "--fleet",
        action="store_true",
        help="treat PATH as a base dir of per-target report subdirs and roll up",
    )
    parser.add_argument(
        "--format", choices=("md", "html", "csv", "json"), default="md", help="output format"
    )
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    try:
        if args.fleet:
            targets = discover_fleet(args.path)
            if not targets:
                print(f"error: no per-target reports found under {args.path}", file=sys.stderr)
                return 2
            fleet = build_fleet(targets)
            if args.format == "json":
                _write(json.dumps(fleet, indent=2, sort_keys=True) + "\n", args.output)
            else:
                # CSV/HTML fleet fall back to the Markdown rollup table.
                _write(render_fleet_markdown(fleet), args.output)
            return 0

        if args.format == "csv":
            _write(render_csv(args.path), args.output)
            return 0
        summary = build(args.path)
        if args.format == "json":
            text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        elif args.format == "html":
            text = render_html(summary)
        else:
            text = render_markdown(summary)
        _write(text, args.output)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
