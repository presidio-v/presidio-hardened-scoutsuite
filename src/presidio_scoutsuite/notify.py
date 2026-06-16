"""Push a fail-closed summary of an audit to a notification sink.

A gate result is only useful if someone sees it. This module turns a finished
report into a compact summary and delivers it to a sink — a local file, a generic
JSON webhook, or a Slack incoming webhook — so a pipeline can route audit results
to where the team already looks.

Two properties matter for a security tool that talks to *external* services:

* **Redaction-aware, fail-closed.** Whatever is about to leave the process is run
  through the same secret scanner the report redaction uses
  (:func:`redact.assert_clean`); if a secret-like string survives into the
  outgoing payload (e.g. echoed in a resource name), delivery is **refused**
  rather than leaking it to Slack/a webhook.
* **No new dependencies.** Webhooks use stdlib ``urllib``; the transport is
  injectable so the module is fully offline-testable without a network.

Driven by flags or by a ``[sinks.<name>]`` table in ``.presidio-scout.toml`` so a
team can wire a standard destination once. Never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import redact
from .errors import NotificationError, PresidioScoutError
from .findings import _RANK, LEVELS, load_report
from .version import __version__

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

SINK_TYPES: tuple[str, ...] = ("file", "webhook", "slack")
_DEFAULT_TOP = 10


def build_summary(report_dir: str | Path, *, top: int = _DEFAULT_TOP) -> dict:
    """Summarize a finished report: provider(s), per-level counts, top findings.

    Fail-closed via :func:`findings.load_report` (raises if no results), so a
    notification can't be sent for a report that was never evaluated.
    """

    report = load_report(report_dir)
    ranked = sorted(
        report.findings,
        key=lambda f: (-_RANK.get(f.level, 0), f.service, f.rule),
    )
    return {
        "tool": "presidio-hardened-scoutsuite",
        "tool_version": __version__,
        "providers": report.providers,
        "totals": report.counts,
        "total_flagged": len(report.findings),
        "top": [
            {
                "level": f.level,
                "service": f.service,
                "rule": f.rule[:-5] if f.rule.endswith(".json") else f.rule,
                "flagged_items": f.flagged_items,
            }
            for f in ranked[: max(0, top)]
        ],
    }


def render_json(summary: dict) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)


def render_text(summary: dict) -> str:
    """Render a compact Markdown/Slack-friendly summary."""

    providers = ", ".join(summary.get("providers") or ["unknown"])
    totals = summary.get("totals", {})
    parts = ", ".join(f"{lvl}={totals.get(lvl, 0)}" for lvl in reversed(LEVELS))
    lines = [
        f"*Presidio ScoutSuite audit* — {providers}",
        f"Flagged findings: {summary.get('total_flagged', 0)} ({parts})",
    ]
    top = summary.get("top") or []
    if top:
        lines.append("Top findings:")
        lines.extend(
            f"• {f['level']} {f['service']}/{f['rule']} ({f['flagged_items']} flagged)" for f in top
        )
    return "\n".join(lines)


def resolve_sink(config_path: str | Path, name: str) -> dict:
    """Resolve a named ``[sinks.<name>]`` table from a TOML config.

    Fail-closed: a missing/malformed config, an absent sink, or one without a
    valid ``type`` raises :class:`NotificationError`.
    """

    p = Path(config_path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise NotificationError(f"cannot read config {p}: {exc}") from exc
    sinks = data.get("sinks")
    if not isinstance(sinks, dict) or name not in sinks:
        raise NotificationError(f"{p}: no [sinks.{name}] table")
    sink = sinks[name]
    if not isinstance(sink, dict) or sink.get("type") not in SINK_TYPES:
        raise NotificationError(f"{p}: [sinks.{name}] needs a 'type' of {', '.join(SINK_TYPES)}")
    return sink


def _http_post(url: str, data: bytes) -> int:
    """POST ``data`` as JSON; return the HTTP status. Stdlib only."""

    request = urllib.request.Request(  # noqa: S310 - scheme checked below
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    if request.type not in ("http", "https"):
        raise NotificationError(f"refusing non-HTTP(S) webhook url scheme: {request.type!r}")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError as exc:
        raise NotificationError(f"webhook delivery to {url} failed: {exc.reason}") from exc


def deliver(
    *,
    sink_type: str,
    text: str,
    url: str | None = None,
    path: str | None = None,
    sender=None,
) -> str:
    """Deliver ``text`` to a sink, fail-closed and redaction-guarded.

    The payload is scanned for secrets first; if any survive, delivery is refused
    (a secret must never be pushed to an external sink). Returns a short status
    string; raises :class:`NotificationError` / :class:`RedactionError` otherwise.
    """

    redact.assert_clean(text, where=f"{sink_type} notification")
    if sender is None:
        sender = _http_post
    if sink_type == "file":
        if not path:
            raise NotificationError("file sink requires a path")
        Path(path).write_text(text, encoding="utf-8")
        return f"wrote notification to {path}"
    if sink_type in ("webhook", "slack"):
        if not url:
            raise NotificationError(f"{sink_type} sink requires a url")
        status = sender(url, text.encode("utf-8"))
        if not (200 <= status < 300):
            raise NotificationError(f"{sink_type} POST to {url} returned HTTP {status}")
        return f"posted notification to {sink_type} (HTTP {status})"
    raise NotificationError(f"unknown sink type {sink_type!r}; expected {', '.join(SINK_TYPES)}")


def _payload_for(sink_type: str, summary: dict, fmt: str) -> str:
    """Pick the wire format for a sink: Slack→text block; file honours --format."""

    if sink_type == "slack":
        return json.dumps({"text": render_text(summary)})
    if sink_type == "file" and fmt == "text":
        return render_text(summary)
    return render_json(summary)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-notify",
        description=(
            "Summarize a ScoutSuite report and push it to a sink (file / webhook / "
            "Slack), fail-closed and redaction-guarded. Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument("--sink", choices=SINK_TYPES, help="sink type")
    parser.add_argument(
        "--sink-name",
        help="resolve a [sinks.<name>] table from --config instead of --sink",
    )
    parser.add_argument("--config", metavar="PATH", help="TOML config for --sink-name")
    parser.add_argument("--url", help="destination URL (webhook/slack)")
    parser.add_argument("--path", help="destination file (file sink)")
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="payload format for the file sink (default: json)",
    )
    parser.add_argument(
        "--only-if",
        choices=LEVELS,
        help="only send if a flagged finding is at or above this level",
    )
    parser.add_argument(
        "--top", type=int, default=_DEFAULT_TOP, help="how many top findings to include"
    )
    args = parser.parse_args(argv)

    try:
        sink_type = args.sink
        url, path = args.url, args.path
        if args.sink_name:
            if not args.config:
                raise NotificationError("--sink-name requires --config")
            sink = resolve_sink(args.config, args.sink_name)
            sink_type = sink["type"]
            url = url or sink.get("url")
            path = path or sink.get("path")
        if not sink_type:
            raise NotificationError("a sink is required (--sink or --sink-name)")

        summary = build_summary(args.report_dir, top=args.top)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.only_if:
        threshold = _RANK[args.only_if]
        if not any(
            _RANK.get(lvl, 0) >= threshold and n > 0 for lvl, n in summary["totals"].items()
        ):
            print(
                f"no findings at or above {args.only_if!r}; not sending notification",
                file=sys.stderr,
            )
            return 0

    try:
        text = _payload_for(sink_type, summary, args.format)
        status = deliver(sink_type=sink_type, text=text, url=url, path=path)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(status)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
