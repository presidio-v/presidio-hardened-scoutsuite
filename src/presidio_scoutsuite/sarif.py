"""Convert a ScoutSuite findings model into SARIF 2.1.0 for GitHub code scanning.

SARIF is the JSON format GitHub's code-scanning API ingests. Exporting the
audit's flagged findings as SARIF lets cloud-misconfiguration findings show up
as code-scanning **alerts** — tracked, deduplicated, and triageable in the
Security tab — uploaded with ``github/codeql-action/upload-sarif`` (see README).

Mapping (documented so it's auditable, not magic):

* **rule id** — ``<service>/<finding-key without .json>`` (stable, unique).
* **level** — ScoutSuite ``danger`` -> SARIF ``error``; ``warning`` -> ``warning``.
* **security-severity** — ``danger`` -> ``8.0`` (high), ``warning`` -> ``4.0``
  (medium); GitHub buckets these into critical/high/medium/low.
* **results** — one per flagged *resource* when ScoutSuite lists them (each
  carried as a SARIF ``logicalLocation``), else one per finding. A synthetic
  physical location (``<provider>/<service>``) is attached because cloud
  findings have no source file, plus a stable ``partialFingerprints`` so GitHub
  can track the same alert across runs.

Built only from the in-memory :class:`~presidio_scoutsuite.findings.FindingsReport`
— pure stdlib, deterministic, offline-testable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .errors import PresidioScoutError
from .findings import FindingsReport, load_report
from .version import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/presidio-v/presidio-hardened-scoutsuite"

#: ScoutSuite level -> SARIF result level.
_LEVEL_TO_SARIF = {"danger": "error", "warning": "warning"}
#: ScoutSuite level -> GitHub ``security-severity`` (CVSS-like 0-10 string).
_LEVEL_TO_SECURITY_SEVERITY = {"danger": "8.0", "warning": "4.0"}


def _sarif_level(level: str) -> str:
    return _LEVEL_TO_SARIF.get(level, "note")


def _rule_id(service: str, key: str) -> str:
    return f"{service}/{key[:-5] if key.endswith('.json') else key}"


def _fingerprint(rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{item}".encode()).hexdigest()[:16]


def to_sarif(report: FindingsReport, *, tool_version: str = __version__) -> dict:
    """Build a SARIF 2.1.0 document from a :class:`FindingsReport`."""

    provider = report.providers[0] if report.providers else "cloud"

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in report.findings:
        rule_id = _rule_id(finding.service, finding.rule)
        level = _sarif_level(finding.level)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.description or rule_id},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "cloud", finding.service],
                    "security-severity": _LEVEL_TO_SECURITY_SEVERITY.get(finding.level, "0.0"),
                },
            }

        artifact_uri = f"{provider}/{finding.service}"
        # One result per flagged resource when available, else one per finding.
        targets = finding.items or (None,)
        for item in targets:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                }
            }
            if item is not None:
                location["logicalLocations"] = [{"fullyQualifiedName": item, "kind": "resource"}]
            text = finding.description or rule_id
            if item is not None:
                text = f"{text} — {item}"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": text},
                    "locations": [location],
                    "partialFingerprints": {
                        "presidioScoutFinding/v1": _fingerprint(rule_id, item or "")
                    },
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "presidio-hardened-scoutsuite",
                        "informationUri": _INFORMATION_URI,
                        "version": tool_version,
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-export",
        description=(
            "Export a ScoutSuite report's flagged findings as SARIF 2.1.0 for "
            "GitHub code scanning. Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument(
        "--format",
        choices=("sarif",),
        default="sarif",
        help="output format (default: sarif)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="write to this file instead of stdout",
    )
    parser.add_argument(
        "--waivers",
        metavar="PATH",
        help="JSON waiver file; waived findings are excluded from the SARIF output",
    )
    args = parser.parse_args(argv)

    try:
        report = load_report(args.report_dir)
        if args.waivers:
            from . import waivers as waivers_mod

            outcome = waivers_mod.apply_waivers(report, waivers_mod.load_waivers(args.waivers))
            for message in waivers_mod.summarize_outcome(outcome):
                print(message, file=sys.stderr)
            report = outcome.kept
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    document = to_sarif(report)
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(
            f"wrote SARIF for {len(document['runs'][0]['results'])} result(s) to {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
