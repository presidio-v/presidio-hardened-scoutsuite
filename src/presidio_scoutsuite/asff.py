"""Export ScoutSuite findings as AWS Security Hub Finding Format (ASFF).

ASFF is the JSON schema AWS Security Hub ingests via ``BatchImportFindings``.
Emitting the audit's flagged findings as ASFF lets cloud-misconfiguration
findings land in Security Hub as managed findings — routed, suppressed, and
aggregated alongside GuardDuty/Inspector/Config — and, via the ``Compliance``
block, tied to the same control identifiers the compliance mapping records.

Mapping (documented so it's auditable):

* **Id** — ``presidio-scout/<provider>/<service>/<rule>[/<resource>]`` (stable).
* **ProductArn** — the account's default custom-integration product ARN.
* **Severity** — ScoutSuite ``danger`` → ``HIGH``/70, ``warning`` → ``MEDIUM``/40.
* **Resources** — one ``Other`` resource per flagged resource (else a synthetic
  ``<provider>:<service>`` resource), so each finding points at what it flagged.
* **Compliance.RelatedRequirements** — the finding's CIS/NIST/SOC 2 controls,
  pulled from :mod:`presidio_scoutsuite.compliance`.

Built only from the in-memory findings model plus injected identifiers — pure
stdlib, deterministic (timestamps are injectable), offline-testable. Never
imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import compliance
from .errors import AsffError, PresidioScoutError
from .findings import FindingsReport, load_report
from .version import __version__

SCHEMA_VERSION = "2018-10-08"
_ACCOUNT_RE = re.compile(r"^\d{12}$")
#: ScoutSuite level -> (ASFF Severity.Label, Severity.Normalized 0-100).
_SEVERITY = {"danger": ("HIGH", 70), "warning": ("MEDIUM", 40)}
_FINDING_TYPE = "Software and Configuration Checks/Industry and Regulatory Standards"


def _rule_id(key: str) -> str:
    return key[:-5] if key.endswith(".json") else key


def _product_arn(account_id: str, region: str, partition: str) -> str:
    return f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default"


def _timestamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_asff(
    report: FindingsReport,
    *,
    account_id: str,
    region: str,
    partition: str = "aws",
    when: datetime | None = None,
    tool_version: str = __version__,
) -> list[dict]:
    """Build a list of ASFF findings from a :class:`FindingsReport`.

    ``account_id`` must be a 12-digit AWS account id and ``region`` non-empty;
    both are required and fail closed (a malformed batch must not reach Security
    Hub). ``when`` is injectable for deterministic output.
    """

    if not _ACCOUNT_RE.match(account_id or ""):
        raise AsffError(f"account_id must be a 12-digit AWS account id, got {account_id!r}")
    if not region:
        raise AsffError("region is required for ASFF export")

    stamp = _timestamp(when or datetime.now(timezone.utc))
    product_arn = _product_arn(account_id, region, partition)
    provider = report.providers[0] if report.providers else "cloud"
    lookup = compliance.merged_controls(report.providers or list(compliance.MAPPED_PROVIDERS))

    findings: list[dict] = []
    for finding in report.findings:
        rule = _rule_id(finding.key)
        label, normalized = _SEVERITY.get(finding.level, ("INFORMATIONAL", 0))
        requirements = compliance.related_requirements(lookup.get(finding.key, {}))
        title = (finding.description or f"{finding.service}/{rule}")[:256]

        targets = finding.items or (None,)
        for item in targets:
            suffix = f"/{item}" if item is not None else ""
            resource_id = item or f"{provider}:{finding.service}"
            entry = {
                "SchemaVersion": SCHEMA_VERSION,
                "Id": f"presidio-scout/{provider}/{finding.service}/{rule}{suffix}",
                "ProductArn": product_arn,
                "GeneratorId": f"presidio-hardened-scoutsuite/{finding.service}/{rule}",
                "ProductName": "presidio-hardened-scoutsuite",
                "CompanyName": "Presidio",
                "AwsAccountId": account_id,
                "Types": [_FINDING_TYPE],
                "CreatedAt": stamp,
                "UpdatedAt": stamp,
                "Severity": {"Label": label, "Normalized": normalized},
                "Title": title,
                "Description": (finding.description or title)[:1024],
                "ProductFields": {
                    "Provider": provider,
                    "Service": finding.service,
                    "Rule": rule,
                    "FlaggedItems": str(finding.flagged_items),
                    "presidio/toolVersion": tool_version,
                },
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": resource_id,
                        "Partition": partition,
                        "Region": region,
                    }
                ],
                "Compliance": {"Status": "FAILED"},
                "RecordState": "ACTIVE",
            }
            if requirements:
                entry["Compliance"]["RelatedRequirements"] = requirements
            findings.append(entry)
    return findings


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-asff",
        description=(
            "Export a ScoutSuite report's flagged findings as AWS Security Hub "
            "ASFF (BatchImportFindings input). Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument("--aws-account-id", required=True, help="12-digit AWS account id")
    parser.add_argument("--aws-region", required=True, help="AWS region for the findings")
    parser.add_argument("--partition", default="aws", help="AWS partition (default: aws)")
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    parser.add_argument(
        "--waivers",
        metavar="PATH",
        help="JSON waiver file; waived findings are excluded from the export",
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
        findings = to_asff(
            report,
            account_id=args.aws_account_id,
            region=args.aws_region,
            partition=args.partition,
        )
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {len(findings)} ASFF finding(s) to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
