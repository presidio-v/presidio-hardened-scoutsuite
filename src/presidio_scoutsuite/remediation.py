"""Map ScoutSuite findings to curated remediation guidance.

Telling an operator *that* a control failed is only half the job; the useful half
is *how to fix it*. This module loads a checked-in, per-rule remediation map
(``policy/<provider>.remediation.json``: rule → summary + steps + references) and
attaches it to a report's flagged findings. The same data fills the AWS Security
Hub ASFF ``Remediation`` field (:mod:`presidio_scoutsuite.asff`).

Like the compliance map, remediation is validated **fail-closed** against the
rule-name manifest (:func:`validate_remediation`): guidance that points at a rule
the pinned ScoutSuite doesn't ship errors, so fix steps can't silently drift from
the rules they claim to address. Pure stdlib, offline-testable; never imports
ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .errors import PresidioScoutError, RemediationError
from .findings import _RANK, load_report

MAPPED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp")
_FILES: dict[str, str] = {p: f"{p}.remediation.json" for p in MAPPED_PROVIDERS}


def _policy_resource(name: str) -> Path:
    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


def _finding_id(service: str, rule: str) -> str:
    return f"{service}/{rule[:-5] if rule.endswith('.json') else rule}"


@dataclass(frozen=True)
class Remediation:
    """Fix guidance for one finding rule."""

    summary: str
    steps: tuple[str, ...]
    references: tuple[str, ...]

    def to_json(self) -> dict:
        return {
            "summary": self.summary,
            "steps": list(self.steps),
            "references": list(self.references),
        }


def load_remediation(provider: str) -> dict[str, Remediation]:
    """Load and shape-check the remediation map bundled for ``provider``.

    Fail-closed: a missing/malformed file, or an entry without a string
    ``summary`` and non-empty string lists ``steps``/``references`` raises
    :class:`RemediationError`.
    """

    try:
        name = _FILES[provider]
    except KeyError as exc:
        raise RemediationError(f"no remediation bundled for provider {provider!r}") from exc
    try:
        data = json.loads(_policy_resource(name).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RemediationError(f"cannot read remediation for {provider!r}: {exc}") from exc

    entries = data.get("remediation")
    if not isinstance(entries, dict):
        raise RemediationError(f"{name}: 'remediation' must be an object mapping rules to guidance")
    out: dict[str, Remediation] = {}
    for rule, entry in entries.items():
        if not isinstance(entry, dict):
            raise RemediationError(f"{name}: entry for {rule!r} must be an object")
        summary = entry.get("summary")
        steps = entry.get("steps", [])
        refs = entry.get("references", [])
        if not isinstance(summary, str) or not summary:
            raise RemediationError(f"{name}: {rule!r} needs a non-empty 'summary' string")
        if not isinstance(steps, list) or not steps or not all(isinstance(s, str) for s in steps):
            raise RemediationError(f"{name}: {rule!r} 'steps' must be a non-empty list of strings")
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            raise RemediationError(f"{name}: {rule!r} 'references' must be a list of strings")
        out[str(rule)] = Remediation(summary, tuple(steps), tuple(refs))
    return out


def validate_remediation(provider: str) -> None:
    """Fail-closed check that every remediated rule exists in the rule manifest."""

    from . import ruleset

    mapping = load_remediation(provider)
    known = ruleset.manifest_rules(provider)
    unknown = sorted(set(mapping) - known)
    if unknown:
        raise RemediationError(
            f"{provider}: remediation references {len(unknown)} rule(s) absent from the "
            f"manifest inventory: {', '.join(unknown)}"
        )


def merged_remediation(providers: list[str]) -> dict[str, Remediation]:
    """Merge the remediation maps for ``providers`` into one rule→guidance lookup."""

    merged: dict[str, Remediation] = {}
    for provider in providers:
        try:
            merged.update(load_remediation(provider))
        except RemediationError:
            continue
    return merged


def remediation_for(rule: str, lookup: dict[str, Remediation]) -> Remediation | None:
    """Look up guidance for a finding rule (with or without the ``.json`` suffix)."""

    if rule in lookup:
        return lookup[rule]
    return lookup.get(f"{rule}.json")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-remediate",
        description=(
            "Attach curated remediation guidance to a ScoutSuite report's flagged "
            "findings. Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on-unmapped",
        action="store_true",
        help="exit non-zero (4) if any flagged finding has no remediation guidance",
    )
    args = parser.parse_args(argv)

    try:
        report = load_report(args.report_dir)
        lookup = merged_remediation(report.providers or list(MAPPED_PROVIDERS))
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = sorted(report.findings, key=lambda f: (-_RANK.get(f.level, 0), f.service, f.rule))
    rows = []
    unmapped = []
    for finding in findings:
        fid = _finding_id(finding.service, finding.rule)
        rem = remediation_for(finding.rule, lookup)
        if rem is None:
            unmapped.append(fid)
        rows.append((fid, finding.level, rem))

    if args.format == "json":
        print(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": fid,
                            "level": level,
                            "remediation": rem.to_json() if rem else None,
                        }
                        for fid, level, rem in rows
                    ],
                    "unmapped": unmapped,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for fid, level, rem in rows:
            if rem is None:
                print(f"{level:<7} {fid}\n  (no remediation guidance)")
                continue
            print(f"{level:<7} {fid}\n  fix: {rem.summary}")
            for step in rem.steps:
                print(f"    - {step}")
            for ref in rem.references:
                print(f"    see: {ref}")

    if args.fail_on_unmapped and unmapped:
        print(
            f"FAIL {len(unmapped)} flagged finding(s) have no remediation guidance",
            file=sys.stderr,
        )
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
