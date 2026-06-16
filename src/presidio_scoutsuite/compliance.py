"""Map ScoutSuite findings to compliance controls (CIS / NIST 800-53 / SOC 2).

An auditor's flagged findings are far more useful to a GRC team when they are
expressed as *control* failures. This module loads a curated, checked-in mapping
from ScoutSuite finding rules to control identifiers in several frameworks, and
turns a :class:`~presidio_scoutsuite.findings.FindingsReport` into a per-control
view: which controls have at least one flagged finding, and which findings carry
no mapping at all.

The mapping data lives in ``policy/<provider>.controls.json`` (one entry per
finding-rule filename → ``{framework: [control ids]}``). It is validated
**fail-closed** against the rule-name manifest the same way curated baselines are
(:func:`validate_mapping`): a mapping that references a rule the pinned ScoutSuite
doesn't ship, or an undeclared framework, errors rather than silently mislabeling
compliance. Pure stdlib, deterministic, offline-testable — never imports
ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .errors import ComplianceError, PresidioScoutError
from .findings import FindingsReport, load_report

#: Frameworks this distribution ships curated mappings for.
FRAMEWORKS: tuple[str, ...] = ("cis", "nist-800-53", "soc2")
#: Providers that ship a curated control mapping.
MAPPED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp")

_MAPPING_FILES: dict[str, str] = {p: f"{p}.controls.json" for p in MAPPED_PROVIDERS}


def _policy_resource(name: str) -> Path:
    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


def _finding_id(service: str, key: str) -> str:
    return f"{service}/{key[:-5] if key.endswith('.json') else key}"


@dataclass(frozen=True)
class ComplianceMapping:
    """A provider's rule→control mapping."""

    provider: str
    frameworks: tuple[str, ...]
    controls: dict[str, dict[str, list[str]]]


def load_mapping(provider: str) -> ComplianceMapping:
    """Load and shape-check the control mapping bundled for ``provider``.

    Fail-closed: a missing/malformed file, a non-object ``controls`` table, or an
    entry that isn't ``{framework: [control, ...]}`` raises
    :class:`ComplianceError`.
    """

    try:
        name = _MAPPING_FILES[provider]
    except KeyError as exc:
        raise ComplianceError(f"no control mapping bundled for provider {provider!r}") from exc
    try:
        data = json.loads(_policy_resource(name).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ComplianceError(f"cannot read control mapping for {provider!r}: {exc}") from exc

    frameworks = tuple(data.get("frameworks", FRAMEWORKS))
    controls = data.get("controls")
    if not isinstance(controls, dict):
        raise ComplianceError(f"{name}: 'controls' must be an object mapping rules to controls")

    cleaned: dict[str, dict[str, list[str]]] = {}
    for rule, entry in controls.items():
        if not isinstance(entry, dict):
            raise ComplianceError(f"{name}: entry for {rule!r} must be an object of frameworks")
        per_fw: dict[str, list[str]] = {}
        for fw, ids in entry.items():
            if fw not in frameworks:
                raise ComplianceError(
                    f"{name}: rule {rule!r} references undeclared framework {fw!r}"
                )
            if not isinstance(ids, list) or not all(isinstance(c, str) for c in ids):
                raise ComplianceError(f"{name}: {rule!r}/{fw} must be a list of control id strings")
            per_fw[fw] = list(ids)
        cleaned[str(rule)] = per_fw
    return ComplianceMapping(provider, frameworks, cleaned)


def validate_mapping(provider: str) -> None:
    """Fail-closed check that every mapped rule exists in the rule manifest.

    A mapping that points at a rule the pinned ScoutSuite doesn't ship (a typo or
    an upstream rename) would silently drop a control from the compliance view —
    so this raises :class:`ComplianceError` listing the unknown rules.
    """

    from . import ruleset

    mapping = load_mapping(provider)
    known = ruleset.manifest_rules(provider)
    unknown = sorted(set(mapping.controls) - known)
    if unknown:
        raise ComplianceError(
            f"{provider}: control mapping references {len(unknown)} rule(s) absent from the "
            f"manifest inventory: {', '.join(unknown)}"
        )


@dataclass
class ComplianceReport:
    """A per-control view of a findings report across one or more frameworks."""

    providers: list[str]
    frameworks: tuple[str, ...]
    #: framework -> control id -> sorted finding ids that fail it
    failing: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    #: finding ids that carry no control mapping at all
    unmapped: list[str] = field(default_factory=list)

    def control_count(self, framework: str) -> int:
        return len(self.failing.get(framework, {}))

    def to_dict(self) -> dict:
        return {
            "providers": self.providers,
            "frameworks": list(self.frameworks),
            "failing_controls": {fw: self.failing.get(fw, {}) for fw in self.frameworks},
            "unmapped_findings": self.unmapped,
        }


def merged_controls(providers: list[str]) -> dict[str, dict[str, list[str]]]:
    """Merge the control tables for ``providers`` into one rule→controls lookup."""

    merged: dict[str, dict[str, list[str]]] = {}
    for provider in providers:
        try:
            merged.update(load_mapping(provider).controls)
        except ComplianceError:
            continue  # provider without a bundled mapping
    return merged


def build_report(
    findings_report: FindingsReport,
    *,
    providers: list[str] | None = None,
    frameworks: tuple[str, ...] = FRAMEWORKS,
) -> ComplianceReport:
    """Build a :class:`ComplianceReport` from flagged findings.

    Providers default to the report's own ``providers`` (or every mapped provider
    if the report didn't record one). Each flagged finding maps to zero or more
    controls per framework; a finding with no mapping entry is collected in
    ``unmapped`` so it's visible rather than silently uncounted.
    """

    provs = providers or findings_report.providers or list(MAPPED_PROVIDERS)
    lookup = merged_controls(provs)
    failing: dict[str, dict[str, list[str]]] = {fw: {} for fw in frameworks}
    unmapped: set[str] = set()

    for finding in findings_report.findings:
        fid = _finding_id(finding.service, finding.rule)
        entry = lookup.get(finding.rule)
        if entry is None:
            unmapped.add(fid)
            continue
        for framework in frameworks:
            for control in entry.get(framework, []):
                failing[framework].setdefault(control, []).append(fid)

    for framework in failing:
        for control in failing[framework]:
            failing[framework][control] = sorted(set(failing[framework][control]))
    return ComplianceReport(provs, tuple(frameworks), failing, sorted(unmapped))


def related_requirements(controls: dict[str, list[str]]) -> list[str]:
    """Format a rule's controls as ASFF-style ``RelatedRequirements`` strings."""

    labels = {"cis": "CIS", "nist-800-53": "NIST.800-53.r5", "soc2": "SOC2"}
    out: list[str] = []
    for framework in FRAMEWORKS:
        for control in controls.get(framework, []):
            out.append(f"{labels.get(framework, framework)} {control}")
    return out


def _format_text(report: ComplianceReport) -> str:
    provider = ", ".join(report.providers) or "unknown"
    lines = [
        f"compliance [{provider}]: "
        + ", ".join(f"{fw}={report.control_count(fw)}" for fw in report.frameworks)
        + f" failing control(s); {len(report.unmapped)} unmapped finding(s)"
    ]
    for framework in report.frameworks:
        controls = report.failing.get(framework, {})
        if not controls:
            continue
        lines.append(f"{framework}:")
        for control in sorted(controls):
            findings = controls[control]
            lines.append(f"  {control:<14} {len(findings)} finding(s): {', '.join(findings)}")
    if report.unmapped:
        lines.append("unmapped findings (no control mapping):")
        for fid in report.unmapped:
            lines.append(f"  {fid}")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-compliance",
        description=(
            "Map a ScoutSuite report's flagged findings to compliance controls "
            "(CIS / NIST 800-53 / SOC 2). Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument(
        "--framework",
        choices=FRAMEWORKS,
        action="append",
        help="limit to this framework (repeatable; default: all)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--waivers",
        metavar="PATH",
        help="JSON waiver file; waived findings are excluded before mapping",
    )
    parser.add_argument(
        "--fail-on-unmapped",
        action="store_true",
        help="exit non-zero (4) if any flagged finding has no control mapping",
    )
    args = parser.parse_args(argv)

    try:
        findings_report = load_report(args.report_dir)
        if args.waivers:
            from . import waivers as waivers_mod

            outcome = waivers_mod.apply_waivers(
                findings_report, waivers_mod.load_waivers(args.waivers)
            )
            for message in waivers_mod.summarize_outcome(outcome):
                print(message, file=sys.stderr)
            findings_report = outcome.kept
        frameworks = tuple(args.framework) if args.framework else FRAMEWORKS
        report = build_report(findings_report, frameworks=frameworks)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(_format_text(report))

    if args.fail_on_unmapped and report.unmapped:
        print(
            f"FAIL {len(report.unmapped)} flagged finding(s) have no control mapping",
            file=sys.stderr,
        )
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
