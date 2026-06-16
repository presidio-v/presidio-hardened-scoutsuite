"""Gate a release on a container/dependency vulnerability scan, fail-closed.

The release pipeline scans the published image (Trivy) and audits the locked
dependency tree (`pip-audit`); this module is the **policy gate** over a scanner
report — the same split the project uses elsewhere (the scanner finds, this
decides). It normalizes a **Trivy** or **Grype** JSON report into a common model
and fails closed when any vulnerability is at or above a chosen severity, with an
``--ignore-unfixed`` mode so a release is only blocked by issues that actually
have a fix.

Pure stdlib, deterministic, offline-testable. Scanning itself stays in the
scanner; signing the SBOM / scan report stays in cosign / GitHub attestations.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import VulnerabilityError

#: Severity levels in ascending order; threshold compares by rank.
LEVELS: tuple[str, ...] = ("negligible", "low", "medium", "high", "critical")
_RANK: dict[str, int] = {level: i for i, level in enumerate(LEVELS, start=1)}
#: Severities a CLI gate accepts as a threshold.
THRESHOLDS: tuple[str, ...] = ("low", "medium", "high", "critical")


def _rank(severity: str) -> int:
    return _RANK.get(severity.lower(), 0)


@dataclass(frozen=True)
class Vuln:
    """One normalized vulnerability match."""

    id: str
    package: str
    installed_version: str
    severity: str
    fixed_version: str | None = None

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)


def _from_trivy(obj: dict) -> list[Vuln]:
    out: list[Vuln] = []
    for result in obj.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            out.append(
                Vuln(
                    id=str(v.get("VulnerabilityID", "")),
                    package=str(v.get("PkgName", "")),
                    installed_version=str(v.get("InstalledVersion", "")),
                    severity=str(v.get("Severity", "")).lower(),
                    fixed_version=(v.get("FixedVersion") or None),
                )
            )
    return out


def _from_grype(obj: dict) -> list[Vuln]:
    out: list[Vuln] = []
    for match in obj.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vuln.get("fix") or {}
        fixed = None
        if fix.get("state") == "fixed":
            fixed = ", ".join(fix.get("versions") or []) or "fixed"
        out.append(
            Vuln(
                id=str(vuln.get("id", "")),
                package=str(artifact.get("name", "")),
                installed_version=str(artifact.get("version", "")),
                severity=str(vuln.get("severity", "")).lower(),
                fixed_version=fixed,
            )
        )
    return out


def parse_report(data: str | bytes) -> list[Vuln]:
    """Parse a Trivy or Grype JSON report into normalized :class:`Vuln`\\ s."""

    text = data.decode("utf-8") if isinstance(data, bytes) else data
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise VulnerabilityError(f"report is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise VulnerabilityError("report is not a JSON object")
    if "Results" in obj:
        return _from_trivy(obj)
    if "matches" in obj:
        return _from_grype(obj)
    raise VulnerabilityError("unrecognized report format (expected Trivy or Grype JSON)")


@dataclass
class VulnReport:
    """Normalized vulnerabilities plus severity gating."""

    vulns: list[Vuln] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {level: 0 for level in LEVELS}
        for v in self.vulns:
            if v.severity in counts:
                counts[v.severity] += 1
        return counts

    def at_or_above(self, threshold: str, *, fixable_only: bool = False) -> list[Vuln]:
        rank = _RANK.get(threshold.lower())
        if rank is None:
            raise VulnerabilityError(
                f"unknown severity {threshold!r}; expected one of {THRESHOLDS}"
            )
        return [
            v for v in self.vulns if _rank(v.severity) >= rank and (v.fixable or not fixable_only)
        ]


def load_report(path: str | Path) -> VulnReport:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise VulnerabilityError(f"cannot read report {p}: {exc}") from exc
    return VulnReport(vulns=parse_report(text))


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-vuln-gate",
        description=(
            "Gate on a Trivy/Grype vulnerability report — exit non-zero (4) if any "
            "vulnerability is at or above the chosen severity. Offline; the scan "
            "itself is done by the scanner."
        ),
    )
    parser.add_argument("report", help="path to a Trivy or Grype JSON report; - for stdin")
    parser.add_argument(
        "--fail-on",
        choices=THRESHOLDS,
        default="critical",
        help="severity threshold (default: critical)",
    )
    parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="only count vulnerabilities that have a fix available",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    try:
        if args.report == "-":
            report = VulnReport(vulns=parse_report(sys.stdin.read()))
        else:
            report = load_report(args.report)
        offending = report.at_or_above(args.fail_on, fixable_only=args.ignore_unfixed)
    except VulnerabilityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = report.counts
    scope = "fixable " if args.ignore_unfixed else ""
    if args.format == "json":
        print(json.dumps({"counts": counts, "offending": len(offending)}, sort_keys=True))
    else:
        summary = ", ".join(f"{level}={counts[level]}" for level in reversed(LEVELS))
        print(f"vulnerabilities: {summary}")

    if offending:
        print(
            f"FAIL {len(offending)} {scope}vulnerability(ies) at or above {args.fail_on!r}:",
            file=sys.stderr,
        )
        for v in sorted(offending, key=lambda x: (-_rank(x.severity), x.package, x.id)):
            fix = f" (fix: {v.fixed_version})" if v.fixable else " (no fix)"
            print(
                f"  {v.severity:<8} {v.id} {v.package} {v.installed_version}{fix}",
                file=sys.stderr,
            )
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
