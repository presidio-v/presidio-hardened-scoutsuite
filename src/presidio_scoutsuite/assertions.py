"""Policy-as-code: declarative pass/fail assertions over a report's findings.

A single ``--fail-on-finding`` threshold is blunt — "fail if anything is danger".
Real policy is more specific: *no* public storage in prod, *no* danger findings in
IAM, *at most* five warnings overall. This module evaluates a declarative policy
file of named assertions against a :class:`~presidio_scoutsuite.findings.FindingsReport`.

Each ``[[assert]]`` selects findings by ``service`` / ``rules`` (globs) /
``min_level`` and requires the matched count to stay within ``max`` (default 0).
Validation and evaluation are **fail-closed**: an unknown key, a bad severity, a
negative ``max``, or an unreadable report errors rather than letting a violating
posture pass. Pure stdlib, offline-testable; never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from .errors import PolicyError, PresidioScoutError
from .findings import _RANK, LEVELS, FindingsReport, load_report

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

_ALLOWED = {"name", "service", "rules", "min_level", "min-level", "max"}


@dataclass(frozen=True)
class Assertion:
    """One named pass/fail rule over the findings."""

    name: str
    service: str | None = None
    rules: tuple[str, ...] = ()
    min_level: str | None = None
    max: int = 0

    def matches(self, service: str, rule: str, level: str) -> bool:
        if self.service is not None and service != self.service:
            return False
        if self.min_level is not None and _RANK.get(level, 0) < _RANK[self.min_level]:
            return False
        if self.rules:
            stripped = rule[:-5] if rule.endswith(".json") else rule
            if not any(fnmatchcase(rule, g) or fnmatchcase(stripped, g) for g in self.rules):
                return False
        return True


def _assertion_from(entry: object, where: str) -> Assertion:
    if not isinstance(entry, dict):
        raise PolicyError(f"{where} must be a table")
    unknown = set(entry) - _ALLOWED
    if unknown:
        raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyError(f"{where} needs a non-empty 'name'")
    service = entry.get("service")
    if service is not None and not isinstance(service, str):
        raise PolicyError(f"{name!r}: 'service' must be a string")
    rules = entry.get("rules", [])
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise PolicyError(f"{name!r}: 'rules' must be a list of strings")
    min_level = entry.get("min_level", entry.get("min-level"))
    if min_level is not None and min_level not in LEVELS:
        raise PolicyError(f"{name!r}: 'min_level' must be one of {', '.join(LEVELS)}")
    max_allowed = entry.get("max", 0)
    if not isinstance(max_allowed, int) or isinstance(max_allowed, bool) or max_allowed < 0:
        raise PolicyError(f"{name!r}: 'max' must be a non-negative integer")
    return Assertion(name, service, tuple(rules), min_level, max_allowed)


def load_policy(path: str | Path) -> list[Assertion]:
    """Parse and fail-closed-validate the policy file (``[[assert]]`` array)."""

    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot read policy file {p}: {exc}") from exc
    extra = set(data) - {"assert"}
    if extra:
        raise PolicyError(f"{p}: unknown top-level key(s): {', '.join(sorted(extra))}")
    raw = data.get("assert")
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"{p}: expected a non-empty [[assert]] array")
    seen: set[str] = set()
    out: list[Assertion] = []
    for i, entry in enumerate(raw, start=1):
        assertion = _assertion_from(entry, f"{p}: assertion #{i}")
        if assertion.name in seen:
            raise PolicyError(f"{p}: duplicate assertion name {assertion.name!r}")
        seen.add(assertion.name)
        out.append(assertion)
    return out


@dataclass
class AssertionResult:
    """Outcome of one assertion."""

    assertion: Assertion
    matched: list[str]

    @property
    def passed(self) -> bool:
        return len(self.matched) <= self.assertion.max


@dataclass
class PolicyReport:
    """Outcome of evaluating a whole policy."""

    results: list[AssertionResult] = field(default_factory=list)

    @property
    def failed(self) -> list[AssertionResult]:
        return [r for r in self.results if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "assertions": [
                {
                    "name": r.assertion.name,
                    "passed": r.passed,
                    "max": r.assertion.max,
                    "matched": sorted(r.matched),
                }
                for r in self.results
            ],
        }


def evaluate(report: FindingsReport, policy: list[Assertion]) -> PolicyReport:
    """Evaluate every assertion against the flagged findings."""

    results: list[AssertionResult] = []
    for assertion in policy:
        matched = sorted(
            f"{f.service}/{f.rule[:-5] if f.rule.endswith('.json') else f.rule}"
            for f in report.findings
            if assertion.matches(f.service, f.rule, f.level)
        )
        results.append(AssertionResult(assertion, matched))
    return PolicyReport(results)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-assert",
        description=(
            "Evaluate a declarative policy of named assertions against a ScoutSuite "
            "report (exit 4 on any failure). Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to a finished report directory")
    parser.add_argument("--policy", required=True, metavar="PATH", help="TOML policy file")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    try:
        report = load_report(args.report_dir)
        policy = load_policy(args.policy)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    outcome = evaluate(report, policy)

    if args.format == "json":
        print(json.dumps(outcome.to_dict(), indent=2, sort_keys=True))
    else:
        for r in outcome.results:
            if r.passed:
                print(f"PASS {r.assertion.name} ({len(r.matched)}/{r.assertion.max})")
            else:
                print(
                    f"FAIL {r.assertion.name} ({len(r.matched)} > {r.assertion.max}): "
                    f"{', '.join(r.matched)}"
                )
        print(f"policy: {len(outcome.failed)}/{len(outcome.results)} assertion(s) failed")

    return 4 if outcome.failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
