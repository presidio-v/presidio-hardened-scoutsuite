"""Fan out a hardened audit across many cloud accounts/subscriptions/projects.

A team rarely has one cloud account — they have an org of them. This module
drives the wrapper across a declared matrix of *targets*, each pinned to its own
read-only identity (an AWS profile/assumed role, a GCP project + impersonated
service account, an Azure subscription), producing one report per target and a
single aggregated gate over the whole fleet.

Two invariants carry over from the rest of the distribution:

* **Out of process per target.** Each target is a separate ``presidio-scout``
  invocation (its own subprocess, its own scrubbed environment), so ScoutSuite
  credential/state never bleeds between accounts — exactly as a single run keeps
  ScoutSuite out of process.
* **No credential brokering** (the 0.12.0 decision). The orchestrator only
  *selects* which identity each target uses by setting that target's
  credential-resolution environment (``AWS_PROFILE``, ``CLOUDSDK_CORE_PROJECT``,
  …); it never mints or assumes credentials itself. Federated/assumed-role setup
  lives in the cloud config, as before.

Fail-closed: a target whose audit can't run, or whose results can't be read for
the gate, fails the aggregate rather than being silently skipped. Pure stdlib,
deterministic, offline-testable (the per-target runner is injectable).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import findings as findings_mod
from . import launcher
from .errors import OrchestrationError, PresidioScoutError

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 (tomllib is stdlib from 3.11)
    import tomli as tomllib  # type: ignore[no-redef]

TARGETS_FILENAME = ".presidio-scout-targets.toml"
_ALLOWED_KEYS = {"name", "provider", "env", "args"}
_TARGET_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GCP_",
    "CLOUDSDK_",
    "GOOGLE_CLOUD_",
    "ALIBABA_",
    "ALICLOUD_",
    "ALIYUN_",
    "OCI_",
)
_TARGET_ENV_NAMES = frozenset(
    {
        # Azure managed identity endpoints are credential selectors but are not
        # AZURE_ prefixed.
        "IDENTITY_ENDPOINT",
        "IDENTITY_HEADER",
        "MSI_ENDPOINT",
        "MSI_SECRET",
    }
)


def _validate_target_env(env: dict[str, str], *, where: str) -> None:
    bad = sorted(
        name
        for name in env
        if name not in _TARGET_ENV_NAMES and not name.startswith(_TARGET_ENV_PREFIXES)
    )
    if bad:
        raise OrchestrationError(f"{where} env contains non-credential key(s): {', '.join(bad)}")


@dataclass(frozen=True)
class Target:
    """A single account/subscription/project to audit."""

    name: str
    provider: str
    #: Extra environment for *credential resolution only* (profile/project/etc.).
    env: dict[str, str] = field(default_factory=dict)
    #: Extra ``presidio-scout`` flags for this target (e.g. a per-target ruleset).
    args: tuple[str, ...] = ()


def load_targets(path: str | Path) -> list[Target]:
    """Parse and fail-closed-validate the targets file.

    Each ``[[targets]]`` entry needs a unique ``name`` and a known ``provider``;
    ``env`` (if present) must be a table of string→string, and ``args`` a list of
    strings. Unknown keys, duplicate names, or bad shapes raise
    :class:`OrchestrationError` so a typo can't silently drop an account.
    """

    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise OrchestrationError(f"cannot read targets file {p}: {exc}") from exc

    raw = data.get("targets")
    if not isinstance(raw, list) or not raw:
        raise OrchestrationError(f"{p}: expected a non-empty [[targets]] array")

    targets: list[Target] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise OrchestrationError(f"{p}: target #{i + 1} must be a table")
        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            raise OrchestrationError(
                f"{p}: target #{i + 1} has unknown key(s): {', '.join(sorted(unknown))}"
            )
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise OrchestrationError(f"{p}: target #{i + 1} needs a non-empty 'name'")
        if name in seen:
            raise OrchestrationError(f"{p}: duplicate target name {name!r}")
        seen.add(name)
        provider = entry.get("provider")
        if provider not in launcher.PROVIDERS:
            raise OrchestrationError(
                f"{p}: target {name!r} has unknown provider {provider!r}; "
                f"expected one of {', '.join(launcher.PROVIDERS)}"
            )
        env = entry.get("env", {})
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()
        ):
            raise OrchestrationError(f"{p}: target {name!r} 'env' must be a table of strings")
        _validate_target_env(env, where=f"{p}: target {name!r}")
        args = entry.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise OrchestrationError(f"{p}: target {name!r} 'args' must be a list of strings")
        targets.append(Target(name, provider, dict(env), tuple(args)))
    return targets


def find_targets(start: str | Path | None = None) -> Path | None:
    """Return ``./.presidio-scout-targets.toml`` if it exists, else ``None``."""

    path = Path(start or Path.cwd()) / TARGETS_FILENAME
    return path if path.is_file() else None


@dataclass
class TargetResult:
    """Outcome of auditing one target."""

    name: str
    provider: str
    exit_code: int
    report_dir: str
    counts: dict[str, int] | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.error is None


def _default_runner(argv: list[str], env: dict[str, str], timeout: float | None) -> int:
    """Run ``presidio-scout`` as a subprocess; return its exit code."""

    proc = subprocess.run(argv, env=env, timeout=timeout, check=False)  # noqa: S603
    return proc.returncode


def run_target(
    target: Target,
    *,
    base_report_dir: str | Path,
    base_env: dict[str, str],
    extra_args: list[str] | None = None,
    scout_cmd: str = "presidio-scout",
    runner=_default_runner,
    timeout: float | None = None,
) -> TargetResult:
    """Audit a single target out of process and read back its findings.

    Builds ``<scout_cmd> <provider> --report-dir <base>/<name> [target args]
    [extra args]`` with ``base_env`` overlaid by the target's credential env, and
    runs it via ``runner`` (injectable for tests). After the run, the target's
    results are read for the aggregate; a results-read failure is recorded on the
    result (it becomes a fail-closed gate failure only when a gate is requested).
    """

    report_dir = Path(base_report_dir) / target.name
    argv = [scout_cmd, target.provider, "--report-dir", str(report_dir)]
    argv += list(target.args)
    argv += list(extra_args or [])
    _validate_target_env(target.env, where=f"target {target.name!r}")
    env = {**launcher.scrub_env(base_env), **target.env}

    try:
        code = runner(argv, env, timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return TargetResult(
            target.name, target.provider, 2, str(report_dir), error=f"run failed: {exc}"
        )

    counts: dict[str, int] | None = None
    read_error: str | None = None
    try:
        counts = findings_mod.load_report(report_dir).counts
    except PresidioScoutError as exc:
        read_error = f"could not read findings: {exc}"
    return TargetResult(target.name, target.provider, code, str(report_dir), counts, read_error)


@dataclass
class OrchestrationReport:
    """Aggregate of a fleet run."""

    results: list[TargetResult]

    @property
    def failed(self) -> list[TargetResult]:
        """Targets whose audit did not exit cleanly."""

        return [r for r in self.results if not r.ok]

    @property
    def totals(self) -> dict[str, int]:
        out = {level: 0 for level in findings_mod.LEVELS}
        for r in self.results:
            for level, n in (r.counts or {}).items():
                if level in out:
                    out[level] += n
        return out

    def gate_breaches(self, level: str) -> list[TargetResult]:
        """Targets with a flagged finding at or above ``level``.

        Fail-closed: a target whose results couldn't be read is also a breach —
        the gate must not pass on an account it never evaluated.
        """

        threshold = findings_mod._RANK.get(level.lower())
        if threshold is None:
            raise OrchestrationError(f"unknown severity level {level!r}")
        breaches: list[TargetResult] = []
        for r in self.results:
            if r.counts is None:
                breaches.append(r)
                continue
            if any(
                findings_mod._RANK.get(lvl, 0) >= threshold and n > 0 for lvl, n in r.counts.items()
            ):
                breaches.append(r)
        return breaches

    def to_dict(self) -> dict:
        return {
            "totals": self.totals,
            "failed": [r.name for r in self.failed],
            "targets": [
                {
                    "name": r.name,
                    "provider": r.provider,
                    "exit_code": r.exit_code,
                    "report_dir": r.report_dir,
                    "counts": r.counts,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


def run_all(
    targets: list[Target],
    *,
    base_report_dir: str | Path,
    base_env: dict[str, str],
    extra_args: list[str] | None = None,
    scout_cmd: str = "presidio-scout",
    runner=_default_runner,
    timeout: float | None = None,
) -> OrchestrationReport:
    """Audit every target (sequentially, for deterministic output)."""

    results = [
        run_target(
            t,
            base_report_dir=base_report_dir,
            base_env=base_env,
            extra_args=extra_args,
            scout_cmd=scout_cmd,
            runner=runner,
            timeout=timeout,
        )
        for t in targets
    ]
    return OrchestrationReport(results)


def _format_text(report: OrchestrationReport) -> str:
    lines = []
    for r in report.results:
        if r.ok and r.counts is not None:
            parts = ", ".join(
                f"{lvl}={r.counts.get(lvl, 0)}" for lvl in reversed(findings_mod.LEVELS)
            )
            lines.append(f"ok   {r.name} [{r.provider}] {parts}")
        else:
            why = r.error or f"exit {r.exit_code}"
            lines.append(f"FAIL {r.name} [{r.provider}] {why}")
    totals = report.totals
    summary = ", ".join(f"{lvl}={totals[lvl]}" for lvl in reversed(findings_mod.LEVELS))
    lines.append(
        f"fleet: {len(report.results)} target(s), {len(report.failed)} failed; totals {summary}"
    )
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    import os

    head, extra = (argv or sys.argv[1:]), []
    if "--" in head:
        idx = head.index("--")
        head, extra = head[:idx], head[idx + 1 :]

    parser = argparse.ArgumentParser(
        prog="presidio-scout-orchestrate",
        description=(
            "Fan a hardened ScoutSuite audit out across many accounts/subscriptions/"
            "projects declared in a targets file, one report per target plus an "
            "aggregated severity gate. Extra args after '--' pass through to each run."
        ),
    )
    parser.add_argument(
        "--targets",
        metavar="PATH",
        help=f"targets file (default: ./{TARGETS_FILENAME})",
    )
    parser.add_argument(
        "--report-dir",
        default="scoutsuite-fleet",
        help="base directory for per-target reports (default: ./scoutsuite-fleet)",
    )
    parser.add_argument(
        "--fail-on-finding",
        choices=findings_mod.LEVELS,
        help="exit non-zero (4) if any target has a flagged finding at or above this level",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="per-target timeout in seconds",
    )
    args = parser.parse_args(head)

    targets_path = args.targets or find_targets()
    if not targets_path:
        print(f"error: no targets file (looked for ./{TARGETS_FILENAME})", file=sys.stderr)
        return 2
    try:
        targets = load_targets(targets_path)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = run_all(
        targets,
        base_report_dir=args.report_dir,
        base_env=dict(os.environ),
        extra_args=extra,
        timeout=args.timeout,
    )

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(_format_text(report))

    # Fail-closed: any target that didn't run cleanly fails the fleet.
    if report.failed:
        print(
            f"FAIL {len(report.failed)} target(s) did not complete: "
            f"{', '.join(r.name for r in report.failed)}",
            file=sys.stderr,
        )
        return 2
    if args.fail_on_finding:
        breaches = report.gate_breaches(args.fail_on_finding)
        if breaches:
            print(
                f"FAIL {len(breaches)} target(s) at or above {args.fail_on_finding!r}: "
                f"{', '.join(r.name for r in breaches)}",
                file=sys.stderr,
            )
            return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
