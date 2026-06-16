"""``presidio-scout`` — a hardened front end for the ScoutSuite CLI.

Runs ScoutSuite out of process with hardened defaults, then redacts the report
and applies the report guard before anything is surfaced.
"""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from . import launcher, redact, report_guard
from .errors import PresidioScoutError
from .version import __version__

#: Curated rulesets bundled with the package, keyed by provider. AWS, Azure, and
#: GCP ship hardened baselines; any other provider falls back to ScoutSuite's
#: default ruleset (with a warning) until its baseline lands.
_BUNDLED_RULESETS = {
    "aws": "aws-cis.json",
    "azure": "azure-cis.json",
    "gcp": "gcp-cis.json",
}


def _bundled_ruleset_path(provider: str) -> Path | None:
    name = _BUNDLED_RULESETS.get(provider)
    if name is None:
        return None
    # importlib.resources keeps this working from a wheel/zip install.
    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="presidio-scout",
        description=(
            "Presidio-hardened wrapper around ScoutSuite. Runs the upstream "
            "'scout' CLI out of process with hardened defaults, then redacts "
            "and guards the generated report."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "provider",
        choices=launcher.PROVIDERS,
        help="cloud provider to audit",
    )
    parser.add_argument(
        "--report-dir",
        default="scoutsuite-report",
        help="directory for the report (locked to 0700); default: ./scoutsuite-report",
    )
    parser.add_argument(
        "--ruleset",
        help="path to a custom ScoutSuite ruleset (overrides the bundled baseline)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="do not apply the bundled hardened ruleset; use ScoutSuite's default",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="skip in-place redaction of the report (NOT recommended)",
    )
    parser.add_argument(
        "--fail-on-secret",
        action="store_true",
        help="exit non-zero if a secret remains in the report after redaction",
    )
    parser.add_argument(
        "--fail-on-remote-ref",
        action="store_true",
        help="exit non-zero if the report references a remote (network) resource",
    )
    parser.add_argument(
        "--scout-bin",
        default="scout",
        help="path to the upstream ScoutSuite executable (default: 'scout' on PATH)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="kill ScoutSuite after this many seconds",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the hardened command that would run, then exit",
    )
    return parser


def _resolve_ruleset(args: argparse.Namespace) -> str | None:
    if args.ruleset:
        return args.ruleset
    if args.no_baseline:
        return None
    bundled = _bundled_ruleset_path(args.provider)
    if bundled is None:
        print(
            f"warning: no bundled baseline ruleset for {args.provider!r}; "
            "using ScoutSuite's default",
            file=sys.stderr,
        )
    return str(bundled) if bundled else None


def _split_passthrough(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv at the first ``--``.

    Everything before it is parsed by argparse (provider + our own options);
    everything after is forwarded to ScoutSuite (subject to the allowlist).
    Done manually because ``argparse.REMAINDER`` greedily swallows our own
    flags too.
    """

    if "--" in argv:
        idx = argv.index("--")
        return argv[:idx], argv[idx + 1 :]
    return argv, []


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    head, extra = _split_passthrough(list(argv))
    parser = build_parser()
    args = parser.parse_args(head)

    try:
        plan = launcher.build_plan(
            args.provider,
            args.report_dir,
            ruleset=_resolve_ruleset(args),
            extra_args=extra,
            scout_bin=args.scout_bin,
        )
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(plan.redacted_command())
        return 0

    try:
        completed = launcher.run(plan, timeout=args.timeout)
    except FileNotFoundError:
        print(
            f"error: ScoutSuite executable {args.scout_bin!r} not found on PATH; "
            "install ScoutSuite or pass --scout-bin",
            file=sys.stderr,
        )
        return 2

    # ScoutSuite's own stdout/stderr may echo identifiers; redact before showing.
    if completed.stderr:
        print(redact.redact_text(completed.stderr)[0], file=sys.stderr, end="")

    if not args.no_redact:
        redacted = redact.redact_report_dir(plan.report_dir)
        for rel, findings in redacted.items():
            print(f"redacted {len(findings)} secret(s) in {rel}", file=sys.stderr)

    try:
        guard = report_guard.guard_report(
            plan.report_dir,
            fail_on_secret=args.fail_on_secret,
            fail_on_remote_ref=args.fail_on_remote_ref,
        )
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    print(
        f"report ready: {plan.report_dir} "
        f"({len(guard.manifest)} files, {len(guard.html_hardened)} HTML hardened, "
        f"{len(guard.sri_hardened)} SRI-pinned)"
    )
    if guard.manifest_path is not None:
        print(f"integrity manifest: {guard.manifest_path} (verify with presidio-scout-verify)")
    if guard.has_secrets:
        print(
            f"warning: {len(guard.secret_findings)} file(s) still contain secret-like strings",
            file=sys.stderr,
        )
    if guard.has_remote_refs:
        print(
            f"warning: report references {len(guard.remote_refs)} remote resource(s); "
            "the CSP blocks them but the report is not fully self-contained",
            file=sys.stderr,
        )

    return completed.returncode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
