"""``presidio-scout`` — a hardened front end for the ScoutSuite CLI.

Runs ScoutSuite out of process with hardened defaults, then redacts the report
and applies the report guard before anything is surfaced.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from importlib import resources
from pathlib import Path

from . import (
    asff,
    attestation,
    compose,
    config,
    credentials,
    launcher,
    redact,
    report_guard,
    sarif,
    scout_integrity,
)
from . import findings as findings_mod
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
        nargs="?",
        choices=launcher.PROVIDERS,
        default=None,
        help="cloud provider to audit (may be set in .presidio-scout.toml)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help=f"org config file (default: ./{config.CONFIG_FILENAME} if present)",
    )
    parser.add_argument(
        "--profile",
        help="apply a named [profiles.<name>] section from the config",
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        help="directory for the report (locked to 0700); default: ./scoutsuite-report",
    )
    parser.add_argument(
        "--ruleset",
        help="path to a custom ScoutSuite ruleset (overrides the bundled baseline)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        default=None,
        help="do not apply the bundled hardened ruleset; use ScoutSuite's default",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        default=None,
        help="skip in-place redaction of the report (NOT recommended)",
    )
    parser.add_argument(
        "--fail-on-secret",
        action="store_true",
        default=None,
        help="exit non-zero if a secret remains in the report after redaction",
    )
    parser.add_argument(
        "--fail-on-remote-ref",
        action="store_true",
        default=None,
        help="exit non-zero if the report references a remote (network) resource",
    )
    parser.add_argument(
        "--fail-on-finding",
        choices=findings_mod.LEVELS,
        help="exit non-zero (4) if any flagged finding is at or above this severity "
        "(warning|danger) — use to gate a pipeline on the audit result",
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="also write the findings as SARIF 2.1.0 to PATH (for GitHub code scanning)",
    )
    parser.add_argument(
        "--asff",
        metavar="PATH",
        help="also write the findings as AWS Security Hub ASFF to PATH "
        "(requires --aws-account-id and --aws-region)",
    )
    parser.add_argument(
        "--aws-account-id",
        help="12-digit AWS account id for ASFF export (--asff)",
    )
    parser.add_argument(
        "--aws-region",
        help="AWS region for ASFF export (--asff)",
    )
    parser.add_argument(
        "--waivers",
        metavar="PATH",
        help="JSON waiver file; matching findings are suppressed before the gate/SARIF "
        "(expired waivers do not suppress)",
    )
    parser.add_argument(
        "--attest",
        metavar="PATH",
        help="write an in-toto run attestation (inputs -> report-manifest digest) to PATH; "
        "sign it with cosign sign-blob",
    )
    parser.add_argument(
        "--scout-bin",
        default=None,
        help="path to the upstream ScoutSuite executable (default: 'scout' on PATH)",
    )
    parser.add_argument(
        "--allow-unverified-scout",
        action="store_true",
        default=None,
        help="run even if the scout version doesn't match the pinned, vetted one "
        "(downgrades the integrity gate to a warning; NOT recommended)",
    )
    parser.add_argument(
        "--require-short-lived-creds",
        action="store_true",
        default=None,
        help="refuse to run with long-lived static credentials (an access key without "
        "a session token, a downloaded GCP key, an Azure client secret) — require "
        "assumed-role / OIDC / impersonation / managed identity instead",
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

    # Org config: [defaults] overlaid with --profile, applied only where the CLI
    # didn't set the option (explicit flags always win). Fail-closed on a bad file.
    try:
        settings = config.load_settings(config_path=args.config, profile=args.profile)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for dest, value in settings.items():
        if getattr(args, dest, None) is None:
            setattr(args, dest, value)
    # Restore the built-in defaults for anything still unset.
    if args.provider is None:
        print(
            "error: no provider given (pass one or set it in .presidio-scout.toml)",
            file=sys.stderr,
        )
        return 2
    if args.report_dir is None:
        args.report_dir = "scoutsuite-report"
    if args.scout_bin is None:
        args.scout_bin = "scout"

    # Org config extensions (fail-closed): extra redaction patterns applied during
    # redaction, and a composed baseline used as the ruleset unless the operator
    # passed --ruleset or --no-baseline.
    extra_redaction: list = []
    cfg_path = Path(args.config) if args.config else config.find_config()
    if cfg_path is not None:
        try:
            raw_config = config.read_raw(cfg_path)
            extra_redaction = compose.parse_redaction_patterns(raw_config)
            composed = compose.compose_baseline(raw_config)
        except PresidioScoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if composed is not None and not args.ruleset and not args.no_baseline:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".presidio-ruleset.json", delete=False, encoding="utf-8"
            ) as tmp:
                json.dump(composed, tmp)
            args.ruleset = tmp.name
            print(f"using composed baseline from {cfg_path} ({len(composed['rules'])} rules)")

    resolved_ruleset = _resolve_ruleset(args)
    try:
        plan = launcher.build_plan(
            args.provider,
            args.report_dir,
            ruleset=resolved_ruleset,
            extra_args=extra,
            scout_bin=args.scout_bin,
        )
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(plan.redacted_command())
        return 0

    # Integrity preflight: confirm the scout we're about to run is the pinned,
    # vetted ScoutSuite before handing it cloud credentials. Capture the version
    # so the run attestation can record what actually ran.
    if args.allow_unverified_scout:
        check = scout_integrity.verify_scout(args.scout_bin, require=False)
        if not check.ok:
            print(f"warning: running unverified ScoutSuite: {check.reason}", file=sys.stderr)
    else:
        try:
            check = scout_integrity.verify_scout(args.scout_bin)
        except PresidioScoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print(
                "       pass --allow-unverified-scout to run anyway (not recommended)",
                file=sys.stderr,
            )
            return 2
    scout_version = check.detected_version

    # Credential preflight: inspect the (scrubbed) child env and fail closed on
    # long-lived static secrets when the operator requires short-lived creds.
    cred = credentials.inspect_credentials(args.provider, plan.env)
    if cred.is_static:
        if args.require_short_lived_creds:
            print(
                f"error: {args.provider}: {cred.detail}; supply short-lived credentials "
                "(assume the bundled audit role, OIDC, impersonation, or managed identity)",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: {args.provider}: {cred.detail}; prefer short-lived credentials "
            "(see the README 'Keyless / short-lived credentials' section)",
            file=sys.stderr,
        )

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
        print(
            redact.redact_text(completed.stderr, extra=extra_redaction)[0], file=sys.stderr, end=""
        )

    if not args.no_redact:
        redacted = redact.redact_report_dir(plan.report_dir, extra=extra_redaction)
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

    findings_report = None
    if args.fail_on_finding or args.sarif or args.asff:
        try:
            findings_report = findings_mod.load_report(plan.report_dir)
            if args.waivers:
                from . import waivers as waivers_mod

                outcome = waivers_mod.apply_waivers(
                    findings_report, waivers_mod.load_waivers(args.waivers)
                )
                for message in waivers_mod.summarize_outcome(outcome):
                    print(message, file=sys.stderr)
                findings_report = outcome.kept
        except PresidioScoutError as exc:
            # Fail-closed: if we can't read the results/waivers we can't gate or export.
            print(f"error: cannot read findings: {exc}", file=sys.stderr)
            return 2

        if args.sarif:
            document = sarif.to_sarif(findings_report)
            Path(args.sarif).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            print(f"SARIF written: {args.sarif} ({len(findings_report.findings)} finding(s))")

        if args.asff:
            if not args.aws_account_id or not args.aws_region:
                print(
                    "error: --asff requires --aws-account-id and --aws-region",
                    file=sys.stderr,
                )
                return 2
            try:
                asff_findings = asff.to_asff(
                    findings_report,
                    account_id=args.aws_account_id,
                    region=args.aws_region,
                )
            except PresidioScoutError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            Path(args.asff).write_text(json.dumps(asff_findings, indent=2) + "\n", encoding="utf-8")
            print(f"ASFF written: {args.asff} ({len(asff_findings)} finding(s))")

    # Run attestation: bind this run's inputs to the report's integrity manifest.
    # Written even if the findings gate trips below, so the signed record exists.
    if args.attest:
        try:
            statement = attestation.attest_report(
                plan.report_dir,
                provider=args.provider,
                scoutsuite_version=scout_version,
                ruleset_path=resolved_ruleset,
                findings=findings_report.counts if findings_report is not None else None,
            )
        except PresidioScoutError as exc:
            print(f"error: cannot build run attestation: {exc}", file=sys.stderr)
            return 3
        Path(args.attest).write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        print(f"run attestation: {args.attest} (sign with cosign sign-blob)")

    if args.fail_on_finding and findings_report is not None:
        counts = findings_report.counts
        print(
            f"findings: {len(findings_report.findings)} flagged "
            f"(danger={counts['danger']}, warning={counts['warning']})"
        )
        offending = findings_report.at_or_above(args.fail_on_finding)
        if offending:
            print(
                f"error: {len(offending)} finding(s) at or above {args.fail_on_finding!r} severity",
                file=sys.stderr,
            )
            return 4

    return completed.returncode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
