"""Validate that curated baselines reference rule names ScoutSuite actually has.

A ScoutSuite ruleset is a thin JSON document: its ``rules`` keys are the
*filenames* of finding rules that live inside ScoutSuite itself (e.g.
``providers/aws/rules/findings/s3-bucket-world-acl.json``). If a curated baseline
names a rule that the pinned ScoutSuite does not ship — a typo, or an upstream
rename between versions — ScoutSuite silently ignores it and the control quietly
drops out of the audit. Nothing in ScoutSuite warns about this.

This module closes that gap. It compares the rule names a baseline references
against the set of rules ScoutSuite provides, from one of two sources:

* **manifest** (offline, the default) — a checked-in inventory of the finding
  rules shipped by the pinned ScoutSuite version, one filename per line in
  ``policy/<provider>.rules.txt``. Lets CI validate the baselines on every push
  without installing GPL ScoutSuite.
* **installed** — the finding-rule files of an actually-installed ScoutSuite,
  discovered by import path. Used at release time (and to regenerate the
  manifest) so the offline inventory can't drift from upstream unnoticed.

The wrapper still never imports ScoutSuite to *run* it — discovery here only
reads rule files off disk to vet our own data.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path

from .errors import RulesetValidationError

#: Providers that ship a curated baseline + rule manifest as of this version.
VALIDATED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "aliyun", "oci")

#: Bundled curated baseline filename per provider.
_BASELINE_FILES: dict[str, str] = {
    "aws": "aws-cis.json",
    "azure": "azure-cis.json",
    "gcp": "gcp-cis.json",
    "aliyun": "aliyun-cis.json",
    "oci": "oci-cis.json",
}

#: Bundled rule-inventory manifest filename per provider.
_MANIFEST_FILES: dict[str, str] = {p: f"{p}.rules.txt" for p in VALIDATED_PROVIDERS}


def _policy_resource(name: str) -> Path:
    """Resolve a file shipped inside the ``presidio_scoutsuite.policy`` package."""

    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


def referenced_rules(ruleset_path: str | Path) -> set[str]:
    """Return the set of finding-rule filenames a ruleset JSON references."""

    data = json.loads(Path(ruleset_path).read_text(encoding="utf-8"))
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise RulesetValidationError(
            f"{ruleset_path}: 'rules' must be an object mapping rule filenames to settings"
        )
    return set(rules)


def baseline_path(provider: str) -> Path:
    """Path to the bundled curated baseline for ``provider``."""

    try:
        return _policy_resource(_BASELINE_FILES[provider])
    except KeyError as exc:
        raise RulesetValidationError(
            f"no curated baseline bundled for provider {provider!r}"
        ) from exc


def _parse_manifest(text: str) -> set[str]:
    rules: set[str] = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            rules.add(entry)
    return rules


def manifest_rules(provider: str) -> set[str]:
    """Return the rule-inventory manifest for ``provider`` (offline source)."""

    try:
        name = _MANIFEST_FILES[provider]
    except KeyError as exc:
        raise RulesetValidationError(f"no rule manifest bundled for provider {provider!r}") from exc
    return _parse_manifest(_policy_resource(name).read_text(encoding="utf-8"))


def installed_rules(provider: str) -> set[str]:
    """Return the finding-rule filenames an installed ScoutSuite ships for
    ``provider``.

    Reads ``ScoutSuite/providers/<provider>/rules/findings/*.json`` off disk.
    Raises :class:`RulesetValidationError` if ScoutSuite is not importable or the
    findings directory is missing, so the caller can fail closed.
    """

    try:
        findings = resources.files("ScoutSuite") / "providers" / provider / "rules" / "findings"
    except (ModuleNotFoundError, ImportError) as exc:
        raise RulesetValidationError(
            "ScoutSuite is not installed; install the '[scoutsuite]' extra to validate "
            "against the upstream rule inventory"
        ) from exc
    with resources.as_file(findings) as path:
        directory = Path(path)
        if not directory.is_dir():
            raise RulesetValidationError(
                f"installed ScoutSuite has no findings directory for provider {provider!r} "
                f"(looked in {directory})"
            )
        return {f.name for f in directory.glob("*.json")}


def render_manifest(provider: str, rules: set[str]) -> str:
    """Render the canonical ``<provider>.rules.txt`` text for ``rules``.

    Pure and deterministic (rules are sorted) so the upgrade automation produces
    a stable, reviewable diff. Used by :func:`regenerate_manifest`.
    """

    header = (
        f"# Finding-rule inventory for the pinned ScoutSuite (see requirements.lock).\n"
        f"#\n"
        f"# One finding-rule filename per line; '#' starts a comment. This is the offline\n"
        f"# source of truth the curated {provider}-cis.json baseline is validated against\n"
        f"# in CI, so the wrapper can be checked without installing GPL ScoutSuite.\n"
        f"#\n"
        f"# Regenerated from the installed ScoutSuite's rule inventory:\n"
        f"#\n"
        f"#     presidio-scout-validate --regenerate --source installed\n"
        f"#\n"
        f"# 'presidio-scout-validate --source installed' flags any drift between this\n"
        f"# inventory and the installed ScoutSuite.\n"
        f"\n"
    )
    return header + "".join(f"{rule}\n" for rule in sorted(rules))


def regenerate_manifest(provider: str) -> Path:
    """Rewrite ``<provider>.rules.txt`` from the installed ScoutSuite inventory.

    Fail-closed via :func:`installed_rules` (raises if ScoutSuite isn't
    installed). Returns the path written. Intended to run inside an env with the
    ``[scoutsuite]`` extra installed — the upgrade workflow does this after a
    version bump so the offline manifest tracks the newly pinned ScoutSuite.
    """

    try:
        name = _MANIFEST_FILES[provider]
    except KeyError as exc:
        raise RulesetValidationError(f"no rule manifest bundled for provider {provider!r}") from exc
    path = _policy_resource(name)
    path.write_text(render_manifest(provider, installed_rules(provider)), encoding="utf-8")
    return path


def available_rules(provider: str, *, source: str = "manifest") -> set[str]:
    """Return the rules ScoutSuite provides for ``provider`` from ``source``."""

    if source == "manifest":
        return manifest_rules(provider)
    if source == "installed":
        return installed_rules(provider)
    raise RulesetValidationError(
        f"unknown rule source {source!r}; expected 'manifest' or 'installed'"
    )


def missing_rules(provider: str, *, source: str = "manifest") -> set[str]:
    """Rules the curated baseline references but ``source`` does not provide."""

    return referenced_rules(baseline_path(provider)) - available_rules(provider, source=source)


def validate_provider(provider: str, *, source: str = "manifest") -> None:
    """Raise :class:`RulesetValidationError` if the baseline names unknown rules."""

    missing = missing_rules(provider, source=source)
    if missing:
        listed = ", ".join(sorted(missing))
        raise RulesetValidationError(
            f"{provider}: curated baseline references {len(missing)} rule(s) absent from the "
            f"{source} inventory: {listed}"
        )


def validate_all(*, source: str = "manifest") -> None:
    """Validate every provider that ships a curated baseline. Fail-closed."""

    for provider in VALIDATED_PROVIDERS:
        validate_provider(provider, source=source)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-validate",
        description=(
            "Validate that the curated ScoutSuite baselines reference only rule "
            "names the pinned ScoutSuite provides. Offline (manifest) by default; "
            "pass --source installed to check against an installed ScoutSuite."
        ),
    )
    parser.add_argument(
        "--source",
        choices=("manifest", "installed"),
        default="manifest",
        help="where to read the upstream rule inventory from (default: manifest)",
    )
    parser.add_argument(
        "--provider",
        choices=VALIDATED_PROVIDERS,
        help="validate a single provider (default: all)",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help=(
            "rewrite the offline rule manifest(s) from the installed ScoutSuite "
            "inventory (requires --source installed); used by upgrade automation"
        ),
    )
    args = parser.parse_args(argv)

    providers = (args.provider,) if args.provider else VALIDATED_PROVIDERS

    if args.regenerate:
        if args.source != "installed":
            print(
                "error: --regenerate requires --source installed",
                file=sys.stderr,
            )
            return 2
        try:
            for provider in providers:
                path = regenerate_manifest(provider)
                count = len(manifest_rules(provider))
                print(f"regenerated {provider}: {count} rule(s) -> {path}")
        except RulesetValidationError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            return 1
        return 0

    failed = False
    for provider in providers:
        try:
            validate_provider(provider, source=args.source)
        except RulesetValidationError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failed = True
        else:
            count = len(referenced_rules(baseline_path(provider)))
            print(f"ok   {provider}: {count} rule(s) all present in the {args.source} inventory")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
