"""Smoke-test the AWS-only ScoutSuite runtime installed from requirements.lock.

Run inside an environment built with

    pip install --no-deps --require-hashes -r requirements.lock

It checks the three claims ADR-0002 relies on, and exits non-zero on any failure:

1. Every module of ScoutSuite's AWS provider imports, and ``scout aws --help`` runs.
2. Every other provider fails to load because its SDK is absent.
3. Every dependency ScoutSuite declares is either installed or listed in
   requirements-aws.overrides, and every listed exclusion is a real ScoutSuite
   dependency that is not installed. A ScoutSuite upgrade that adds a dependency
   therefore fails here until a reviewer decides which side it belongs on.

This script imports ScoutSuite (GPL-2.0). It is a test of the bundled runtime, not
part of the MIT wrapper package, and is never shipped in the wheel.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

OVERRIDES = Path(__file__).resolve().parent.parent / "requirements-aws.overrides"
OTHER_PROVIDERS = ("azure", "gcp", "aliyun", "oci", "kubernetes", "do")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _excluded() -> set[str]:
    names = set()
    for line in OVERRIDES.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(_normalize(re.split(r"[\s;<>=!~\[]", line, maxsplit=1)[0]))
    return names


def check_aws_imports() -> list[str]:
    errors = []
    from ScoutSuite.providers import get_provider_object

    get_provider_object("aws")
    import ScoutSuite.providers.aws as aws

    count = 0
    for mod in pkgutil.walk_packages(aws.__path__, prefix="ScoutSuite.providers.aws."):
        try:
            importlib.import_module(mod.name)
            count += 1
        except Exception as exc:  # noqa: BLE001 - report every failing module
            errors.append(f"AWS module {mod.name} failed to import: {exc!r}")
    print(f"aws: {count} provider modules imported")

    scout = shutil.which("scout")
    if scout is None:
        errors.append("the 'scout' console script is not on PATH")
    else:
        proc = subprocess.run([scout, "aws", "--help"], capture_output=True, text=True)
        if proc.returncode != 0:
            errors.append(f"'scout aws --help' exited {proc.returncode}: {proc.stderr[-500:]}")
        else:
            print("aws: 'scout aws --help' ok")
    return errors


def check_other_providers_absent() -> list[str]:
    from ScoutSuite.providers import get_provider_object

    errors = []
    for provider in OTHER_PROVIDERS:
        try:
            get_provider_object(provider)
        except ImportError as exc:
            print(f"{provider}: refused as expected ({exc.name or exc})")
        else:
            errors.append(f"provider {provider!r} loaded, but its SDK should not be installed")
    return errors


def check_dependency_drift() -> list[str]:
    declared = set()
    for req in metadata.requires("ScoutSuite") or []:
        if "extra ==" in req:
            continue
        declared.add(_normalize(re.split(r"[\s;<>=!~\[(]", req, maxsplit=1)[0]))

    def installed(name: str) -> bool:
        try:
            metadata.version(name)
        except metadata.PackageNotFoundError:
            return False
        return True

    excluded = _excluded()
    errors = []
    for name in sorted(declared - excluded):
        if not installed(name):
            errors.append(f"ScoutSuite needs {name!r}: not installed and not excluded")
    for name in sorted(excluded):
        if name not in declared:
            errors.append(f"{name!r} is excluded but ScoutSuite does not declare it")
        elif installed(name):
            errors.append(f"{name!r} is excluded but installed")
    print(
        f"dependencies: {len(declared - excluded)} installed, "
        f"{len(excluded & declared)} excluded by requirements-aws.overrides"
    )
    return errors


def main() -> int:
    errors = check_aws_imports() + check_other_providers_absent() + check_dependency_drift()
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
