"""Org defaults and named profiles from ``.presidio-scout.toml``.

Lets a team check in its hardened defaults — provider, ruleset, which gates to
enforce, the waivers file — once, instead of repeating long flag lists in every
pipeline. ``[defaults]`` applies to every run; a ``[profiles.<name>]`` table
(selected with ``--profile``) overlays it; and explicit CLI flags still win over
both. ``presidio-scout-policy`` validates the file so a typo in org policy fails
loudly rather than being silently ignored.

TOML is parsed with the stdlib ``tomllib`` (Python 3.11+); on 3.9/3.10 the tiny
``tomli`` backport is used — the single conditional runtime dependency.
Validation is fail-closed: unknown sections/keys, wrong types, or out-of-range
values (e.g. an unknown provider or severity) all error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

from .errors import ConfigError
from .launcher import PROVIDERS

CONFIG_FILENAME = ".presidio-scout.toml"

_STR, _BOOL, _NUM = "str", "bool", "num"

#: Recognized settings: argparse ``dest`` -> (kind, allowed-values | None).
#: TOML keys may be kebab-case (``report-dir``) and are normalized to ``dest``.
_OPTIONS: dict[str, tuple[str, tuple[str, ...] | None]] = {
    "provider": (_STR, PROVIDERS),
    "report_dir": (_STR, None),
    "ruleset": (_STR, None),
    "no_baseline": (_BOOL, None),
    "no_redact": (_BOOL, None),
    "fail_on_secret": (_BOOL, None),
    "fail_on_remote_ref": (_BOOL, None),
    "fail_on_finding": (_STR, ("warning", "danger")),
    "require_short_lived_creds": (_BOOL, None),
    "allow_unverified_scout": (_BOOL, None),
    "scout_bin": (_STR, None),
    "timeout": (_NUM, None),
    "waivers": (_STR, None),
    "sarif": (_STR, None),
    "attest": (_STR, None),
}


def _validate_table(table: object, *, where: str) -> dict:
    if not isinstance(table, dict):
        raise ConfigError(f"{where} must be a table")
    out: dict = {}
    for raw_key, value in table.items():
        dest = raw_key.replace("-", "_")
        if dest not in _OPTIONS:
            raise ConfigError(f"{where}: unknown setting {raw_key!r}")
        kind, allowed = _OPTIONS[dest]
        if kind == _STR and not isinstance(value, str):
            raise ConfigError(f"{where}: {raw_key!r} must be a string")
        if kind == _BOOL and not isinstance(value, bool):
            raise ConfigError(f"{where}: {raw_key!r} must be a boolean")
        if kind == _NUM and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            raise ConfigError(f"{where}: {raw_key!r} must be a number")
        if allowed is not None and value not in allowed:
            raise ConfigError(f"{where}: {raw_key!r} must be one of {', '.join(allowed)}")
        out[dest] = value
    return out


def _read(path: Path) -> dict:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    extra = set(data) - {"defaults", "profiles"}
    if extra:
        raise ConfigError(f"{path}: unknown top-level section(s): {', '.join(sorted(extra))}")
    return data


def validate_file(path: str | Path) -> list[str]:
    """Validate the whole config (defaults + every profile). Returns profile names."""

    data = _read(Path(path))
    _validate_table(data.get("defaults", {}), where="[defaults]")
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ConfigError("[profiles] must be a table")
    for name, table in profiles.items():
        _validate_table(table, where=f"[profiles.{name}]")
    return sorted(profiles)


def resolve(path: str | Path, profile: str | None = None) -> dict:
    """Return merged settings: ``[defaults]`` overlaid with ``[profiles.<profile>]``."""

    data = _read(Path(path))
    merged = _validate_table(data.get("defaults", {}), where="[defaults]")
    if profile is not None:
        profiles = data.get("profiles", {})
        if not isinstance(profiles, dict) or profile not in profiles:
            raise ConfigError(f"profile {profile!r} not found in {path}")
        merged.update(_validate_table(profiles[profile], where=f"[profiles.{profile}]"))
    return merged


def find_config(start: str | Path | None = None) -> Path | None:
    """Return ``./.presidio-scout.toml`` if present in ``start`` (cwd by default)."""

    path = Path(start or Path.cwd()) / CONFIG_FILENAME
    return path if path.is_file() else None


def load_settings(
    *,
    config_path: str | Path | None = None,
    profile: str | None = None,
    cwd: str | Path | None = None,
) -> dict:
    """Resolve settings for a run: explicit ``config_path`` or auto-discovered cwd config.

    Returns ``{}`` when there is no config and no profile was requested; raises
    :class:`ConfigError` if a profile is requested without a (findable) config.
    """

    path = Path(config_path) if config_path else find_config(cwd)
    if path is None:
        if profile is not None:
            raise ConfigError(f"--profile {profile!r} requested but no {CONFIG_FILENAME} found")
        return {}
    if not path.is_file():
        raise ConfigError(f"config file {path} not found")
    return resolve(path, profile)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-policy",
        description="Validate or show a .presidio-scout.toml org config.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    val = sub.add_parser("validate", help="validate the config (all profiles)")
    val.add_argument("--config", help=f"path to the config (default: ./{CONFIG_FILENAME})")
    show = sub.add_parser("show", help="print the resolved settings as JSON")
    show.add_argument("--config", help=f"path to the config (default: ./{CONFIG_FILENAME})")
    show.add_argument("--profile", help="overlay this profile")
    args = parser.parse_args(argv)

    path = Path(args.config) if args.config else find_config()
    if path is None:
        print(f"error: no {CONFIG_FILENAME} found", file=sys.stderr)
        return 2

    try:
        if args.command == "validate":
            profiles = validate_file(path)
            extra = f" + profiles: {', '.join(profiles)}" if profiles else ""
            print(f"ok   {path}: valid (defaults{extra})")
        else:
            print(json.dumps(resolve(path, args.profile), indent=2, sort_keys=True))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
