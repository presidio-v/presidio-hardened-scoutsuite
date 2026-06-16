"""ScoutSuite upgrade automation: keep the pin coherent, make bumps reviewable.

The pinned ScoutSuite version underpins every gate in this distribution — the
install-integrity preflight (:mod:`scout_integrity`), the hash-pinned lockfile
the container installs with ``--require-hashes``, and the rule-name inventory
the curated baselines validate against (:mod:`ruleset`). That version is declared
in several files that **must agree**; if they drift, a gate can silently check
against the wrong version. This module is two things:

* a **fail-closed coherence gate** over the pin sites — the ``scoutsuite`` extra
  in ``pyproject.toml`` (the authoritative source of truth that
  :func:`scout_integrity.pinned_version` reads), the ``scoutsuite==`` line in
  ``requirements.lock``, and the ``PINNED_SCOUTSUITE_VERSION`` fallback constant
  in ``scout_integrity.py`` — that errors if any disagree;
* a deterministic, reviewable **bump planner / applier**: it performs only the
  *offline, deterministic* part of an upgrade (the in-repo text pins) and emits
  the exact, ordered commands for the parts that need an environment —
  regenerating the hash-pinned ``requirements.lock`` (needs PyPI) and the
  rule-name manifests (needs the GPL ScoutSuite installed).

Pure stdlib, deterministic, offline-testable, and — like the rest of the
wrapper — never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import UpgradeError

# --- pin sites ---------------------------------------------------------------

#: Authoritative pin: the ``scoutsuite`` extra in pyproject.toml. This is what
#: :func:`scout_integrity.pinned_version` reads from installed metadata.
_PYPROJECT = "pyproject.toml"
_LOCK = "requirements.lock"
_INTEGRITY = "src/presidio_scoutsuite/scout_integrity.py"

#: ``ScoutSuite==X`` inside the extra (also matches the lock's lower-cased line).
_EXTRA_RE = re.compile(r"ScoutSuite\s*==\s*([0-9][^\s\"';\\]*)", re.IGNORECASE)
#: ``scoutsuite==X`` at the start of a line in the pip-compile lockfile.
_LOCK_RE = re.compile(r"(?mi)^scoutsuite==([0-9][^\s\\]*)")
#: ``PINNED_SCOUTSUITE_VERSION = "X"`` fallback constant.
_CONST_RE = re.compile(r"""PINNED_SCOUTSUITE_VERSION\s*=\s*["']([^"']+)["']""")

#: Well-formed release version: 2 to 4 dotted numeric components (e.g. 5.14.0).
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")


@dataclass(frozen=True)
class Pin:
    """A single declared ScoutSuite version and where it lives."""

    name: str
    path: Path
    version: str | None
    #: True when :func:`apply_text_pins` can deterministically rewrite it in
    #: place (text pin). The lockfile is False — it carries hashes and must be
    #: regenerated from PyPI, not hand-edited.
    rewritable: bool


def parse_version(value: str) -> tuple[int, ...]:
    """Parse a dotted release version into a comparable tuple of ints.

    Fail-closed: anything that isn't 2–4 plain numeric components (no pre/post
    suffixes, no wildcards) raises :class:`UpgradeError` rather than being
    coerced — an upgrade gate must not guess at an ambiguous version string.
    """

    if not isinstance(value, str) or not _VERSION_RE.match(value):
        raise UpgradeError(f"malformed version {value!r}: expected 2–4 dotted numbers, e.g. 5.14.0")
    return tuple(int(part) for part in value.split("."))


def find_root(start: Path | None = None) -> Path:
    """Walk up from ``start`` (default: cwd) to the repo root holding pyproject.toml."""

    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / _PYPROJECT).is_file():
            return candidate
    raise UpgradeError(f"could not find {_PYPROJECT} at or above {here}")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UpgradeError(f"cannot read {path}: {exc}") from exc


def _extract(regex: re.Pattern[str], text: str) -> str | None:
    match = regex.search(text)
    return match.group(1) if match else None


def discover_pins(root: Path | None = None) -> list[Pin]:
    """Read the declared ScoutSuite version from every pin site under ``root``."""

    base = root or find_root()
    return [
        Pin(
            "scoutsuite extra (pyproject.toml)",
            base / _PYPROJECT,
            _extract(_EXTRA_RE, _read(base / _PYPROJECT)),
            rewritable=True,
        ),
        Pin(
            "requirements.lock",
            base / _LOCK,
            _extract(_LOCK_RE, _read(base / _LOCK)),
            rewritable=False,
        ),
        Pin(
            "PINNED_SCOUTSUITE_VERSION (scout_integrity.py)",
            base / _INTEGRITY,
            _extract(_CONST_RE, _read(base / _INTEGRITY)),
            rewritable=True,
        ),
    ]


def authoritative_version(root: Path | None = None) -> str:
    """The current pinned version, read from the authoritative ``scoutsuite`` extra.

    Fail-closed: if the extra's pin is absent the project has no defined pinned
    ScoutSuite, so we error rather than fall back to a stale constant.
    """

    base = root or find_root()
    version = _extract(_EXTRA_RE, _read(base / _PYPROJECT))
    if version is None:
        raise UpgradeError(
            f"no 'ScoutSuite==' pin found in the [scoutsuite] extra of {base / _PYPROJECT}"
        )
    return version


@dataclass
class CoherenceReport:
    """Outcome of :func:`check_coherence`."""

    version: str | None
    pins: list[Pin]
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def check_coherence(root: Path | None = None) -> CoherenceReport:
    """Verify every pin site declares the same ScoutSuite version.

    The authoritative version is the ``scoutsuite`` extra. A pin that is missing
    or disagrees is reported as a problem; an empty problem list means coherent.
    Does not raise (so a caller can render the full picture) — the CLI turns a
    non-empty report into a non-zero exit.
    """

    pins = discover_pins(root)
    authoritative = pins[0].version
    problems: list[str] = []
    if authoritative is None:
        problems.append(f"{pins[0].name}: no ScoutSuite pin found (no source of truth)")
    for pin in pins:
        if pin.version is None:
            problems.append(f"{pin.name}: no ScoutSuite version found")
        elif authoritative is not None and pin.version != authoritative:
            problems.append(
                f"{pin.name}: pinned {pin.version}, expected {authoritative} (from {pins[0].name})"
            )
    return CoherenceReport(authoritative, pins, problems)


def assert_coherent(root: Path | None = None) -> str:
    """Return the coherent pinned version, or raise :class:`UpgradeError`."""

    report = check_coherence(root)
    if not report.ok:
        raise UpgradeError("incoherent ScoutSuite pin:\n  " + "\n  ".join(report.problems))
    assert report.version is not None  # guaranteed by ok
    return report.version


# --- planning / applying -----------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One ordered action in an upgrade plan."""

    description: str
    #: ``"edit"`` text pins (done by :func:`apply_text_pins`); ``"regenerate"``
    #: needs an environment (PyPI / installed ScoutSuite); ``"verify"`` re-checks.
    kind: str
    command: str | None = None

    @property
    def automatable(self) -> bool:
        """True when :func:`apply_text_pins` performs this step offline."""

        return self.kind == "edit"


@dataclass
class UpgradePlan:
    """A deterministic, reviewable plan to move from ``current`` to ``target``."""

    current: str
    target: str
    steps: list[Step]

    def to_dict(self) -> dict:
        return {
            "current": self.current,
            "target": self.target,
            "steps": [
                {
                    "description": s.description,
                    "kind": s.kind,
                    "command": s.command,
                    "automatable": s.automatable,
                }
                for s in self.steps
            ],
        }


def plan_upgrade(target: str, *, root: Path | None = None) -> UpgradePlan:
    """Build the ordered steps to bump the pinned ScoutSuite to ``target``.

    Fail-closed on two preconditions: the current pins must already be coherent
    (you don't bump from a broken base), and ``target`` must be well-formed and
    strictly newer than the current pin (no silent downgrade or no-op).
    """

    base = root or find_root()
    current = assert_coherent(base)
    if parse_version(target) <= parse_version(current):
        raise UpgradeError(f"target {target} is not newer than the current pin {current}")
    lock_cmd = (
        "pip-compile --allow-unsafe --extra=scoutsuite --generate-hashes "
        "--output-file=requirements.lock --strip-extras pyproject.toml"
    )
    steps = [
        Step(
            f"Pin ScoutSuite=={target} in the [scoutsuite] extra of pyproject.toml",
            "edit",
        ),
        Step(
            f'Set PINNED_SCOUTSUITE_VERSION = "{target}" in scout_integrity.py',
            "edit",
        ),
        Step(
            "Regenerate the hash-pinned requirements.lock against PyPI",
            "regenerate",
            lock_cmd,
        ),
        Step(
            "Regenerate the rule-name manifests against the installed ScoutSuite "
            "(needs the GPL [scoutsuite] extra installed)",
            "regenerate",
            'pip install -e ".[scoutsuite]" && presidio-scout-validate --source installed',
        ),
        Step(
            "Re-check pin coherence",
            "verify",
            "presidio-scout-upgrade check",
        ),
        Step(
            "Validate the curated baselines against the new offline manifest",
            "verify",
            "presidio-scout-validate --source manifest",
        ),
        Step(
            "Run the test suite",
            "verify",
            "pytest",
        ),
    ]
    return UpgradePlan(current, target, steps)


def _rewrite(path: Path, regex: re.Pattern[str], old: str, new: str) -> None:
    text = _read(path)
    updated, count = regex.subn(lambda m: m.group(0).replace(old, new, 1), text, count=1)
    if count != 1:
        raise UpgradeError(f"expected exactly one pin to rewrite in {path}, changed {count}")
    path.write_text(updated, encoding="utf-8")


def apply_text_pins(target: str, *, root: Path | None = None) -> list[Path]:
    """Apply only the deterministic, offline text pins for an upgrade.

    Rewrites the ``scoutsuite`` extra in pyproject.toml and the
    ``PINNED_SCOUTSUITE_VERSION`` constant in scout_integrity.py to ``target``.
    Deliberately does **not** touch ``requirements.lock`` or the rule manifests
    — those need PyPI / an installed ScoutSuite and are regenerated by the
    workflow. After this call the pins are intentionally incoherent (the lock
    still names the old version) until that regeneration runs; the returned
    paths are what changed. Fail-closed: refuses an incoherent base, a malformed
    target, or a target that isn't strictly newer.
    """

    base = root or find_root()
    current = assert_coherent(base)
    if parse_version(target) <= parse_version(current):
        raise UpgradeError(f"target {target} is not newer than the current pin {current}")
    pyproject = base / _PYPROJECT
    integrity = base / _INTEGRITY
    _rewrite(pyproject, _EXTRA_RE, current, target)
    _rewrite(integrity, _CONST_RE, current, target)
    return [pyproject, integrity]


# --- CLI ---------------------------------------------------------------------


def _print_report(report: CoherenceReport) -> None:
    for pin in report.pins:
        shown = pin.version if pin.version is not None else "<none>"
        print(f"  {shown:<12} {pin.name}")
    if report.ok:
        print(f"ok   coherent: ScoutSuite pinned to {report.version} everywhere")
    else:
        for problem in report.problems:
            print(f"FAIL {problem}", file=sys.stderr)


def _print_plan(plan: UpgradePlan) -> None:
    print(f"Upgrade ScoutSuite {plan.current} -> {plan.target}\n")
    for i, step in enumerate(plan.steps, 1):
        tag = {"edit": "auto", "regenerate": "env ", "verify": "check"}[step.kind]
        print(f"  {i}. [{tag}] {step.description}")
        if step.command:
            print(f"        $ {step.command}")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-upgrade",
        description=(
            "Keep the pinned ScoutSuite version coherent across pin sites and "
            "make version bumps a reviewable, fail-closed operation."
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repo root (default: discovered from the current directory)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="verify every pin site agrees (exit 4 on drift)")
    sub.add_parser("current", help="print the authoritative pinned version")
    p_plan = sub.add_parser("plan", help="print the ordered steps to bump to --to")
    p_plan.add_argument("--to", required=True, metavar="VERSION", help="target version")
    p_plan.add_argument("--json", action="store_true", help="emit the plan as JSON")
    p_apply = sub.add_parser(
        "apply",
        help="apply the offline text pins for a bump to --to (lock/manifests regen separately)",
    )
    p_apply.add_argument("--to", required=True, metavar="VERSION", help="target version")
    args = parser.parse_args(argv)

    try:
        if args.command == "check":
            report = check_coherence(args.root)
            _print_report(report)
            return 0 if report.ok else 4
        if args.command == "current":
            print(authoritative_version(args.root))
            return 0
        if args.command == "plan":
            plan = plan_upgrade(args.to, root=args.root)
            if args.json:
                print(json.dumps(plan.to_dict(), indent=2))
            else:
                _print_plan(plan)
            return 0
        if args.command == "apply":
            changed = apply_text_pins(args.to, root=args.root)
            for path in changed:
                print(f"edited {path}")
            print(
                "\nText pins updated. requirements.lock and the rule manifests are "
                "now stale — regenerate them before committing:"
            )
            print(
                "  $ pip-compile --allow-unsafe --extra=scoutsuite --generate-hashes "
                "--output-file=requirements.lock --strip-extras pyproject.toml"
            )
            print(
                '  $ pip install -e ".[scoutsuite]" && presidio-scout-validate --source installed'
            )
            return 0
    except UpgradeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
