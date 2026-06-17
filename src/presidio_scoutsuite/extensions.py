"""A small, stable extension point so orgs add capability without forking.

The distribution stays MIT and dependency-free, but a team may need its own
redactors (internal credential shapes), exporters (a bespoke finding format), or
sinks (an internal ticketing system). This module defines a **stable contract**
for those, discovered two ways:

* **Installed plugins** — Python entry points under the groups
  :data:`REDACTOR_GROUP` / :data:`EXPORTER_GROUP` / :data:`SINK_GROUP`.
* **Explicit references** — ``"module:attr"`` strings (e.g. from config or a
  flag), loaded with :func:`load_object`.

Each extension implements a tiny :class:`typing.Protocol` (see :class:`Redactor`,
:class:`Exporter`, :class:`Sink`). Loading is **fail-closed**: a malformed
reference, an import failure, a plugin that errors on load, or a redactor that
yields a malformed pattern raises :class:`ExtensionError` rather than being
silently skipped — a broken redactor extension must never quietly let a secret
through. Pure stdlib; never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import re
import sys
from typing import Protocol, runtime_checkable

from .errors import ExtensionError, PresidioScoutError

REDACTOR_GROUP = "presidio_scoutsuite.redactors"
EXPORTER_GROUP = "presidio_scoutsuite.exporters"
SINK_GROUP = "presidio_scoutsuite.sinks"
GROUPS = (REDACTOR_GROUP, EXPORTER_GROUP, SINK_GROUP)


@runtime_checkable
class Redactor(Protocol):
    """Supplies extra ``(name, compiled-pattern)`` secret redactors."""

    def patterns(self) -> list[tuple[str, re.Pattern[str]]]: ...


class Exporter(Protocol):
    """Renders a findings report into some text format."""

    def export(self, report: object) -> str: ...


class Sink(Protocol):
    """Delivers an audit summary somewhere (returns a short status string)."""

    def send(self, summary: dict) -> str: ...


def load_object(ref: str):
    """Import and return the object referenced by ``"module:attr"``.

    Fail-closed: a malformed reference or an import/attribute failure raises
    :class:`ExtensionError`.
    """

    if not isinstance(ref, str) or ref.count(":") != 1 or not all(ref.split(":")):
        raise ExtensionError(f"extension reference must be 'module:attr', got {ref!r}")
    module_name, attr = ref.split(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ExtensionError(f"cannot import extension module {module_name!r}: {exc}") from exc
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise ExtensionError(f"{module_name!r} has no attribute {attr!r}") from exc


def _entry_points(group: str) -> list:
    return list(importlib.metadata.entry_points().select(group=group))


def discover(group: str) -> dict[str, object]:
    """Load every installed entry point in ``group`` to ``{name: object}``.

    Fail-closed: an entry point that raises on load raises :class:`ExtensionError`
    naming it, rather than being silently dropped.
    """

    if group not in GROUPS:
        raise ExtensionError(f"unknown extension group {group!r}; expected one of {GROUPS}")
    out: dict[str, object] = {}
    for ep in _entry_points(group):
        try:
            out[ep.name] = ep.load()
        except Exception as exc:  # noqa: BLE001 - any plugin failure is fail-closed
            raise ExtensionError(f"failed to load extension {ep.name!r} in {group}: {exc}") from exc
    return out


def _validate_patterns(source: str, raw: object) -> list[tuple[str, re.Pattern[str]]]:
    if not isinstance(raw, (list, tuple)):
        raise ExtensionError(f"redactor {source!r}: patterns() must return a list")
    out: list[tuple[str, re.Pattern[str]]] = []
    for i, item in enumerate(raw, start=1):
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ExtensionError(
                f"redactor {source!r}: pattern #{i} must be a (name, pattern) pair"
            )
        name, pattern = item
        if not isinstance(name, str) or not name:
            raise ExtensionError(
                f"redactor {source!r}: pattern #{i} name must be a non-empty string"
            )
        if isinstance(pattern, str):
            try:
                pattern = re.compile(pattern)
            except re.error as exc:
                raise ExtensionError(
                    f"redactor {source!r}: pattern #{i} invalid regex: {exc}"
                ) from exc
        elif not isinstance(pattern, re.Pattern):
            raise ExtensionError(
                f"redactor {source!r}: pattern #{i} must be a regex string or compiled pattern"
            )
        out.append((name, pattern))
    return out


def redactor_patterns(redactors: dict[str, object]) -> list[tuple[str, re.Pattern[str]]]:
    """Collect and validate the extra patterns from loaded redactor extensions."""

    collected: list[tuple[str, re.Pattern[str]]] = []
    for name, obj in redactors.items():
        getter = getattr(obj, "patterns", None)
        if not callable(getter):
            raise ExtensionError(f"redactor {name!r} has no callable patterns()")
        collected.extend(_validate_patterns(name, getter()))
    return collected


def installed_redactor_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Discover installed redactor plugins and return their combined patterns.

    Empty when no plugin is installed — so the core run path gains nothing to fail
    on by default, but a broken installed redactor fails closed.
    """

    return redactor_patterns(discover(REDACTOR_GROUP))


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-ext",
        description=(
            "Inspect installed presidio-scout extensions (redactors / exporters / "
            "sinks) discovered via Python entry points."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list discovered extensions per group")

    args = parser.parse_args(argv)
    if args.command == "list":
        try:
            for group in GROUPS:
                names = sorted(discover(group))
                short = group.split(".")[-1]
                print(f"{short}: {', '.join(names) if names else '(none)'}")
        except PresidioScoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
