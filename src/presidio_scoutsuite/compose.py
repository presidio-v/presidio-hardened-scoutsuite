"""Org-extensible redaction patterns and composed baselines, from config.

Two optional, fail-closed extensions to ``.presidio-scout.toml`` that let an org
tailor the hardened defaults without forking the distribution:

* ``[redaction]`` — extra secret patterns applied **in addition to** the built-in
  redactors, so a team can scrub its own credential shapes (internal tokens, etc.)
  out of reports.
* ``[baseline]`` — compose a curated ruleset from a bundled provider baseline:
  raise/lower a rule's severity, add another rule the pinned ScoutSuite ships, or
  disable one — instead of hand-maintaining a whole ruleset file.

Both are validated **fail-closed** by ``presidio-scout-policy`` (and again when a
run applies them): an uncompilable regex, an unknown baseline rule (not in the
pinned ScoutSuite's manifest), or a bad severity errors rather than silently
doing nothing. Pure stdlib; never imports ScoutSuite.
"""

from __future__ import annotations

import json
import re

from . import ruleset
from .errors import ConfigError

_LEVELS = ("warning", "danger")


def _section(data: dict, name: str) -> dict | None:
    section = data.get(name)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ConfigError(f"[{name}] must be a table")
    return section


def parse_redaction_patterns(data: dict) -> list[tuple[str, re.Pattern[str]]]:
    """Compile ``[redaction].extra-patterns`` into (name, pattern) pairs.

    Each entry is either a bare regex string or a ``{name, pattern}`` table.
    Fail-closed: an unknown key, a non-string pattern, or an uncompilable regex
    raises :class:`ConfigError`.
    """

    section = _section(data, "redaction")
    if section is None:
        return []
    unknown = set(section) - {"extra-patterns", "extra_patterns"}
    if unknown:
        raise ConfigError(f"[redaction]: unknown key(s): {', '.join(sorted(unknown))}")
    entries = section.get("extra-patterns", section.get("extra_patterns", []))
    if not isinstance(entries, list):
        raise ConfigError("[redaction].extra-patterns must be an array")

    out: list[tuple[str, re.Pattern[str]]] = []
    for i, item in enumerate(entries, start=1):
        if isinstance(item, str):
            name, pattern = f"custom_{i}", item
        elif isinstance(item, dict):
            bad = set(item) - {"name", "pattern"}
            if bad:
                raise ConfigError(
                    f"[redaction] pattern #{i}: unknown key(s): {', '.join(sorted(bad))}"
                )
            pattern = item.get("pattern")
            name = item.get("name", f"custom_{i}")
            if not isinstance(pattern, str):
                raise ConfigError(f"[redaction] pattern #{i}: 'pattern' must be a string")
            if not isinstance(name, str):
                raise ConfigError(f"[redaction] pattern #{i}: 'name' must be a string")
        else:
            raise ConfigError(
                f"[redaction] pattern #{i} must be a regex string or a {{name, pattern}} table"
            )
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ConfigError(
                f"[redaction] pattern #{i}: invalid regex {pattern!r}: {exc}"
            ) from exc
        out.append((name, compiled))
    return out


def compose_baseline(data: dict) -> dict | None:
    """Build a composed ruleset from ``[baseline]``, or ``None`` if absent.

    Starts from the bundled ``base`` provider baseline, then applies
    ``[baseline.set-level]`` (override/add a rule's severity) and
    ``[baseline.disable]`` (drop rules). Fail-closed: an unknown base, an unknown
    rule (not in the pinned ScoutSuite's manifest), or a bad severity raises
    :class:`ConfigError`. Returns a ruleset dict ready to write for ScoutSuite.
    """

    section = _section(data, "baseline")
    if section is None:
        return None
    unknown = set(section) - {"base", "set-level", "set_level", "disable"}
    if unknown:
        raise ConfigError(f"[baseline]: unknown key(s): {', '.join(sorted(unknown))}")

    base = section.get("base")
    if base not in ruleset.VALIDATED_PROVIDERS:
        raise ConfigError(
            f"[baseline].base must be one of {', '.join(ruleset.VALIDATED_PROVIDERS)}"
        )
    manifest = ruleset.manifest_rules(base)
    composed: dict = json.loads(ruleset.baseline_path(base).read_text(encoding="utf-8")).get(
        "rules", {}
    )
    composed = dict(composed)

    set_level = section.get("set-level", section.get("set_level", {}))
    if not isinstance(set_level, dict):
        raise ConfigError("[baseline.set-level] must be a table of rule -> severity")
    for rule, level in set_level.items():
        if rule not in manifest:
            raise ConfigError(
                f"[baseline.set-level]: rule {rule!r} is not in the {base} manifest inventory"
            )
        if level not in _LEVELS:
            raise ConfigError(
                f"[baseline.set-level]: {rule!r} severity must be one of {', '.join(_LEVELS)}"
            )
        composed[rule] = [{"enabled": True, "level": level}]

    disable = section.get("disable", {})
    if disable:
        if not isinstance(disable, dict):
            raise ConfigError("[baseline.disable] must be a table")
        bad = set(disable) - {"rules"}
        if bad:
            raise ConfigError(f"[baseline.disable]: unknown key(s): {', '.join(sorted(bad))}")
        rules = disable.get("rules", [])
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            raise ConfigError("[baseline.disable].rules must be a list of rule-filename strings")
        for rule in rules:
            if rule not in manifest:
                raise ConfigError(
                    f"[baseline.disable]: rule {rule!r} is not in the {base} manifest inventory"
                )
            if rule not in composed:
                raise ConfigError(
                    f"[baseline.disable]: rule {rule!r} is not enabled in the composed baseline"
                )
            composed.pop(rule)

    if not composed:
        raise ConfigError("[baseline]: composition produced an empty ruleset")
    return {
        "about": f"Presidio composed baseline (from {base}-cis.json via .presidio-scout.toml)",
        "rules": composed,
    }


def validate_extensions(data: dict) -> None:
    """Fail-closed validation of both extension sections (for presidio-scout-policy)."""

    parse_redaction_patterns(data)
    compose_baseline(data)
