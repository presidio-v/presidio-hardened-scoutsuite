"""Offline checks on the AWS-only runtime lock (ADR-0002).

These run without ScoutSuite installed. scripts/runtime_smoke.py covers the
checks that need the installed runtime (AWS imports, other providers refused,
dependency drift against ScoutSuite's metadata).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.lock"
OVERRIDES = ROOT / "requirements-aws.overrides"

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_entries() -> dict[str, list[str]]:
    """Map each pinned package to the hash lines that follow it."""
    entries: dict[str, list[str]] = {}
    current = None
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line)
        if match:
            current = _normalize(match.group(1))
            entries[current] = []
        elif current and "--hash=sha256:" in line:
            entries[current].append(line.strip())
    return entries


def _override_lines() -> list[str]:
    lines = []
    for raw in OVERRIDES.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def test_lock_pins_scoutsuite_and_hashes_every_entry():
    entries = _lock_entries()
    assert "scoutsuite" in entries
    unhashed = [name for name, hashes in entries.items() if not hashes]
    assert unhashed == []


def test_every_override_is_a_never_true_exclusion():
    for line in _override_lines():
        assert line.endswith("; python_version < '0'"), line


def test_no_excluded_sdk_in_lock():
    excluded = {_normalize(line.split(";", 1)[0].strip()) for line in _override_lines()}
    assert excluded, "requirements-aws.overrides lists no exclusions"
    assert excluded.isdisjoint(_lock_entries())


def test_no_azure_gcp_or_protobuf_in_lock():
    # The packages behind the former runtime-track blockers (PYSEC-2026-1209,
    # PYSEC-2026-1805/1806) must not come back through some other dependency.
    names = _lock_entries()
    leaked = [n for n in names if n.startswith(("azure-", "google-", "msgraph")) or n == "protobuf"]
    assert leaked == []


def test_lock_header_records_the_override_recipe():
    head = LOCK.read_text(encoding="utf-8").splitlines()[:3]
    assert any("--override requirements-aws.overrides" in line for line in head)
