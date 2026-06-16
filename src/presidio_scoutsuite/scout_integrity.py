"""Verify the ScoutSuite about to be run is the pinned, vetted version.

The wrapper drives ``scout`` out of process and never imports it, so it cannot
assume that whatever ``scout`` is on ``PATH`` is the version this distribution
pinned and vetted. A newer, older, or modified ScoutSuite can ship different
rules or behaviour and silently weaken an audit. This module runs a fail-closed
preflight: resolve the ``scout`` executable, ask it its version (out of
process), and require it to match the pinned version before any audit runs.

Two complementary layers of integrity:

* **install-time artifact hash** — ``pip install --require-hashes -r
  requirements.lock`` guarantees the *installed files* are the exact PyPI
  artifacts this distribution pinned;
* **run-time version gate** (this module) — confirms the *executed* ``scout`` is
  that pinned version, even when ScoutSuite lives in a separate environment or
  is supplied via ``--scout-bin``.

Pure stdlib, deterministic, and unit-testable without ScoutSuite installed (the
subprocess that reads ``scout --version`` is injectable).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from importlib import metadata

from .errors import ScoutIntegrityError

#: Fallback pin if our own package metadata can't be read (see :func:`pinned_version`).
PINNED_SCOUTSUITE_VERSION = "5.14.0"

_OWN_DISTRIBUTION = "presidio-hardened-scoutsuite"
#: Matches the ``scoutsuite`` extra's pin, e.g. ``ScoutSuite==5.14.0; extra == "scoutsuite"``.
_REQUIRES_RE = re.compile(r"ScoutSuite\s*==\s*([0-9][^\s;]*)", re.IGNORECASE)
#: First version-looking token in ``scout --version`` output (e.g. "Scout Suite 5.14.0").
_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def pinned_version() -> str:
    """The ScoutSuite version this distribution pins.

    Read from our *own* package metadata (the ``scoutsuite`` extra's
    ``ScoutSuite==`` requirement) so there is a single source of truth and the
    runtime gate can't drift from what the lockfile/extra install. Falls back to
    :data:`PINNED_SCOUTSUITE_VERSION` if the metadata isn't available.
    """

    try:
        for requirement in metadata.requires(_OWN_DISTRIBUTION) or []:
            match = _REQUIRES_RE.search(requirement)
            if match:
                return match.group(1)
    except metadata.PackageNotFoundError:
        pass
    return PINNED_SCOUTSUITE_VERSION


def detect_version(
    scout_bin: str,
    *,
    runner=subprocess.run,
    timeout: float | None = 30,
) -> str | None:
    """Return the version reported by ``scout --version``, or ``None``.

    ``None`` means the executable couldn't be run or printed nothing
    version-shaped. ``runner`` is injectable so this is testable offline.
    """

    try:
        proc = runner(
            [scout_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    match = _VERSION_RE.search(output)
    return match.group(1) if match else None


@dataclass
class ScoutIntegrityResult:
    """Outcome of :func:`verify_scout`."""

    scout_bin: str
    resolved_path: str | None
    detected_version: str | None
    expected_version: str

    @property
    def found(self) -> bool:
        return self.resolved_path is not None

    @property
    def ok(self) -> bool:
        return self.found and self.detected_version == self.expected_version

    @property
    def reason(self) -> str:
        """Human-readable explanation; ``"ok"`` when verified."""

        if not self.found:
            return f"scout executable {self.scout_bin!r} not found on PATH"
        if self.detected_version is None:
            return f"could not determine the version of {self.resolved_path}"
        if not self.ok:
            return (
                f"scout version {self.detected_version} does not match the pinned, vetted "
                f"version {self.expected_version}"
            )
        return "ok"


def verify_scout(
    scout_bin: str = "scout",
    *,
    expected_version: str | None = None,
    runner=subprocess.run,
    timeout: float | None = 30,
    require: bool = True,
) -> ScoutIntegrityResult:
    """Verify the ``scout`` executable matches the pinned ScoutSuite version.

    Resolves ``scout_bin`` (PATH lookup or an explicit path), reads its version
    out of process, and compares it to ``expected_version`` (defaulting to
    :func:`pinned_version`). When ``require`` is true (the default) a mismatch,
    a missing executable, or an undeterminable version raises
    :class:`ScoutIntegrityError`; when false the same conditions are reported on
    the returned :class:`ScoutIntegrityResult` (``ok`` is ``False``) without
    raising — used for the ``--allow-unverified-scout`` warn-and-continue path.
    """

    expected = expected_version or pinned_version()
    resolved = shutil.which(scout_bin)
    detected = detect_version(resolved, runner=runner, timeout=timeout) if resolved else None
    result = ScoutIntegrityResult(scout_bin, resolved, detected, expected)
    if require and not result.ok:
        raise ScoutIntegrityError(result.reason)
    return result
