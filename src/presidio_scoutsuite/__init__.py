"""presidio-hardened-scoutsuite — a security-hardened distribution of ScoutSuite.

The public API is intentionally small: build/run a hardened ScoutSuite
invocation, then redact and guard the report. ScoutSuite itself is driven out of
process (see :mod:`presidio_scoutsuite.launcher`) and is never imported here.
"""

from __future__ import annotations

from .errors import (
    LauncherError,
    PresidioScoutError,
    RedactionError,
    ReportGuardError,
    ReportVerificationError,
    RulesetValidationError,
)
from .launcher import LaunchPlan, build_plan, run, scrub_env, validate_passthrough
from .manifest import build_manifest
from .redact import assert_clean, redact_report_dir, redact_text, scan
from .report_guard import GuardResult, guard_report
from .ruleset import (
    available_rules,
    missing_rules,
    referenced_rules,
    validate_all,
    validate_provider,
)
from .verify import VerifyResult, verify_report
from .version import __version__

__all__ = [
    "__version__",
    "PresidioScoutError",
    "LauncherError",
    "RedactionError",
    "ReportGuardError",
    "ReportVerificationError",
    "RulesetValidationError",
    "LaunchPlan",
    "build_plan",
    "run",
    "scrub_env",
    "validate_passthrough",
    "redact_text",
    "scan",
    "assert_clean",
    "redact_report_dir",
    "GuardResult",
    "guard_report",
    "build_manifest",
    "VerifyResult",
    "verify_report",
    "referenced_rules",
    "available_rules",
    "missing_rules",
    "validate_provider",
    "validate_all",
]
