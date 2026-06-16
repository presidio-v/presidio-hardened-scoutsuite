"""presidio-hardened-scoutsuite — a security-hardened distribution of ScoutSuite.

The public API is intentionally small: build/run a hardened ScoutSuite
invocation, then redact and guard the report. ScoutSuite itself is driven out of
process (see :mod:`presidio_scoutsuite.launcher`) and is never imported here.
"""

from __future__ import annotations

from .attestation import attest_report, build_attestation, verify_attestation
from .config import load_settings, resolve, validate_file
from .credentials import CredentialCheck, assert_short_lived, inspect_credentials
from .diff import DiffResult, diff_reports, load_and_diff
from .errors import (
    AttestationError,
    ConfigError,
    CredentialError,
    FindingsError,
    LauncherError,
    PresidioScoutError,
    ProvenanceVerificationError,
    RedactionError,
    ReportGuardError,
    ReportVerificationError,
    RulesetValidationError,
    ScoutIntegrityError,
    VulnerabilityError,
    WaiverError,
)
from .findings import Finding, FindingsReport, load_report
from .launcher import LaunchPlan, build_plan, run, scrub_env, validate_passthrough
from .manifest import build_manifest
from .provenance import Provenance, ProvenancePolicy, load_statement
from .redact import assert_clean, redact_report_dir, redact_text, scan
from .report_guard import GuardResult, guard_report
from .ruleset import (
    available_rules,
    missing_rules,
    referenced_rules,
    validate_all,
    validate_provider,
)
from .sarif import to_sarif
from .scout_integrity import ScoutIntegrityResult, pinned_version, verify_scout
from .verify import VerifyResult, verify_report
from .version import __version__
from .vuln import Vuln, VulnReport, parse_report
from .waivers import Waiver, apply_waivers, load_waivers

__all__ = [
    "__version__",
    "PresidioScoutError",
    "LauncherError",
    "CredentialError",
    "ConfigError",
    "RedactionError",
    "ReportGuardError",
    "ReportVerificationError",
    "ProvenanceVerificationError",
    "ScoutIntegrityError",
    "FindingsError",
    "WaiverError",
    "AttestationError",
    "VulnerabilityError",
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
    "Provenance",
    "ProvenancePolicy",
    "load_statement",
    "ScoutIntegrityResult",
    "verify_scout",
    "pinned_version",
    "Finding",
    "FindingsReport",
    "load_report",
    "to_sarif",
    "Waiver",
    "load_waivers",
    "apply_waivers",
    "build_attestation",
    "attest_report",
    "verify_attestation",
    "DiffResult",
    "diff_reports",
    "load_and_diff",
    "CredentialCheck",
    "inspect_credentials",
    "assert_short_lived",
    "Vuln",
    "VulnReport",
    "parse_report",
    "load_settings",
    "resolve",
    "validate_file",
    "referenced_rules",
    "available_rules",
    "missing_rules",
    "validate_provider",
    "validate_all",
]
