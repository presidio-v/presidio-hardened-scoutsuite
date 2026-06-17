"""presidio-hardened-scoutsuite — a security-hardened distribution of ScoutSuite.

The public API is intentionally small: build/run a hardened ScoutSuite
invocation, then redact and guard the report. ScoutSuite itself is driven out of
process (see :mod:`presidio_scoutsuite.launcher`) and is never imported here.
"""

from __future__ import annotations

from .asff import to_asff
from .assertions import Assertion, AssertionResult, PolicyReport, evaluate, load_policy
from .attestation import attest_report, build_attestation, verify_attestation
from .compliance import (
    ComplianceMapping,
    ComplianceReport,
    build_report,
    load_mapping,
    validate_mapping,
)
from .compose import compose_baseline, parse_redaction_patterns, validate_extensions
from .config import load_settings, read_raw, resolve, validate_file
from .credentials import CredentialCheck, assert_short_lived, inspect_credentials
from .diff import DiffResult, diff_reports, load_and_diff
from .errors import (
    AsffError,
    AttestationError,
    ComplianceError,
    ConfigError,
    CredentialError,
    EvidenceError,
    ExtensionError,
    FindingsError,
    LauncherError,
    NotificationError,
    OrchestrationError,
    PolicyError,
    PresidioScoutError,
    ProvenanceVerificationError,
    RedactionError,
    RemediationError,
    ReportGuardError,
    ReportVerificationError,
    RulesetValidationError,
    ScoutIntegrityError,
    TrendError,
    UpgradeError,
    VulnerabilityError,
    WaiverError,
)
from .evidence import (
    EvidenceRef,
    ItemMap,
    build_evidence,
    emit_report,
    load_item_map,
    load_trust_store,
    validate_item_map,
    verify_ref,
)
from .extensions import (
    Exporter,
    Redactor,
    Sink,
    discover,
    installed_redactor_patterns,
    load_object,
)
from .findings import Finding, FindingsReport, load_report
from .launcher import LaunchPlan, build_plan, run, scrub_env, validate_passthrough
from .manifest import build_manifest
from .notify import build_summary, deliver, render_text, resolve_sink
from .orchestrate import (
    OrchestrationReport,
    Target,
    TargetResult,
    load_targets,
    run_all,
    run_target,
)
from .provenance import Provenance, ProvenancePolicy, load_statement
from .redact import assert_clean, redact_report_dir, redact_text, scan
from .remediation import Remediation, load_remediation, remediation_for, validate_remediation
from .report_guard import GuardResult, guard_report
from .ruleset import (
    available_rules,
    missing_rules,
    referenced_rules,
    regenerate_manifest,
    render_manifest,
    validate_all,
    validate_provider,
)
from .sarif import to_sarif
from .scout_integrity import ScoutIntegrityResult, pinned_version, verify_scout
from .summary import build as build_summary_report
from .summary import build_fleet, render_html, render_markdown
from .trend import Comparison, Snapshot, compare, load_history, record, snapshot
from .upgrade import (
    CoherenceReport,
    Pin,
    UpgradePlan,
    apply_text_pins,
    check_coherence,
    discover_pins,
    plan_upgrade,
)
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
    "ExtensionError",
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
    "ComplianceError",
    "AsffError",
    "OrchestrationError",
    "NotificationError",
    "PolicyError",
    "TrendError",
    "RemediationError",
    "UpgradeError",
    "EvidenceError",
    "EvidenceRef",
    "ItemMap",
    "build_evidence",
    "emit_report",
    "load_item_map",
    "validate_item_map",
    "verify_ref",
    "load_trust_store",
    "Assertion",
    "AssertionResult",
    "PolicyReport",
    "load_policy",
    "evaluate",
    "Remediation",
    "load_remediation",
    "validate_remediation",
    "remediation_for",
    "Snapshot",
    "Comparison",
    "snapshot",
    "compare",
    "record",
    "load_history",
    "Redactor",
    "Exporter",
    "Sink",
    "discover",
    "load_object",
    "installed_redactor_patterns",
    "build_summary_report",
    "build_fleet",
    "render_markdown",
    "render_html",
    "build_summary",
    "render_text",
    "resolve_sink",
    "deliver",
    "Target",
    "TargetResult",
    "OrchestrationReport",
    "load_targets",
    "run_target",
    "run_all",
    "ComplianceMapping",
    "ComplianceReport",
    "load_mapping",
    "validate_mapping",
    "build_report",
    "to_asff",
    "Pin",
    "CoherenceReport",
    "UpgradePlan",
    "discover_pins",
    "check_coherence",
    "plan_upgrade",
    "apply_text_pins",
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
    "read_raw",
    "parse_redaction_patterns",
    "compose_baseline",
    "validate_extensions",
    "referenced_rules",
    "available_rules",
    "missing_rules",
    "validate_provider",
    "validate_all",
    "render_manifest",
    "regenerate_manifest",
]
