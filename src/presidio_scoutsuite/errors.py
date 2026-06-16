"""Exception hierarchy for presidio-hardened-scoutsuite.

All errors derive from :class:`PresidioScoutError` so callers can catch the
whole family with a single ``except``.
"""

from __future__ import annotations


class PresidioScoutError(Exception):
    """Base class for every error raised by this package."""


class LauncherError(PresidioScoutError):
    """The requested ScoutSuite invocation is invalid or would weaken the
    hardened posture (bad provider, disallowed pass-through flag, etc.)."""


class RedactionError(PresidioScoutError):
    """A secret was detected in output that must be clean.

    Raised by the fail-closed redaction guard when a credential survives into
    a report/log that the caller asked to be verified clean.
    """


class ReportGuardError(PresidioScoutError):
    """The generated report failed an integrity or sanitization check."""


class ReportVerificationError(PresidioScoutError):
    """A report could not be verified against its integrity manifest.

    Raised when the manifest is missing/unreadable, has been tampered with
    (its self-digest or signature does not match), or the report's files no
    longer hash to the values the manifest records (modified, added, or
    removed files).
    """


class FindingsError(PresidioScoutError):
    """The ScoutSuite results data could not be located or parsed.

    Raised when no ``scoutsuite_results*.js`` data file is found under a report
    directory, or its embedded JSON can't be decoded — so a ``--fail-on-finding``
    gate can never silently pass on a report it couldn't actually evaluate.
    """


class ScoutIntegrityError(PresidioScoutError):
    """The ScoutSuite about to be run is not the pinned, vetted version.

    Raised by the fail-closed preflight when the ``scout`` executable can't be
    found, its version can't be determined, or its version does not match the
    one this distribution pins — so an unvetted or modified ScoutSuite (which
    could ship different rules or behaviour) can't silently weaken an audit.
    Bypass with ``--allow-unverified-scout``.
    """


class ProvenanceVerificationError(PresidioScoutError):
    """A build-provenance attestation failed policy verification.

    Raised when a SLSA provenance statement does not attest the expected
    builder, source repository, predicate type, or artifact digest — i.e. the
    artifact you are about to pull was not built the way this distribution
    requires. This is a *policy* check run after the attestation's signature has
    already been cryptographically verified (e.g. by ``cosign verify-attestation``).
    """


class RulesetValidationError(PresidioScoutError):
    """A curated ruleset references rule names the pinned ScoutSuite does not
    provide.

    Raised when a bundled baseline points at a finding rule that is missing from
    the upstream rule inventory — a typo or upstream rename that would otherwise
    make ScoutSuite silently ignore the rule and weaken the audit.
    """
