"""Build and verify a signed-able **run attestation** for an audit.

The earlier layers each attest one thing: the report manifest (0.3) records what
the report *contains*; ``presidio-scout-verify`` (0.3) proves the report still
matches it; the SLSA verifier (0.4) checks how the *artifacts* were built; the
integrity gate (0.5) checks *which* ScoutSuite ran. This module ties them
together into one statement about the *audit run itself*: an in-toto v1
attestation whose **subject is the report's integrity manifest** and whose
predicate records the run's inputs — provider, the curated ruleset's digest, the
verified ScoutSuite version, this wrapper's version, and the manifest's own
content digest (plus optional finding counts).

That chain is what makes it meaningful: report files → manifest (verified by
``presidio-scout-verify``) → this attestation's subject (sha256 of the manifest)
→ a detached signature (``cosign sign-blob`` over the statement). Anyone can then
confirm *this exact report was produced by this provider, with this ruleset, by
this vetted ScoutSuite* — not merely that some report exists.

Pure stdlib, deterministic, offline-testable. Signing is delegated to cosign
(same keyless model as the release images); this module produces and verifies
the *statement*.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import manifest as manifest_mod
from .errors import AttestationError
from .scout_integrity import pinned_version
from .version import __version__

#: in-toto statement + this distribution's run-attestation predicate type.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://presidio-v.github.io/presidio-hardened-scoutsuite/scout-run/v1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(report_dir: Path) -> tuple[Path, dict]:
    manifest_path = report_dir / manifest_mod.MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise AttestationError(f"no integrity manifest at {manifest_path}; guard the report first")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AttestationError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if not isinstance(document, dict) or "content_digest" not in document:
        raise AttestationError(f"manifest {manifest_path} is malformed")
    return manifest_path, document


def build_attestation(
    *,
    manifest_path: Path,
    manifest_document: dict,
    provider: str,
    scoutsuite_version: str | None,
    ruleset_path: str | Path | None = None,
    findings: dict[str, int] | None = None,
    wrapper_version: str = __version__,
    created: datetime | None = None,
) -> dict:
    """Assemble the in-toto run-attestation statement.

    The subject is the report's integrity manifest file (by SHA-256); the
    predicate records the run's inputs and the manifest's own content digest.
    The statement is meant to be signed as a whole (e.g. ``cosign sign-blob``).
    """

    when = (created or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ruleset_block: dict | None = None
    if ruleset_path is not None:
        rpath = Path(ruleset_path)
        if not rpath.is_file():
            raise AttestationError(f"ruleset {rpath} does not exist")
        ruleset_block = {"name": rpath.name, "sha256": _sha256_file(rpath)}

    predicate: dict = {
        "provider": provider,
        "wrapperVersion": wrapper_version,
        "scoutsuiteVersion": scoutsuite_version,
        "ruleset": ruleset_block,
        "reportManifest": {
            "algorithm": manifest_document.get("algorithm", manifest_mod.HASH_ALGORITHM),
            "contentDigest": manifest_document["content_digest"],
            "fileCount": manifest_document.get("file_count"),
        },
        "createdAt": when.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if findings is not None:
        predicate["findings"] = dict(sorted(findings.items()))

    return {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": [
            {"name": manifest_path.name, "digest": {"sha256": _sha256_file(manifest_path)}}
        ],
        "predicate": predicate,
    }


def attest_report(
    report_dir: str | Path,
    *,
    provider: str,
    scoutsuite_version: str | None = None,
    ruleset_path: str | Path | None = None,
    findings: dict[str, int] | None = None,
    created: datetime | None = None,
) -> dict:
    """Build a run attestation from a finished, guarded report directory."""

    root = Path(report_dir)
    manifest_path, document = _read_manifest(root)
    return build_attestation(
        manifest_path=manifest_path,
        manifest_document=document,
        provider=provider,
        scoutsuite_version=scoutsuite_version,
        ruleset_path=ruleset_path,
        findings=findings,
        created=created,
    )


@dataclass
class AttestationResult:
    """Outcome of :func:`verify_attestation`."""

    provider: str = ""
    scoutsuite_version: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def verify_attestation(report_dir: str | Path, statement: dict) -> AttestationResult:
    """Check a run attestation against the report it claims to describe.

    Confirms the statement's predicate type, that its subject digest matches the
    report's on-disk integrity manifest, and that the recorded manifest content
    digest matches the manifest itself. (Signature verification is cosign's job;
    this is the policy/binding check, like :mod:`presidio_scoutsuite.provenance`.)
    """

    root = Path(report_dir)
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    result = AttestationResult(
        provider=str((predicate or {}).get("provider", "")),
        scoutsuite_version=(predicate or {}).get("scoutsuiteVersion"),
    )

    if statement.get("predicateType") != PREDICATE_TYPE:
        result.errors.append(
            f"predicate type {statement.get('predicateType')!r} is not {PREDICATE_TYPE!r}"
        )

    try:
        manifest_path, document = _read_manifest(root)
    except AttestationError as exc:
        result.errors.append(str(exc))
        return result

    actual_digest = _sha256_file(manifest_path)
    subjects = statement.get("subject") or []
    attested = {s.get("digest", {}).get("sha256") for s in subjects if isinstance(s, dict)}
    if actual_digest not in attested:
        result.errors.append("subject digest does not match the report's integrity manifest")

    recorded = (predicate or {}).get("reportManifest", {}).get("contentDigest")
    if recorded != document.get("content_digest"):
        result.errors.append("attested manifest content digest does not match the manifest")

    return result


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-attest",
        description=(
            "Build or verify an in-toto run attestation binding an audit's inputs "
            "to its report integrity manifest. Sign the statement with cosign "
            "(sign-blob) for a complete, verifiable record."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="build a run attestation for a report")
    gen.add_argument("report_dir", help="path to a finished, guarded report directory")
    gen.add_argument("--provider", required=True, help="cloud provider that was audited")
    gen.add_argument("--scout-version", help="ScoutSuite version (default: the pinned version)")
    gen.add_argument("--ruleset", help="path to the ruleset used (recorded by digest)")
    gen.add_argument("-o", "--output", help="write to this file instead of stdout")

    ver = sub.add_parser("verify", help="verify a run attestation against a report")
    ver.add_argument("report_dir", help="path to the guarded report directory")
    ver.add_argument("statement", help="path to the attestation statement JSON; - for stdin")

    args = parser.parse_args(argv)

    if args.command == "generate":
        try:
            statement = attest_report(
                args.report_dir,
                provider=args.provider,
                scoutsuite_version=args.scout_version or pinned_version(),
                ruleset_path=args.ruleset,
            )
        except AttestationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        text = json.dumps(statement, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"wrote run attestation to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0

    raw = sys.stdin.read() if args.statement == "-" else Path(args.statement).read_text("utf-8")
    try:
        statement = json.loads(raw)
    except ValueError as exc:
        print(f"error: attestation is not valid JSON: {exc}", file=sys.stderr)
        return 2
    result = verify_attestation(args.report_dir, statement)
    if result.ok:
        print(
            f"ok   run attestation verified: provider={result.provider} "
            f"scoutsuite={result.scoutsuite_version}"
        )
        return 0
    for err in result.errors:
        print(f"FAIL {err}", file=sys.stderr)
    return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
