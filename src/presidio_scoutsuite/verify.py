"""Verify a hardened report against its integrity manifest, offline.

:mod:`presidio_scoutsuite.report_guard` writes ``presidio-report-manifest.json``
into every report directory. This module re-reads that manifest and checks the
report still matches it — no ScoutSuite, no network, no extra dependencies:

* the manifest's own **self-digest** is recomputed and compared, so an edit to
  the recorded hashes is caught;
* the optional **HMAC signature** is verified when a key is available;
* every file is re-hashed and compared, surfacing **modified**, **missing**, and
  **added** files.

Exposed as the ``presidio-scout-verify`` console script (exit ``0`` verified,
``3`` tampered/mismatch, ``2`` no usable manifest).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest
from .errors import ReportVerificationError

#: Signature states. ``unverified`` means a signature is present but the
#: verifier has no key to check it (integrity is still confirmed by the hashes).
SIG_OK = "ok"
SIG_ABSENT = "absent"
SIG_UNVERIFIED = "unverified"
SIG_BAD = "bad"


@dataclass
class VerifyResult:
    """Outcome of :func:`verify_report`."""

    report_dir: Path
    manifest_path: Path
    content_digest_ok: bool = True
    signature: str = SIG_ABSENT
    verified_count: int = 0
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing tamper-relevant differs from the manifest.

        An ``unverified`` signature does not fail verification — the file
        hashes and self-digest already establish integrity — but a ``bad``
        one does.
        """

        return (
            self.content_digest_ok
            and self.signature != SIG_BAD
            and not self.modified
            and not self.missing
            and not self.added
        )


def _load_manifest(report_dir: Path) -> tuple[Path, dict]:
    manifest_path = report_dir / manifest.MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise ReportVerificationError(
            f"no integrity manifest at {manifest_path}; report was not guarded "
            "(or the manifest was removed)"
        )
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportVerificationError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("files"), dict):
        raise ReportVerificationError(f"manifest {manifest_path} is malformed")
    algorithm = document.get("algorithm")
    if algorithm != manifest.HASH_ALGORITHM:
        raise ReportVerificationError(
            f"manifest {manifest_path} uses unsupported hash algorithm {algorithm!r}"
        )
    return manifest_path, document


def _check_signature(document: dict, files: Mapping[str, str], key: bytes | None) -> str:
    signature = document.get("signature")
    if not signature:
        return SIG_ABSENT
    if key is None:
        return SIG_UNVERIFIED
    expected = manifest.sign(manifest.HASH_ALGORITHM, files, key)
    return SIG_OK if hmac.compare_digest(expected, str(signature.get("value", ""))) else SIG_BAD


def verify_report(report_dir: str | Path, *, key: bytes | None = None) -> VerifyResult:
    """Verify the report under ``report_dir`` against its manifest.

    Raises :class:`ReportVerificationError` only for a missing/malformed
    manifest (there is nothing to verify against); content differences are
    reported on the returned :class:`VerifyResult` instead. ``key`` defaults to
    the :data:`~presidio_scoutsuite.manifest.HMAC_ENV_VAR` environment key.
    """

    root = Path(report_dir)
    if not root.is_dir():
        raise ReportVerificationError(f"report dir {root} does not exist")
    if key is None:
        key = manifest.hmac_key_from_env()

    manifest_path, document = _load_manifest(root)
    recorded: dict[str, str] = document["files"]

    result = VerifyResult(report_dir=root, manifest_path=manifest_path)
    result.content_digest_ok = manifest.content_digest(
        manifest.HASH_ALGORITHM, recorded
    ) == document.get("content_digest")
    result.signature = _check_signature(document, recorded, key)

    on_disk: dict[str, str] = {}
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        rel = str(file.relative_to(root))
        if rel == manifest.MANIFEST_FILENAME:
            continue
        on_disk[rel] = _sha256(file)

    for rel, digest in sorted(recorded.items()):
        if rel not in on_disk:
            result.missing.append(rel)
        elif on_disk[rel] != digest:
            result.modified.append(rel)
    result.added = sorted(set(on_disk) - set(recorded))
    result.verified_count = len(recorded) - len(result.missing) - len(result.modified)
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-verify",
        description=(
            "Verify a hardened ScoutSuite report against its integrity manifest "
            "(presidio-report-manifest.json). Offline; no ScoutSuite required."
        ),
    )
    parser.add_argument("report_dir", help="path to the guarded report directory")
    args = parser.parse_args(argv)

    try:
        result = verify_report(args.report_dir)
    except ReportVerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if result.signature == SIG_BAD:
        print("FAIL manifest signature does not match", file=sys.stderr)
    if not result.content_digest_ok:
        print("FAIL manifest self-digest does not match (manifest was edited)", file=sys.stderr)
    for rel in result.modified:
        print(f"FAIL modified: {rel}", file=sys.stderr)
    for rel in result.missing:
        print(f"FAIL missing:  {rel}", file=sys.stderr)
    for rel in result.added:
        print(f"FAIL added:    {rel}", file=sys.stderr)

    if result.ok:
        note = {
            SIG_OK: " (signature verified)",
            SIG_UNVERIFIED: " (signature present but unverified — no key)",
        }.get(result.signature, "")
        print(f"ok   verified {result.verified_count} file(s) in {result.report_dir}{note}")
        return 0
    return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
