"""Build, canonicalize, and (optionally) sign a report integrity manifest.

The report guard records a SHA-256 over every file in a finished report so the
report can be integrity-checked later, offline, by :mod:`presidio_scoutsuite.verify`.
This module is the single source of truth for the manifest's *shape* and its
two tamper-evidence layers:

* **self-digest** — a SHA-256 over the canonical, security-relevant content of
  the manifest (the algorithm + the sorted per-file hashes). It lets a verifier
  detect edits to the recorded hashes themselves, independent of any signature.
* **signature** (optional) — an HMAC-SHA256 over that same canonical content,
  keyed by :data:`HMAC_ENV_VAR`. This is a *symmetric* signature: it proves the
  manifest was produced by a holder of the shared pipeline key (e.g. the same
  CI that ran the audit), not non-repudiation. For distribution / third-party
  verification, sign the manifest *file* out of band with cosign
  (``cosign sign-blob``), exactly as the release pipeline signs images.

Everything here is pure stdlib and deterministic: the canonical payload omits
informational metadata (timestamp, generator) so the digest and signature
depend only on the report's contents, not on when or where it was guarded.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from datetime import datetime, timezone

from .version import __version__

#: Name of the manifest written into the report directory. Excluded from its
#: own file inventory (a file cannot hash itself).
MANIFEST_FILENAME = "presidio-report-manifest.json"

#: Schema identifier; bump the version suffix on any breaking shape change.
MANIFEST_SCHEMA = "presidio-scout/report-manifest/v1"

#: Per-file content hash algorithm.
HASH_ALGORITHM = "sha256"

#: Signature algorithm used when a key is supplied.
SIGNATURE_ALGORITHM = "HMAC-SHA256"

#: Environment variable holding the (symmetric) signing key, if any.
HMAC_ENV_VAR = "PRESIDIO_MANIFEST_HMAC_KEY"


def canonical_payload(algorithm: str, files: Mapping[str, str]) -> bytes:
    """Return the canonical bytes the digest and signature are computed over.

    Only the security-relevant content is included — the hash algorithm and the
    file→hash map, with keys sorted and whitespace stripped — so the result is
    byte-stable regardless of insertion order or surrounding metadata.
    """

    payload = {"algorithm": algorithm, "files": dict(sorted(files.items()))}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_digest(algorithm: str, files: Mapping[str, str]) -> str:
    """SHA-256 over :func:`canonical_payload` — the manifest's self-digest."""

    return hashlib.sha256(canonical_payload(algorithm, files)).hexdigest()


def sign(algorithm: str, files: Mapping[str, str], key: bytes) -> str:
    """HMAC-SHA256 of the canonical payload, keyed by ``key`` (hex digest)."""

    return hmac.new(key, canonical_payload(algorithm, files), hashlib.sha256).hexdigest()


def hmac_key_from_env(env: Mapping[str, str] | None = None) -> bytes | None:
    """Return the configured signing key from the environment, or ``None``.

    The key is read from :data:`HMAC_ENV_VAR`; surrounding whitespace is
    stripped and a value that is empty after stripping is treated as unset.
    """

    raw = (env if env is not None else os.environ).get(HMAC_ENV_VAR, "")
    raw = raw.strip()
    return raw.encode("utf-8") if raw else None


def build_manifest(
    files: Mapping[str, str],
    *,
    generated_at: datetime | None = None,
    sign_key: bytes | None = None,
) -> dict:
    """Assemble the manifest document for a mapping of ``relpath -> sha256``.

    ``generated_at`` defaults to the current UTC time and is informational only
    (it is *not* covered by the digest/signature, so it never affects
    verification). When ``sign_key`` is provided an HMAC ``signature`` block is
    attached.
    """

    when = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ordered = dict(sorted(files.items()))
    document = {
        "schema": MANIFEST_SCHEMA,
        "generator": "presidio-hardened-scoutsuite",
        "version": __version__,
        "generated_at": when.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "algorithm": HASH_ALGORITHM,
        "file_count": len(ordered),
        "content_digest": content_digest(HASH_ALGORITHM, ordered),
        "files": ordered,
    }
    if sign_key is not None:
        document["signature"] = {
            "algorithm": SIGNATURE_ALGORITHM,
            "value": sign(HASH_ALGORITHM, ordered, sign_key),
        }
    return document
