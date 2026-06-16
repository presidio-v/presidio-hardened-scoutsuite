"""Verify SLSA build provenance against this distribution's expected policy.

The release pipeline attaches **SLSA provenance** to the published artifacts
(``provenance: mode=max`` for the container image; PyPI attestations for the
wheel). A signature proves the attestation is authentic, but it does *not* tell
you *what* was built or *by whom* — you still have to check the provenance
*says the right thing*: built by this repo's GitHub Actions, from this source
repository, for the digest you're about to pull. Skipping that check is the most
common way provenance verification gives false assurance.

This module is that policy gate. It is deliberately split from cryptographic
verification:

* **signature / transparency-log verification** is done by ``cosign
  verify-attestation`` (Fulcio + Rekor) — heavy crypto, network, and trust-root
  machinery that belongs in cosign, not re-implemented here;
* **policy verification** — does the *verified* statement attest the expected
  builder, source, predicate type, and artifact digest? — is owned here:
  pure-stdlib, deterministic, fail-closed, and unit-testable offline.

Typical use::

    cosign verify-attestation --type slsaprovenance \\
        --certificate-identity-regexp '^https://github.com/presidio-v/.*' \\
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
        ghcr.io/presidio-v/presidio-hardened-scoutsuite@sha256:DIGEST \\
        --output text > prov.jsonl
    presidio-scout-verify-provenance prov.jsonl --digest sha256:DIGEST

Both SLSA provenance ``v0.2`` and ``v1`` predicates are understood.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .errors import ProvenanceVerificationError

#: Bundled default policy (overridable via CLI flags).
_POLICY_FILE = "provenance-policy.json"

_STATEMENT_TYPES = frozenset(
    {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}
)


def _policy_resource(name: str) -> Path:
    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


@dataclass(frozen=True)
class ProvenancePolicy:
    """The expectations a provenance statement must satisfy."""

    expected_source_uri: str
    builder_id_prefixes: tuple[str, ...]
    allowed_predicate_types: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> ProvenancePolicy:
        try:
            return cls(
                expected_source_uri=str(data["expected_source_uri"]),
                builder_id_prefixes=tuple(data["builder_id_prefixes"]),
                allowed_predicate_types=tuple(data["allowed_predicate_types"]),
            )
        except (KeyError, TypeError) as exc:
            raise ProvenanceVerificationError(f"malformed provenance policy: {exc}") from exc

    @classmethod
    def bundled(cls) -> ProvenancePolicy:
        return cls.from_dict(json.loads(_policy_resource(_POLICY_FILE).read_text(encoding="utf-8")))


def _normalize_uri(uri: str) -> str:
    """Canonicalize a source URI for comparison.

    Strips a leading VCS scheme (``git+``), any ``@ref`` / ``#ref`` suffix, a
    trailing ``.git``, and a trailing slash, so the many spellings SLSA tools
    emit for the same repo compare equal.
    """

    value = uri.strip()
    if value.startswith("git+"):
        value = value[4:]
    for sep in ("@", "#"):
        if sep in value:
            value = value.split(sep, 1)[0]
    if value.endswith(".git"):
        value = value[:-4]
    return value.rstrip("/")


@dataclass
class Provenance:
    """A parsed in-toto/SLSA provenance statement."""

    statement: dict

    @property
    def predicate(self) -> dict:
        pred = self.statement.get("predicate")
        return pred if isinstance(pred, dict) else {}

    @property
    def predicate_type(self) -> str:
        return str(self.statement.get("predicateType", ""))

    @property
    def subject_digests(self) -> set[str]:
        """All ``alg:hex`` digests named in the statement subject."""

        digests: set[str] = set()
        for entry in self.statement.get("subject", []) or []:
            if isinstance(entry, dict):
                for alg, value in (entry.get("digest") or {}).items():
                    digests.add(f"{alg}:{value}")
        return digests

    @property
    def builder_id(self) -> str:
        """Builder identity, across SLSA v0.2 (``builder``) and v1 (``runDetails``)."""

        pred = self.predicate
        for path in (("builder", "id"), ("runDetails", "builder", "id")):
            node: object = pred
            for key in path:
                node = node.get(key, {}) if isinstance(node, dict) else {}
            if isinstance(node, str) and node:
                return node
        return ""

    @property
    def source_uri(self) -> str:
        """Best-effort source-repository URI, across v0.2 and v1 layouts."""

        pred = self.predicate
        # SLSA v0.2: invocation.configSource.uri, else first material uri.
        config = pred.get("invocation", {}).get("configSource", {})
        if isinstance(config, dict) and config.get("uri"):
            return str(config["uri"])
        materials = pred.get("materials")
        if (
            isinstance(materials, list)
            and materials
            and isinstance(materials[0], dict)
            and materials[0].get("uri")
        ):
            return str(materials[0]["uri"])
        # SLSA v1: buildDefinition.externalParameters / resolvedDependencies.
        build_def = pred.get("buildDefinition", {})
        if isinstance(build_def, dict):
            ext = build_def.get("externalParameters", {})
            if isinstance(ext, dict):
                workflow = ext.get("workflow", {})
                if isinstance(workflow, dict) and workflow.get("repository"):
                    return str(workflow["repository"])
            deps = build_def.get("resolvedDependencies")
            if isinstance(deps, list) and deps and isinstance(deps[0], dict) and deps[0].get("uri"):
                return str(deps[0]["uri"])
        return ""


def _extract_statement(obj: object) -> dict | None:
    """Recursively locate an in-toto statement inside a decoded JSON value.

    Handles a bare statement (a dict with ``predicateType``), a DSSE envelope
    (decoding its base64 ``payload``), and arbitrarily nested forms such as the
    array ``gh attestation verify --format json`` emits (each element wrapping a
    sigstore bundle around the statement).
    """

    if isinstance(obj, dict):
        if "predicateType" in obj:
            return obj
        payload = obj.get("payload")
        if isinstance(payload, str):
            try:
                decoded = json.loads(base64.b64decode(payload))
            except (ValueError, TypeError):
                decoded = None
            if isinstance(decoded, dict) and "predicateType" in decoded:
                return decoded
        for value in obj.values():
            found = _extract_statement(value)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _extract_statement(item)
            if found is not None:
                return found
    return None


def load_statement(data: str | bytes) -> Provenance:
    """Parse a provenance statement from raw text.

    Accepts a bare in-toto Statement, a DSSE envelope (``{"payload": "<base64>",
    "payloadType": …}``), a line of cosign's JSON-Lines ``verify-attestation``
    output, or the JSON array ``gh attestation verify --format json`` emits — the
    in-toto statement is located in any of these.
    """

    text = data.decode("utf-8") if isinstance(data, bytes) else data
    text = text.strip()
    if not text:
        raise ProvenanceVerificationError("empty provenance input")

    # Whole-document JSON (bare statement, DSSE envelope, or a gh/cosign JSON
    # array); fall back to the first non-empty line for cosign's JSON-Lines text.
    try:
        obj: object = json.loads(text)
    except ValueError:
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        try:
            obj = json.loads(first)
        except ValueError as exc:
            raise ProvenanceVerificationError(f"provenance is not valid JSON: {exc}") from exc

    # A lone DSSE envelope with an undecodable payload is a clear, common error.
    if isinstance(obj, dict) and "predicateType" not in obj and isinstance(obj.get("payload"), str):
        try:
            json.loads(base64.b64decode(obj["payload"]))
        except (ValueError, TypeError) as exc:
            raise ProvenanceVerificationError(f"cannot decode DSSE payload: {exc}") from exc

    statement = _extract_statement(obj)
    if statement is None:
        raise ProvenanceVerificationError(
            "input is not an in-toto provenance statement (no predicateType)"
        )
    if statement.get("_type") and statement["_type"] not in _STATEMENT_TYPES:
        raise ProvenanceVerificationError(f"unsupported statement type {statement['_type']!r}")
    return Provenance(statement=statement)


@dataclass
class VerifyResult:
    """Outcome of :func:`verify`. ``ok`` is true only when ``errors`` is empty."""

    builder_id: str = ""
    source_uri: str = ""
    predicate_type: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def verify(
    prov: Provenance,
    *,
    artifact_digest: str | None = None,
    policy: ProvenancePolicy | None = None,
) -> VerifyResult:
    """Check ``prov`` against ``policy`` (the bundled policy by default).

    Collects every policy violation into :class:`VerifyResult` rather than
    stopping at the first, so an operator sees the whole picture. ``ok`` is
    ``False`` if anything failed. ``artifact_digest`` (``alg:hex``), when given,
    must appear in the statement's subject.
    """

    policy = policy or ProvenancePolicy.bundled()
    result = VerifyResult(
        builder_id=prov.builder_id,
        source_uri=prov.source_uri,
        predicate_type=prov.predicate_type,
    )

    if prov.predicate_type not in policy.allowed_predicate_types:
        result.errors.append(
            f"predicate type {prov.predicate_type!r} is not allowed "
            f"(expected one of {', '.join(policy.allowed_predicate_types)})"
        )

    if not any(prov.builder_id.startswith(p) for p in policy.builder_id_prefixes):
        result.errors.append(
            f"builder id {prov.builder_id!r} does not match any trusted prefix "
            f"({', '.join(policy.builder_id_prefixes)})"
        )

    if _normalize_uri(prov.source_uri) != _normalize_uri(policy.expected_source_uri):
        result.errors.append(
            f"source uri {prov.source_uri!r} does not match expected {policy.expected_source_uri!r}"
        )

    if artifact_digest is not None and artifact_digest not in prov.subject_digests:
        present = ", ".join(sorted(prov.subject_digests)) or "none"
        result.errors.append(
            f"artifact digest {artifact_digest} not attested by this provenance "
            f"(subject digests: {present})"
        )

    return result


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-verify-provenance",
        description=(
            "Verify a SLSA build-provenance statement against this distribution's "
            "expected policy (builder, source repo, predicate type, artifact "
            "digest). Run AFTER cosign verify-attestation has checked the "
            "signature; this is the policy gate, not signature verification."
        ),
    )
    parser.add_argument(
        "statement",
        help="path to the provenance statement (in-toto, DSSE, or cosign output); - for stdin",
    )
    parser.add_argument(
        "--digest",
        help="artifact digest (alg:hex) that the provenance must attest",
    )
    parser.add_argument(
        "--source-uri",
        help="override the expected source repository URI",
    )
    parser.add_argument(
        "--builder-id-prefix",
        action="append",
        dest="builder_id_prefixes",
        help="override the trusted builder-id prefixes (repeatable)",
    )
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.statement == "-" else Path(args.statement).read_text("utf-8")

    try:
        prov = load_statement(raw)
        policy = ProvenancePolicy.bundled()
        if args.source_uri:
            policy = ProvenancePolicy(
                expected_source_uri=args.source_uri,
                builder_id_prefixes=policy.builder_id_prefixes,
                allowed_predicate_types=policy.allowed_predicate_types,
            )
        if args.builder_id_prefixes:
            policy = ProvenancePolicy(
                expected_source_uri=policy.expected_source_uri,
                builder_id_prefixes=tuple(args.builder_id_prefixes),
                allowed_predicate_types=policy.allowed_predicate_types,
            )
        result = verify(prov, artifact_digest=args.digest, policy=policy)
    except ProvenanceVerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if result.ok:
        print(
            f"ok   provenance verified: built by {result.builder_id} "
            f"from {result.source_uri} ({result.predicate_type})"
        )
        return 0
    for err in result.errors:
        print(f"FAIL {err}", file=sys.stderr)
    return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
