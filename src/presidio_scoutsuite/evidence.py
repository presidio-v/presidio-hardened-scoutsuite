"""Emit signed evidence for clean controls — presidio-evidence producer (0.28.0).

This makes a ScoutSuite audit a **producer** in the ``presidio-hardened-*``
evidence substrate. When a curated control is **clean** in a run (no flagged
finding for any rule mapped to it), this module emits a signed ``EvidenceRef``
(schema ``presidio-hardened/evidence-ref@1``) that a peer **consumer** —
``presidio-hardened-ikigov-assess`` — verifies fail-closed and uses to affirm
its governance checklist items. ScoutSuite is the second producer in the family
(after ``presidio-hardened-ai``); ikigov-assess consumes both.

What a clean control evidences is a deliberate, curated mapping
(``policy/<provider>.evidence.json``, validated fail-closed against the rule
manifest): **T5** = "a security review of the infrastructure and all
dependencies has been conducted and findings addressed"; **O5** = "an audit log
is maintained, stored immutably, and accessible to authorised auditors". A claim
is signed only when *every* rule mapped to its item is clean.

Wire format (must byte-match the consumer and the cross-repo golden vectors in
``presidio-evidence/vectors/``): the detached signature is over
``canonical_json({"content_hash": ..., "signer": ...})`` where ``canonical_json``
is ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)``;
the signer identity is bound into the signed message so a signature cannot be
replayed under another signer. HMAC-SHA256 uses the stdlib; Ed25519 (the secure
default) needs the optional ``[crypto]`` extra. Pure stdlib otherwise, offline,
fail-closed — never imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from . import manifest as manifest_mod
from .errors import EvidenceError, PresidioScoutError
from .findings import FindingsReport, load_report
from .version import __version__

#: Cross-repo wire-format contract identifiers (mirrors presidio-evidence).
SCHEMA_ID = "presidio-hardened/evidence-ref@1"
#: Signature algorithms, secure default first.
SIGNING_ALGORITHMS: tuple[str, ...] = ("ed25519", "hmac-sha256")
#: This producer's identity, recorded as the ref ``source`` and default signer.
SOURCE = "presidio-hardened-scoutsuite"
#: Environment variable carrying the signing key when ``--evidence-key`` is unset.
SIGNING_KEY_ENV = "PRESIDIO_EVIDENCE_SIGNING_KEY"
#: Providers that ship a curated rule→checklist-item map.
MAPPED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "aliyun", "oci")

#: Vendored snapshot of the IKI-Gov checklist item ids (the consumer's
#: ``VALID_ITEM_IDS``). Kept here so emission/verification validate item ids
#: offline without importing the consumer; reconciled when the checklist changes.
VALID_ITEM_IDS: frozenset[str] = frozenset(
    {f"{p}{n}" for p in ("S", "D", "T", "O", "I") for n in range(1, 6)}
)

_CONTRACT_FIELDS = (
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
)
_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
_MAX_STR = 512

_MAPPING_FILES: dict[str, str] = {p: f"{p}.evidence.json" for p in MAPPED_PROVIDERS}


# ── wire format ──────────────────────────────────────────────────────────────
def _canonical(payload: Mapping[str, object]) -> bytes:
    """Strict canonical JSON bytes: sorted keys, compact, UTF-8 preserved."""
    return json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def claim_subject(
    *, item_id: str, provider: str, rules: list[str], report_digest: str
) -> dict[str, object]:
    """The canonical object whose SHA-256 is a clean control's ``content_hash``.

    It binds the checklist item, the provider, the exact set of clean rules, and
    the audited report's integrity-manifest digest, so the claim is reproducible
    and tied to one specific report.
    """
    return {
        "item_id": item_id,
        "provider": provider,
        "rules": sorted(rules),
        "status": "clean",
        "report_manifest_digest": report_digest,
    }


def content_hash(subject: Mapping[str, object]) -> str:
    """SHA-256 (lowercase hex) over the canonical claim subject."""
    return hashlib.sha256(_canonical(subject)).hexdigest()


def _signing_message(content_hash_hex: str, signer: str) -> bytes:
    return _canonical({"content_hash": content_hash_hex, "signer": signer})


def _sign_hmac(content_hash_hex: str, signer: str, key: str) -> str:
    return hmac.new(
        key.encode("utf-8"), _signing_message(content_hash_hex, signer), hashlib.sha256
    ).hexdigest()


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise EvidenceError(
            "Ed25519 evidence signing/verification needs the optional extra: "
            "pip install 'presidio-hardened-scoutsuite[crypto]' (or use "
            "--evidence-alg hmac-sha256)"
        ) from exc
    return ed25519


def _sign_ed25519(content_hash_hex: str, signer: str, private_key_hex: str) -> str:
    ed25519 = _require_crypto()
    try:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise EvidenceError(f"invalid Ed25519 private key: {exc}") from exc
    return sk.sign(_signing_message(content_hash_hex, signer)).hex()


def sign(alg: str, content_hash_hex: str, signer: str, key: str) -> str:
    """Detached signature over ``{content_hash, signer}`` for ``alg`` (wire-format)."""
    if alg == "hmac-sha256":
        return _sign_hmac(content_hash_hex, signer, key)
    if alg == "ed25519":
        return _sign_ed25519(content_hash_hex, signer, key)
    raise EvidenceError(f"unknown signing algorithm {alg!r}; expected one of {SIGNING_ALGORITHMS}")


# ── evidence refs & envelopes ────────────────────────────────────────────────
@dataclass(frozen=True)
class EvidenceRef:
    """One signed evidence reference (the 8 frozen contract fields, in order)."""

    item_id: str
    source: str
    source_version: str
    ledger_ref: str
    content_hash: str
    signer: str
    signature: str
    claimed_at: str

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _CONTRACT_FIELDS}


def _str_field(raw: Mapping[str, object], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value or len(value) > _MAX_STR:
        raise EvidenceError(f"evidence ref field '{name}' must be a non-empty string <={_MAX_STR}")
    if "\x00" in value:
        raise EvidenceError(f"evidence ref field '{name}' contains a null byte")
    return value


def _parse_ref(raw: object) -> EvidenceRef:
    if not isinstance(raw, Mapping):
        raise EvidenceError("each evidence entry must be an object")
    missing = [f for f in _CONTRACT_FIELDS if f not in raw]
    if missing:
        raise EvidenceError(f"evidence ref missing field(s): {', '.join(missing)}")
    fields = {name: _str_field(raw, name) for name in _CONTRACT_FIELDS}
    if fields["item_id"] not in VALID_ITEM_IDS:
        raise EvidenceError(
            f"evidence ref item_id is not a known checklist item: {fields['item_id']}"
        )
    if not _HEX_RE.match(fields["content_hash"]):
        raise EvidenceError("evidence ref content_hash must be lowercase hex")
    if not _HEX_RE.match(fields["signature"]):
        raise EvidenceError("evidence ref signature must be lowercase hex")
    return EvidenceRef(**fields)


def parse_document(doc: object) -> list[EvidenceRef]:
    """Parse and validate an evidence envelope into refs (fail-closed)."""
    if not isinstance(doc, Mapping) or "evidence" not in doc:
        raise EvidenceError("evidence document must be an object with an 'evidence' array")
    schema = doc.get("schema")
    if schema is not None and schema != SCHEMA_ID:
        raise EvidenceError(f"unsupported evidence schema: {schema!r} (expected {SCHEMA_ID!r})")
    entries = doc.get("evidence")
    if not isinstance(entries, list):
        raise EvidenceError("'evidence' must be an array")
    return [_parse_ref(entry) for entry in entries]


def load_evidence(text: str) -> list[EvidenceRef]:
    """Parse evidence-envelope JSON text into validated refs."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid evidence JSON: {exc.msg}") from exc
    return parse_document(doc)


# ── rule → checklist-item mapping ────────────────────────────────────────────
def _policy_resource(name: str) -> Path:
    with resources.as_file(resources.files("presidio_scoutsuite.policy") / name) as p:
        return Path(p)


@dataclass(frozen=True)
class ItemMap:
    """A provider's rule→checklist-item map (which items a clean rule evidences)."""

    provider: str
    items: tuple[str, ...]
    rules: dict[str, list[str]]


def load_item_map(provider: str, *, path: str | Path | None = None) -> ItemMap:
    """Load and shape-check the evidence map bundled for ``provider``.

    Fail-closed: a missing/malformed file, a non-object ``rules`` table, an entry
    that isn't a list of item-id strings, or an item id outside the known
    checklist raises :class:`EvidenceError`.
    """
    if path is not None:
        source = Path(path)
    else:
        try:
            source = _policy_resource(_MAPPING_FILES[provider])
        except KeyError as exc:
            raise EvidenceError(f"no evidence map bundled for provider {provider!r}") from exc
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"cannot read evidence map for {provider!r}: {exc}") from exc

    rules = data.get("rules")
    if not isinstance(rules, dict):
        raise EvidenceError(f"{source.name}: 'rules' must be an object mapping rules to items")
    cleaned: dict[str, list[str]] = {}
    items_used: set[str] = set()
    for rule, item_ids in rules.items():
        if (
            not isinstance(item_ids, list)
            or not item_ids
            or not all(isinstance(i, str) for i in item_ids)
        ):
            raise EvidenceError(f"{source.name}: {rule!r} must be a non-empty list of item ids")
        for item in item_ids:
            if item not in VALID_ITEM_IDS:
                raise EvidenceError(
                    f"{source.name}: rule {rule!r} references unknown item {item!r}"
                )
            items_used.add(item)
        cleaned[str(rule)] = list(item_ids)
    return ItemMap(provider, tuple(sorted(items_used)), cleaned)


def validate_item_map(provider: str) -> None:
    """Fail-closed check that every mapped rule exists in the rule manifest.

    A map that points at a rule the pinned ScoutSuite doesn't ship (a typo or an
    upstream rename) would silently never be evaluated — so we could attest an
    item "clean" on a control that never ran. Raise listing the unknown rules.
    """
    from . import ruleset

    item_map = load_item_map(provider)
    known = ruleset.manifest_rules(provider)
    unknown = sorted(set(item_map.rules) - known)
    if unknown:
        raise EvidenceError(
            f"{provider}: evidence map references {len(unknown)} rule(s) absent from the "
            f"manifest inventory: {', '.join(unknown)}"
        )


# ── building evidence from a findings report ─────────────────────────────────
def _iso_now(when: datetime | None = None) -> str:
    when = (when or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def report_manifest_digest(report_dir: str | Path) -> str:
    """Read the audited report's integrity-manifest content digest (fail-closed)."""
    path = Path(report_dir) / manifest_mod.MANIFEST_FILENAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"cannot read report integrity manifest: {exc}") from exc
    digest = document.get("content_digest")
    if not isinstance(digest, str) or not _HEX_RE.match(digest):
        raise EvidenceError("report manifest is missing a valid 'content_digest'")
    return digest


def build_evidence(
    findings_report: FindingsReport,
    *,
    report_digest: str,
    signer: str,
    key: str,
    alg: str,
    providers: list[str] | None = None,
    map_path: str | Path | None = None,
    source_version: str = __version__,
    claimed_at: str | None = None,
) -> dict:
    """Build a signed evidence envelope for the report's clean controls.

    One :class:`EvidenceRef` is emitted per ``(provider, item)`` whose **every**
    mapped rule is clean (absent from the flagged findings). Providers default to
    the ones the report recorded; an empty set fails closed, since we can't know
    what was audited.
    """
    provs = providers if providers is not None else list(findings_report.providers)
    if not provs:
        raise EvidenceError(
            "cannot determine which provider(s) were audited; pass --provider explicitly"
        )
    failing = {finding.rule for finding in findings_report.findings}
    claimed = claimed_at or _iso_now()
    ledger_ref = f"presidio-report-manifest:sha256/{report_digest}"

    refs: list[EvidenceRef] = []
    for provider in provs:
        item_map = load_item_map(provider, path=map_path)
        item_to_rules: dict[str, list[str]] = {}
        for rule, items in item_map.rules.items():
            for item in items:
                item_to_rules.setdefault(item, []).append(rule)
        for item in sorted(item_to_rules):
            mapped = item_to_rules[item]
            if any(rule in failing for rule in mapped):
                continue  # an item is clean only when every mapped rule is clean
            subject = claim_subject(
                item_id=item, provider=provider, rules=mapped, report_digest=report_digest
            )
            chash = content_hash(subject)
            refs.append(
                EvidenceRef(
                    item_id=item,
                    source=SOURCE,
                    source_version=source_version,
                    ledger_ref=ledger_ref,
                    content_hash=chash,
                    signer=signer,
                    signature=sign(alg, chash, signer, key),
                    claimed_at=claimed,
                )
            )
    return {
        "schema": SCHEMA_ID,
        "source": SOURCE,
        "source_version": source_version,
        "generated_at": claimed,
        "evidence": [ref.to_dict() for ref in refs],
    }


def emit_report(
    report_dir: str | Path,
    *,
    signer: str,
    key: str,
    alg: str,
    providers: list[str] | None = None,
    map_path: str | Path | None = None,
) -> dict:
    """Load a finished report and build its signed evidence envelope."""
    findings_report = load_report(report_dir)
    digest = report_manifest_digest(report_dir)
    return build_evidence(
        findings_report,
        report_digest=digest,
        signer=signer,
        key=key,
        alg=alg,
        providers=providers,
        map_path=map_path,
    )


# ── verification (round-trip / `verify` subcommand) ──────────────────────────
def _normalise_entry(signer: str, value: object) -> dict[str, object]:
    """Normalise a trust entry to ``{'alg', 'keys'}`` (``keys`` is always a list).

    A bare string is an HMAC secret. An object declares the signer's algorithm
    and key material, which may be a single value or a list (key rotation):
    ``{'alg': 'ed25519'|'hmac-sha256', 'public_key'|'key': '<hex>' | [...]}``.
    """
    if isinstance(value, str):
        return {"alg": "hmac-sha256", "keys": [value]}
    if isinstance(value, Mapping):
        alg = value.get("alg", "hmac-sha256")
        if alg not in SIGNING_ALGORITHMS:
            raise EvidenceError(f"trust entry '{signer}': unknown alg {alg!r}")
        raw = value.get("public_key") if alg == "ed25519" else value.get("key")
        raw = raw if raw is not None else (value.get("key") or value.get("public_key"))
        keys = [raw] if isinstance(raw, str) else raw
        if (
            not isinstance(keys, list)
            or not keys
            or not all(isinstance(k, str) and k for k in keys)
        ):
            raise EvidenceError(f"trust entry '{signer}': missing or invalid key material")
        return {"alg": alg, "keys": list(keys)}
    raise EvidenceError(f"trust entry '{signer}': must be a string or an object")


def load_trust_store(text: str) -> dict[str, dict[str, object]]:
    """Parse a trust-store JSON document into normalised ``{'alg', 'keys'}`` entries."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid trust-store JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise EvidenceError("trust store must be a JSON object keyed by signer id")
    normalised = {signer: _normalise_entry(signer, value) for signer, value in data.items()}
    if any(entry["alg"] == "ed25519" for entry in normalised.values()):
        _require_crypto()  # fail fast with a clear message before verification
    return normalised


def _verify_hmac(content_hash_hex: str, signer: str, signature: str, secret: str) -> bool:
    return hmac.compare_digest(_sign_hmac(content_hash_hex, signer, secret), signature)


def _verify_ed25519(
    content_hash_hex: str, signer: str, signature: str, public_key_hex: str
) -> bool:
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature), _signing_message(content_hash_hex, signer))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_ref(ref: EvidenceRef, trust: Mapping[str, object]) -> bool:
    """Verify a ref's signature against the trust store (timing-safe, fail-closed).

    Succeeds if the signature matches **any** key listed for the signer (which is
    what allows key rotation); an unknown signer returns ``False``.
    """
    entry = trust.get(ref.signer)
    if entry is None:
        return False
    norm = (
        entry
        if isinstance(entry, Mapping) and "keys" in entry
        else _normalise_entry(ref.signer, entry)
    )
    verify = _verify_ed25519 if norm["alg"] == "ed25519" else _verify_hmac
    return any(verify(ref.content_hash, ref.signer, ref.signature, key) for key in norm["keys"])


# ── console entry point ──────────────────────────────────────────────────────
def resolve_key(key_path: str | None) -> str:
    """Read the signing key from ``key_path`` or :data:`SIGNING_KEY_ENV`, fail-closed."""
    if key_path:
        try:
            raw = Path(key_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise EvidenceError(f"cannot read signing key file: {exc}") from exc
    else:
        raw = os.environ.get(SIGNING_KEY_ENV, "")
    raw = raw.strip()
    if not raw:
        raise EvidenceError(
            f"no signing key: pass --key PATH or set {SIGNING_KEY_ENV} "
            "(Ed25519: 32-byte private key as 64 hex chars; HMAC: a shared secret)"
        )
    return raw


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-evidence",
        description=(
            "Emit or verify signed evidence (presidio-hardened/evidence-ref@1) for a "
            "ScoutSuite report's clean controls. A clean control evidences an IKI-Gov "
            "checklist item a peer tool can verify. Offline; no ScoutSuite required."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit", help="build a signed evidence envelope for a report")
    emit.add_argument("report_dir", help="path to a finished, guarded report directory")
    emit.add_argument(
        "--signer",
        default=SOURCE,
        help=f"signer identity bound into each signature (default: {SOURCE})",
    )
    emit.add_argument(
        "--key", metavar="PATH", help=f"signing key file (default: ${SIGNING_KEY_ENV})"
    )
    emit.add_argument(
        "--alg",
        choices=SIGNING_ALGORITHMS,
        default="ed25519",
        help="signature algorithm (default: ed25519; hmac-sha256 needs no extra)",
    )
    emit.add_argument(
        "--provider",
        action="append",
        help="provider audited (repeatable; default: the provider(s) the report recorded)",
    )
    emit.add_argument(
        "--map", metavar="PATH", help="override the bundled rule→item map with this file"
    )
    emit.add_argument("-o", "--output", help="write to this file instead of stdout")

    ver = sub.add_parser("verify", help="verify an evidence envelope against a trust store")
    ver.add_argument("--evidence", required=True, metavar="PATH", help="evidence envelope JSON")
    ver.add_argument(
        "--trust", required=True, metavar="PATH", help="trust-store JSON {signer: key}"
    )
    ver.add_argument("--quiet", "-q", action="store_true", help="suppress per-ref output")

    args = parser.parse_args(argv)

    if args.command == "emit":
        try:
            key = resolve_key(args.key)
            envelope = emit_report(
                args.report_dir,
                signer=args.signer,
                key=key,
                alg=args.alg,
                providers=args.provider,
                map_path=args.map,
            )
        except PresidioScoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        text = json.dumps(envelope, indent=2, sort_keys=True) + "\n"
        # Fail-closed: evidence carries only item ids, rule names, digests and
        # signatures — never raw findings — but scan before emitting regardless.
        from . import redact

        try:
            redact.assert_clean(text, where="evidence envelope")
        except PresidioScoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(
                f"evidence: {args.output} ({len(envelope['evidence'])} clean control(s), "
                f"alg={args.alg})",
                file=sys.stderr,
            )
        else:
            sys.stdout.write(text)
        return 0

    # verify
    try:
        refs = load_evidence(Path(args.evidence).read_text(encoding="utf-8"))
        trust = load_trust_store(Path(args.trust).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ok = True
    for ref in refs:
        verified = verify_ref(ref, trust)
        ok = ok and verified
        if not args.quiet:
            mark = "ok  " if verified else "FAIL"
            print(f"{mark} {ref.item_id} signer={ref.signer} ({ref.content_hash[:12]}…)")
    if ok:
        print(f"ok   {len(refs)} evidence ref(s) verified", file=sys.stderr)
        return 0
    print("FAIL one or more evidence refs did not verify", file=sys.stderr)
    return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
