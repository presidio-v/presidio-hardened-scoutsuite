"""Emit signed evidence for clean controls — family evidence producer (0.28.0+).

This makes a ScoutSuite audit a **producer** in the ``presidio-hardened-*``
evidence substrate. When a curated control is **clean** in a run (no flagged
finding for any rule mapped to it), this module emits a signed ``EvidenceRef``
(schema ``presidio-hardened/evidence-ref@2``) that a peer **consumer** —
``presidio-hardened-ikigov-assess`` — verifies fail-closed and uses to affirm
its governance checklist items. ScoutSuite is the second producer in the family
(after ``presidio-hardened-ai``); ikigov-assess consumes both.

What a clean control evidences is a deliberate, curated mapping
(``policy/<provider>.evidence.json``, validated fail-closed against the rule
manifest): **T5** = "a security review of the infrastructure and all
dependencies has been conducted and findings addressed"; **O5** = "an audit log
is maintained, stored immutably, and accessible to authorised auditors". A claim
is signed only when *every* rule mapped to its item is clean.

Wire format: the detached signature is over the family evidence contract's
signing message, the canonical JSON of ``{"content_hash", "signer"}`` only.
Canonical JSON is ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)`` encoded as UTF-8, with floats (and so
NaN/Infinity) rejected anywhere in the payload. The checklist item, provider,
clean rule set and report digest are bound through ``content_hash`` (see
:func:`claim_subject`), and the signer is bound directly, so a valid signature
cannot be replayed under another signer or claim. HMAC-SHA256 uses the stdlib;
Ed25519 (the secure default) needs the optional ``[crypto]`` extra. Pure stdlib
otherwise, offline, fail-closed — never imports ScoutSuite.

Legacy signatures (deprecated): releases up to 0.29.x signed the canonical JSON
of every contract field except ``signature``, which no other family verifier
accepts. :func:`verify_ref_detailed` still accepts such a signature, but only
after the contract message fails, and it reports ``legacy_signature=True`` and
logs a WARNING. ``presidio-scout-evidence resign`` re-signs legacy refs over the
contract message. Legacy acceptance is removed in v0.32.0 or 90 days after the
v0.30.0 release, whichever is later.
imports ScoutSuite.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
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

#: Cross-repo wire-format contract identifiers (the family evidence contract).
SCHEMA_ID = "presidio-hardened/evidence-ref@2"
#: Verifier-side trust-store schema id (the consumer's contract id).
TRUST_STORE_SCHEMA_ID = "presidio-hardened/trust-store@1"
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
#: Fields the pre-0.30.0 (legacy, deprecated) signing message covered.
_LEGACY_SIGNED_FIELDS = tuple(field for field in _CONTRACT_FIELDS if field != "signature")
#: When legacy-signature acceptance goes away (see the module docstring).
LEGACY_SIGNATURE_REMOVAL = "v0.32.0 or 90 days after the v0.30.0 release, whichever is later"
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_HEX_RE = re.compile(r"^(?:[0-9a-f]{64}|[0-9a-f]{128})$")
_ED25519_PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_STR = 512

_MAPPING_FILES: dict[str, str] = {p: f"{p}.evidence.json" for p in MAPPED_PROVIDERS}

_log = logging.getLogger(__name__)


# ── wire format ──────────────────────────────────────────────────────────────
def _reject_floats(payload: object) -> None:
    """Reject floats anywhere in ``payload`` (the contract's strict profile).

    Floats have no single canonical text form across languages, so the contract
    forbids them outright; this also rules out NaN and +/-Infinity.
    """
    if isinstance(payload, float):
        raise EvidenceError("floats are not permitted in canonical evidence payloads")
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            _reject_floats(key)
            _reject_floats(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _reject_floats(value)


def _canonical(payload: object) -> bytes:
    """Strict canonical JSON bytes: sorted keys, compact, UTF-8, no floats/NaN."""
    _reject_floats(payload)
    if isinstance(payload, Mapping):
        payload = dict(payload)
    try:
        text = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"payload is not canonicalisable: {exc}") from exc
    return text.encode("utf-8")


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


def signing_message(content_hash: str, signer: str) -> bytes:
    """The family contract's signing message: canonical ``{content_hash, signer}``."""
    return _canonical({"content_hash": content_hash, "signer": signer})


def _contract_fields(fields: Mapping[str, object]) -> tuple[str, str]:
    values = []
    for name in ("content_hash", "signer"):
        value = fields.get(name)
        if not isinstance(value, str) or not value:
            raise EvidenceError(f"cannot sign evidence ref; missing or invalid field: {name}")
        values.append(value)
    return values[0], values[1]


def _signing_message(fields: Mapping[str, object]) -> bytes:
    return signing_message(*_contract_fields(fields))


def _legacy_signing_message(fields: Mapping[str, object]) -> bytes:
    """Pre-0.30.0 message (every field but ``signature``). Verification only."""
    missing = [field for field in _LEGACY_SIGNED_FIELDS if field not in fields]
    if missing:
        raise EvidenceError(f"legacy message needs field(s): {', '.join(missing)}")
    return _canonical({field: fields[field] for field in _LEGACY_SIGNED_FIELDS})


def _hmac_hex(message: bytes, key: str) -> str:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _sign_hmac(fields: Mapping[str, object], key: str) -> str:
    return _hmac_hex(_signing_message(fields), key)


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


def _sign_ed25519(fields: Mapping[str, object], private_key_hex: str) -> str:
    ed25519 = _require_crypto()
    try:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise EvidenceError(f"invalid Ed25519 private key: {exc}") from exc
    return sk.sign(_signing_message(fields)).hex()


def sign(alg: str, fields: Mapping[str, object], key: str) -> str:
    """Detached signature over the evidence ref's signed fields for ``alg``."""
    if alg == "hmac-sha256":
        return _sign_hmac(fields, key)
    if alg == "ed25519":
        return _sign_ed25519(fields, key)
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
    if not _SHA256_HEX_RE.match(fields["content_hash"]):
        raise EvidenceError("evidence ref content_hash must be a lowercase SHA-256 hex digest")
    if not _SIGNATURE_HEX_RE.match(fields["signature"]):
        raise EvidenceError(
            "evidence ref signature must be lowercase hex with HMAC-SHA256 or Ed25519 length"
        )
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
    declared_provider = data.get("provider")
    if declared_provider is not None and declared_provider != provider:
        raise EvidenceError(
            f"{source.name}: provider {declared_provider!r} does not match {provider!r}"
        )
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
    if not isinstance(digest, str) or not _SHA256_HEX_RE.match(digest):
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
    if not _SHA256_HEX_RE.match(report_digest):
        raise EvidenceError("report_digest must be a lowercase SHA-256 hex digest")
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
            signed_fields = {
                "item_id": item,
                "source": SOURCE,
                "source_version": source_version,
                "ledger_ref": ledger_ref,
                "content_hash": chash,
                "signer": signer,
                "claimed_at": claimed,
            }
            refs.append(
                EvidenceRef(
                    item_id=item,
                    source=SOURCE,
                    source_version=source_version,
                    ledger_ref=ledger_ref,
                    content_hash=chash,
                    signer=signer,
                    signature=sign(alg, signed_fields, key),
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
        if alg == "ed25519" and not all(_ED25519_PUBKEY_RE.match(k) for k in keys):
            # Reject a malformed key at load rather than silently failing every
            # verification later (an operator typo must be loud, not fail-open-ish).
            raise EvidenceError(
                f"trust entry '{signer}': Ed25519 public keys must be 64 lowercase hex chars"
            )
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


def _verify_hmac(signature: str, message: bytes, secret: str) -> bool:
    return hmac.compare_digest(_hmac_hex(message, secret), signature)


def _verify_ed25519(signature: str, message: bytes, public_key_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of verifying one ref.

    ``legacy_signature`` is ``True`` only when the ref verified over the
    deprecated pre-0.30.0 message (every field but ``signature``) and not over
    the family contract message. Such a ref should be re-signed with
    ``presidio-scout-evidence resign``.
    """

    ok: bool
    legacy_signature: bool = False

    def __bool__(self) -> bool:
        return self.ok


def _trust_entry(ref: EvidenceRef, trust: Mapping[str, object]) -> dict[str, object] | None:
    entry = trust.get(ref.signer)
    if entry is None:
        return None
    if isinstance(entry, Mapping) and "keys" in entry:
        return dict(entry)
    return _normalise_entry(ref.signer, entry)


def verify_ref_detailed(ref: EvidenceRef, trust: Mapping[str, object]) -> VerifyResult:
    """Verify a ref's signature against the trust store (timing-safe, fail-closed).

    The family contract message is tried first, against **any** key listed for
    the signer (which is what allows key rotation). Only if that fails is the
    deprecated legacy message tried; a legacy match succeeds with
    ``legacy_signature=True`` and a WARNING is logged. An unknown signer fails.
    """
    norm = _trust_entry(ref, trust)
    if norm is None:
        return VerifyResult(False)
    verify = _verify_ed25519 if norm["alg"] == "ed25519" else _verify_hmac
    keys = norm["keys"]
    message = _signing_message(ref.to_dict())
    if any(verify(ref.signature, message, key) for key in keys):
        return VerifyResult(True)
    legacy = _legacy_signing_message(ref.to_dict())
    if any(verify(ref.signature, legacy, key) for key in keys):
        _log.warning(
            "evidence ref %s from signer %r verified only over the deprecated legacy "
            "signing message; re-sign it with `presidio-scout-evidence resign`. "
            "Legacy acceptance is removed in %s.",
            ref.item_id,
            ref.signer,
            LEGACY_SIGNATURE_REMOVAL,
        )
        return VerifyResult(True, legacy_signature=True)
    return VerifyResult(False)


def verify_ref(ref: EvidenceRef, trust: Mapping[str, object]) -> bool:
    """``True`` if :func:`verify_ref_detailed` accepts the ref (legacy included)."""
    return verify_ref_detailed(ref, trust).ok


def resign_document(
    doc: Mapping[str, object], trust: Mapping[str, object], *, key: str, alg: str
) -> tuple[dict, int]:
    """Re-sign a document's legacy-signed refs over the contract message.

    Fail-closed: every ref must already verify against ``trust`` (contract or
    legacy message), so a ref that was never validly signed cannot be laundered
    into a valid one. Each new signature is checked against ``trust`` before it
    is accepted, which proves ``key`` belongs to the ref's signer. Refs that
    already use the contract message are left untouched. Returns the new
    document and the number of refs re-signed.
    """
    refs = parse_document(doc)
    out: list[dict[str, str]] = []
    resigned = 0
    for ref in refs:
        result = verify_ref_detailed(ref, trust)
        if not result.ok:
            raise EvidenceError(
                f"evidence ref {ref.item_id} (signer {ref.signer!r}) does not verify "
                "against the trust store; refusing to re-sign it"
            )
        if not result.legacy_signature:
            out.append(ref.to_dict())
            continue
        new = EvidenceRef(**{**ref.to_dict(), "signature": sign(alg, ref.to_dict(), key)})
        check = verify_ref_detailed(new, trust)
        if not check.ok or check.legacy_signature:
            raise EvidenceError(
                f"the provided key does not match the trust-store entry for signer "
                f"{ref.signer!r}; refusing to re-sign"
            )
        out.append(new.to_dict())
        resigned += 1
    return {**dict(doc), "evidence": out}, resigned


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


def _cmd_resign(args: argparse.Namespace) -> int:
    """``resign``: re-sign legacy refs. Key material is never printed or logged."""
    try:
        doc = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        trust = load_trust_store(Path(args.trust).read_text(encoding="utf-8"))
        key = resolve_key(args.key)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: invalid evidence JSON: {exc}", file=sys.stderr)
        return 2
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        envelope, resigned = resign_document(doc, trust, key=key, alg=args.alg)
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    text = json.dumps(envelope, indent=2, sort_keys=True) + "\n"
    from . import redact

    try:
        redact.assert_clean(text, where="evidence envelope")
    except PresidioScoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(
        f"resign: {resigned} legacy ref(s) re-signed, "
        f"{len(envelope['evidence']) - resigned} already conformant",
        file=sys.stderr,
    )
    return 0


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="presidio-scout-evidence",
        description=(
            "Emit, verify or re-sign signed evidence (presidio-hardened/evidence-ref@2) for a "
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

    res = sub.add_parser(
        "resign",
        help="re-sign legacy (pre-0.30.0) refs over the family contract message",
    )
    res.add_argument("--evidence", required=True, metavar="PATH", help="evidence envelope JSON")
    res.add_argument(
        "--trust",
        required=True,
        metavar="PATH",
        help="trust-store JSON; every ref must verify against it before re-signing",
    )
    res.add_argument(
        "--key", metavar="PATH", help=f"signing key file (default: ${SIGNING_KEY_ENV})"
    )
    res.add_argument(
        "--alg",
        choices=SIGNING_ALGORITHMS,
        default="ed25519",
        help="signature algorithm of the signer's trust entry (default: ed25519)",
    )
    res.add_argument("-o", "--output", help="write to this file instead of stdout")

    args = parser.parse_args(argv)

    if args.command == "resign":
        return _cmd_resign(args)

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
    legacy = 0
    for ref in refs:
        result = verify_ref_detailed(ref, trust)
        ok = ok and result.ok
        legacy += result.legacy_signature
        if not args.quiet:
            mark = "ok  " if result.ok else "FAIL"
            note = " [legacy signature]" if result.legacy_signature else ""
            print(f"{mark} {ref.item_id} signer={ref.signer} ({ref.content_hash[:12]}…){note}")
    if ok:
        print(f"ok   {len(refs)} evidence ref(s) verified", file=sys.stderr)
        if legacy:
            print(
                f"warning: {legacy} ref(s) use the deprecated legacy signing message; "
                f"run `presidio-scout-evidence resign` (legacy acceptance is removed in "
                f"{LEGACY_SIGNATURE_REMOVAL})",
                file=sys.stderr,
            )
        return 0
    print("FAIL one or more evidence refs did not verify", file=sys.stderr)
    return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
