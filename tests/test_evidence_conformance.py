"""Conformance against the vendored family evidence contract test vectors.

The vectors under ``tests/vectors/`` are byte-for-byte copies (see its README).
The interop check at the end re-implements the family verifier's message and
HMAC check independently of :mod:`presidio_scoutsuite.evidence`, so a producer
change that drifts from the contract cannot pass by agreeing with itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from pathlib import Path

import pytest

from presidio_scoutsuite import evidence as E
from presidio_scoutsuite.errors import EvidenceError

_TESTS = Path(__file__).parent
_VECTORS = _TESTS / "vectors"
_INTEROP = _TESTS / "interop"

_CANONICAL = json.loads((_VECTORS / "canonical-json" / "vectors.json").read_text("utf-8"))
_HMAC = json.loads((_VECTORS / "signing" / "hmac-sha256-golden.json").read_text("utf-8"))


# ── canonical JSON ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("case", _CANONICAL["cases"], ids=lambda c: c["name"])
def test_canonical_json_vectors(case):
    encoded = E._canonical(case["payload"])
    assert encoded == case["canonical"].encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == case["sha256_hex"]
    assert E.content_hash(case["payload"]) == case["sha256_hex"]


@pytest.mark.parametrize("case", _CANONICAL["rejected"], ids=lambda c: c["name"])
def test_canonical_json_rejects_float_vectors(case):
    with pytest.raises(EvidenceError):
        E._canonical(case["payload"])


@pytest.mark.parametrize(
    "payload",
    [
        {"x": math.nan},
        {"x": math.inf},
        {"x": [-math.inf]},
        {"x": ("t", 0.0)},
        {1.5: "float key"},
    ],
    ids=["nan", "inf", "neg-inf-nested", "float-in-tuple", "float-key"],
)
def test_canonical_json_rejects_nan_inf_and_floats(payload):
    with pytest.raises(EvidenceError):
        E._canonical(payload)


def test_canonical_json_rejects_unserialisable():
    with pytest.raises(EvidenceError):
        E._canonical({"x": object()})


# ── signing message + HMAC golden ────────────────────────────────────────────
def test_signing_message_matches_contract_vector():
    message = E.signing_message(_HMAC["content_hash"], _HMAC["signer"])
    assert message == _HMAC["message_canonical"].encode("utf-8")


def test_hmac_golden_signature():
    fields = {"content_hash": _HMAC["content_hash"], "signer": _HMAC["signer"]}
    assert E.sign("hmac-sha256", fields, _HMAC["key"]) == _HMAC["signature_hex"]


def test_hmac_golden_verifies_and_tamper_cases_fail():
    message = E.signing_message(_HMAC["content_hash"], _HMAC["signer"])
    assert E._verify_hmac(_HMAC["signature_hex"], message, _HMAC["key"])
    for case in _HMAC["tamper_cases"]:
        tampered = E.signing_message(case["content_hash"], case["signer"])
        assert E._verify_hmac(case["signature_hex"], tampered, case["key"]) is case["verifies"]


# ── interop golden, checked the way the family verifier does ─────────────────
def _family_message(content_hash: str, signer: str) -> bytes:
    """Independent re-implementation of the contract signing message."""
    return json.dumps(
        {"content_hash": content_hash, "signer": signer},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _family_hmac_keys(entry) -> list[str]:
    """trust-store@1 HMAC entry: a bare secret or {alg, key: str | [str]}."""
    if isinstance(entry, str):
        return [entry]
    assert entry.get("alg", "hmac-sha256") == "hmac-sha256"
    key = entry["key"]
    return [key] if isinstance(key, str) else list(key)


def test_interop_golden_verifies_like_family_verifier():
    envelope = json.loads((_INTEROP / "scout-evidence-aws.json").read_text("utf-8"))
    trust = json.loads((_INTEROP / "scout-evidence-aws.trust.json").read_text("utf-8"))
    assert envelope["schema"] == "presidio-hardened/evidence-ref@2"
    assert envelope["evidence"]
    for ref in envelope["evidence"]:
        keys = _family_hmac_keys(trust[ref["signer"]])
        message = _family_message(ref["content_hash"], ref["signer"])
        expected = [hmac.new(k.encode("utf-8"), message, hashlib.sha256).hexdigest() for k in keys]
        assert any(hmac.compare_digest(e, ref["signature"]) for e in expected), ref["item_id"]


def test_interop_golden_fails_family_verifier_when_tampered():
    envelope = json.loads((_INTEROP / "scout-evidence-aws.json").read_text("utf-8"))
    trust = json.loads((_INTEROP / "scout-evidence-aws.trust.json").read_text("utf-8"))
    ref = envelope["evidence"][0]
    (key,) = _family_hmac_keys(trust[ref["signer"]])
    for content_hash, signer in (("0" * 64, ref["signer"]), (ref["content_hash"], "evil")):
        message = _family_message(content_hash, signer)
        mac = hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(mac, ref["signature"])
