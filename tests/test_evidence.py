"""Tests for evidence emission (family evidence producer, 0.28.0+).

Signatures are over the family contract message ``canonical({content_hash,
signer})`` since 0.30.0; conformance against the vendored contract vectors lives
in ``test_evidence_conformance.py``. The HMAC vectors here are exercised with the
stdlib so the wire format is pinned without the optional ``[crypto]`` extra; the
Ed25519 golden vector and ed25519 trust-store paths run only when a real Ed25519
operation works (``_needs_ed25519`` skips an importable-but-broken backend).
The cross-repo interop golden under ``tests/interop/`` is a ScoutSuite-emitted
envelope ikigov-assess must verify.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from presidio_scoutsuite import cli, launcher, report_guard, scout_integrity
from presidio_scoutsuite import evidence as E
from presidio_scoutsuite.errors import EvidenceError
from presidio_scoutsuite.findings import Finding, FindingsReport

# ── this repo's own vectors (contract message; legacy message for back-compat) ─
GOLDEN_CH = "b" * 64
GOLDEN_SIGNER = "presidio-hardened-ai"
GOLDEN_HMAC_KEY = "shared-key"
GOLDEN_REF_FIELDS = {
    "item_id": "T5",
    "source": E.SOURCE,
    "source_version": "0.29.0",
    "ledger_ref": "presidio-report-manifest:sha256/" + "a" * 64,
    "content_hash": GOLDEN_CH,
    "signer": GOLDEN_SIGNER,
    "claimed_at": "2026-06-17T00:00:00Z",
}
GOLDEN_HMAC_SIG = "cb276327fcc4174566780ef567368cb6f91791a22bd7cbbdabe30619c58ec0b1"
GOLDEN_CANONICAL = (
    '{"content_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    '"signer":"presidio-hardened-ai"}'
)
# Pre-0.30.0 (legacy, deprecated) message and signatures over the same fields.
LEGACY_HMAC_SIG = "4a87680aeba36ed35975f536e80ce7dcf57de128cfbda444d7284f21903a6aec"
LEGACY_CANONICAL = (
    '{"claimed_at":"2026-06-17T00:00:00Z",'
    '"content_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    '"item_id":"T5",'
    '"ledger_ref":"presidio-report-manifest:sha256/'
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    '","signer":"presidio-hardened-ai",'
    '"source":"presidio-hardened-scoutsuite",'
    '"source_version":"0.29.0"}'
)

ED_PRIV = "0101010101010101010101010101010101010101010101010101010101010101"
ED_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
ED_SIG = (
    "b9c19dd11e65625e76c41f31554980f933a6affd962b9364a5cb7c27b99b4984"
    "b7bb64f4ceabbc974f33c43ac14edb5dd4d5d26e0f2cbbb28dcdefc4ee8b260e"
)
LEGACY_ED_SIG = (
    "24175d2302cfda4a53d2795ab80838b4fd9e162096beec9c60abdcf96fc5b"
    "495c0b3112a8f2ef05541ce97c2d543e3cb8687984278f01ad2c9a4fb7d75036a0c"
)


# ── wire format ──────────────────────────────────────────────────────────────
def test_canonical_signing_message_matches_vector():
    assert E._signing_message(GOLDEN_REF_FIELDS).decode("utf-8") == GOLDEN_CANONICAL


def test_hmac_golden_signature_matches_producer():
    assert E.sign("hmac-sha256", GOLDEN_REF_FIELDS, GOLDEN_HMAC_KEY) == GOLDEN_HMAC_SIG


def test_legacy_message_is_unchanged_for_back_compat():
    assert E._legacy_signing_message(GOLDEN_REF_FIELDS).decode("utf-8") == LEGACY_CANONICAL


def test_canonical_preserves_unicode_and_sorts_keys():
    assert E._canonical({"b": "ß", "a": 1}) == '{"a":1,"b":"ß"}'.encode()


def test_unknown_alg_rejected():
    with pytest.raises(EvidenceError):
        E.sign("rot13", GOLDEN_REF_FIELDS, "k")


# ── building evidence from a findings report ─────────────────────────────────
def _report(findings, providers=("aws",)):
    return FindingsReport(findings=list(findings), providers=list(providers))


def test_clean_controls_emit_evidence_failing_ones_do_not():
    # One flagged O5 rule (cloudtrail) → O5 not clean; every T5 rule is clean.
    report = _report([Finding("cloudtrail", "cloudtrail-no-logging.json", "danger", 1)])
    env = E.build_evidence(
        report,
        report_digest="a" * 64,
        signer=E.SOURCE,
        key="k",
        alg="hmac-sha256",
    )
    assert env["schema"] == E.SCHEMA_ID
    assert env["source"] == E.SOURCE
    items = {ref["item_id"] for ref in env["evidence"]}
    assert items == {"T5"}
    ref = env["evidence"][0]
    assert ref["ledger_ref"] == "presidio-report-manifest:sha256/" + "a" * 64
    assert ref["signer"] == E.SOURCE
    assert E._SHA256_HEX_RE.match(ref["content_hash"])


def test_fully_clean_report_emits_all_items():
    env = E.build_evidence(
        _report([]), report_digest="b" * 64, signer="s", key="k", alg="hmac-sha256"
    )
    assert {ref["item_id"] for ref in env["evidence"]} == {"O5", "T5"}


def test_content_hash_binds_report_digest():
    a = E.build_evidence(
        _report([]), report_digest="a" * 64, signer="s", key="k", alg="hmac-sha256"
    )
    b = E.build_evidence(
        _report([]), report_digest="c" * 64, signer="s", key="k", alg="hmac-sha256"
    )
    ha = {r["item_id"]: r["content_hash"] for r in a["evidence"]}
    hb = {r["item_id"]: r["content_hash"] for r in b["evidence"]}
    assert ha != hb  # a different report yields different claims


def test_build_evidence_without_providers_fails_closed():
    with pytest.raises(EvidenceError):
        E.build_evidence(
            _report([], providers=()),
            report_digest="a" * 64,
            signer="s",
            key="k",
            alg="hmac-sha256",
        )


def test_emitted_evidence_round_trips_through_verify():
    env = E.build_evidence(
        _report([]), report_digest="a" * 64, signer="sig-er", key="sek", alg="hmac-sha256"
    )
    refs = E.parse_document(env)
    trust = E.load_trust_store(json.dumps({"sig-er": "sek"}))
    assert refs and all(E.verify_ref(r, trust) for r in refs)


# ── rule → checklist-item maps ───────────────────────────────────────────────
def test_bundled_maps_validate_against_manifest():
    for provider in E.MAPPED_PROVIDERS:
        E.validate_item_map(provider)  # fail-closed; raises if a rule is unknown


def test_unknown_provider_map_fails_closed():
    with pytest.raises(EvidenceError):
        E.load_item_map("gcp-east")


def test_map_with_unknown_item_rejected(tmp_path):
    bad = tmp_path / "bad.evidence.json"
    bad.write_text(json.dumps({"provider": "aws", "rules": {"r.json": ["Z9"]}}))
    with pytest.raises(EvidenceError):
        E.load_item_map("aws", path=bad)


def test_map_provider_mismatch_rejected(tmp_path):
    bad = tmp_path / "bad.evidence.json"
    bad.write_text(json.dumps({"provider": "gcp", "rules": {"s3-bucket-world-acl.json": ["T5"]}}))
    with pytest.raises(EvidenceError):
        E.load_item_map("aws", path=bad)


def test_map_with_unknown_rule_fails_validation(tmp_path, monkeypatch):
    bad = tmp_path / "bad.evidence.json"
    bad.write_text(json.dumps({"provider": "aws", "rules": {"not-a-real-rule.json": ["T5"]}}))
    monkeypatch.setattr(E, "_policy_resource", lambda name: bad)
    with pytest.raises(EvidenceError):
        E.validate_item_map("aws")


# ── parsing / validation (fail-closed) ───────────────────────────────────────
def _ref_dict(**over):
    base = {
        "item_id": "T5",
        "source": E.SOURCE,
        "source_version": "0.29.0",
        "ledger_ref": "presidio-report-manifest:sha256/" + "a" * 64,
        "content_hash": GOLDEN_CH,
        "signer": GOLDEN_SIGNER,
        "signature": GOLDEN_HMAC_SIG,
        "claimed_at": "2026-06-17T00:00:00Z",
    }
    base.update(over)
    return base


@pytest.mark.parametrize(
    "doc",
    [
        {"evidence": [_ref_dict(item_id="Q9")]},  # unknown checklist item
        {"evidence": [_ref_dict(content_hash="NOTHEX")]},  # bad hex
        {"evidence": [_ref_dict(content_hash="abc123def456")]},  # truncated digest
        {"evidence": [_ref_dict(signature="ZZ")]},  # bad hex signature
        {"evidence": [_ref_dict(signature="deadbeef")]},  # truncated signature
        {"schema": "other@2", "evidence": []},  # wrong schema id
        {"evidence": "nope"},  # evidence not an array
        {"no_evidence": []},  # missing evidence array
        {
            "evidence": [{k: v for k, v in _ref_dict().items() if k != "ledger_ref"}]
        },  # missing field
    ],
)
def test_parse_document_rejects_malformed(doc):
    with pytest.raises(EvidenceError):
        E.parse_document(doc)


def test_load_evidence_bad_json():
    with pytest.raises(EvidenceError):
        E.load_evidence("{not json")


# ── trust store + verification ───────────────────────────────────────────────
def test_load_trust_store_string_and_object():
    trust = E.load_trust_store(
        json.dumps({"a": "secret", "b": {"alg": "hmac-sha256", "key": ["k1", "k2"]}})
    )
    assert trust["a"] == {"alg": "hmac-sha256", "keys": ["secret"]}
    assert trust["b"]["keys"] == ["k1", "k2"]


def test_verify_unknown_signer_is_false():
    ref = E.EvidenceRef(**_ref_dict())
    assert E.verify_ref(ref, {}) is False


def test_verify_hmac_golden_and_tamper():
    ref = E.EvidenceRef(**_ref_dict())
    trust = E.load_trust_store(json.dumps({GOLDEN_SIGNER: GOLDEN_HMAC_KEY}))
    assert E.verify_ref(ref, trust) is True
    tampered = E.EvidenceRef(**_ref_dict(content_hash="c" * 64))
    assert E.verify_ref(tampered, trust) is False
    wrong_signer = E.EvidenceRef(**_ref_dict(signer="evil"))
    assert E.verify_ref(wrong_signer, trust) is False


def test_contract_signature_covers_only_content_hash_and_signer():
    # The family contract signs {content_hash, signer} only. item_id, ledger_ref
    # and the report digest are committed to by content_hash (see claim_subject),
    # so a verifier holding the report re-derives the hash to bind them; the
    # signature alone does not cover item_id/ledger_ref/claimed_at.
    trust = E.load_trust_store(json.dumps({GOLDEN_SIGNER: GOLDEN_HMAC_KEY}))
    relabelled = E.EvidenceRef(**_ref_dict(claimed_at="2026-06-18T00:00:00Z"))
    assert E.verify_ref(relabelled, trust) is True
    subject_t5 = E.claim_subject(
        item_id="T5", provider="aws", rules=["r.json"], report_digest="a" * 64
    )
    subject_o5 = E.claim_subject(
        item_id="O5", provider="aws", rules=["r.json"], report_digest="a" * 64
    )
    assert E.content_hash(subject_t5) != E.content_hash(subject_o5)


def test_hmac_key_rotation_any_key_verifies():
    ref = E.EvidenceRef(**_ref_dict())
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "hmac-sha256", "key": ["stale", GOLDEN_HMAC_KEY]}})
    )
    assert E.verify_ref(ref, trust) is True


# ── Ed25519 (needs the optional [crypto] extra) ──────────────────────────────
def _ed25519_available() -> bool:
    """True only if a real Ed25519 operation works (not just an importable shell)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32)).sign(b"probe")
        return True
    except BaseException:  # broken backend (e.g. missing _cffi_backend) → skip, not error
        return False


_HAS_ED25519 = _ed25519_available()
_needs_ed25519 = pytest.mark.skipif(not _HAS_ED25519, reason="cryptography Ed25519 unavailable")


@_needs_ed25519
def test_ed25519_golden_sign_and_verify():
    assert E.sign("ed25519", GOLDEN_REF_FIELDS, ED_PRIV) == ED_SIG
    ref = E.EvidenceRef(**_ref_dict(signature=ED_SIG))
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}})
    )
    assert E.verify_ref_detailed(ref, trust) == E.VerifyResult(True, legacy_signature=False)
    tampered = E.EvidenceRef(**_ref_dict(signature=ED_SIG, content_hash="c" * 64))
    assert E.verify_ref(tampered, trust) is False


@_needs_ed25519
def test_ed25519_legacy_signature_accepted_with_flag():
    ref = E.EvidenceRef(**_ref_dict(signature=LEGACY_ED_SIG))
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}})
    )
    assert E.verify_ref_detailed(ref, trust) == E.VerifyResult(True, legacy_signature=True)
    tampered = E.EvidenceRef(**_ref_dict(signature=LEGACY_ED_SIG, item_id="O5"))
    assert E.verify_ref(tampered, trust) is False


@_needs_ed25519
def test_ed25519_key_rotation_multiple_public_keys():
    ref = E.EvidenceRef(**_ref_dict(signature=ED_SIG))
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ["00" * 32, ED_PUB]}})
    )
    assert E.verify_ref(ref, trust) is True


# ── key resolution ───────────────────────────────────────────────────────────
def test_resolve_key_from_file_and_env(tmp_path, monkeypatch):
    monkeypatch.delenv(E.SIGNING_KEY_ENV, raising=False)
    kf = tmp_path / "k"
    kf.write_text("  filekey\n")
    assert E.resolve_key(str(kf)) == "filekey"
    monkeypatch.setenv(E.SIGNING_KEY_ENV, "envkey")
    assert E.resolve_key(None) == "envkey"


def test_resolve_key_missing_fails_closed(monkeypatch):
    monkeypatch.delenv(E.SIGNING_KEY_ENV, raising=False)
    with pytest.raises(EvidenceError):
        E.resolve_key(None)


def test_null_byte_field_rejected():
    with pytest.raises(EvidenceError):
        E.parse_document({"evidence": [_ref_dict(ledger_ref="bad\x00ref")]})


def test_non_object_evidence_entry_rejected():
    with pytest.raises(EvidenceError):
        E.parse_document({"evidence": ["not-an-object"]})


def test_build_evidence_provider_override_and_map(tmp_path):
    # Override provider list and the bundled map with a one-rule file.
    m = tmp_path / "custom.evidence.json"
    m.write_text(json.dumps({"provider": "aws", "rules": {"s3-bucket-world-acl.json": ["T5"]}}))
    env = E.build_evidence(
        _report([], providers=()),
        report_digest="a" * 64,
        signer="s",
        key="k",
        alg="hmac-sha256",
        providers=["aws"],
        map_path=m,
    )
    assert {r["item_id"] for r in env["evidence"]} == {"T5"}


# ── emit_report end-to-end (report dir → envelope) ───────────────────────────
def _guarded_report(tmp_path, results):
    (tmp_path / "report.html").write_text("<html><head></head><body>ok</body></html>")
    sub = tmp_path / "scoutsuite-results"
    sub.mkdir(parents=True, exist_ok=True)
    (sub / "scoutsuite_results_aws-1.js").write_text("scoutsuite_results =\n" + json.dumps(results))
    report_guard.guard_report(tmp_path)  # writes the integrity manifest
    return tmp_path


def test_emit_report_reads_dir_and_binds_manifest(tmp_path):
    results = {
        "provider_code": "aws",
        "services": {
            "s3": {
                "findings": {"s3-bucket-world-acl.json": {"level": "danger", "flagged_items": 1}}
            }
        },
    }
    report_dir = _guarded_report(tmp_path, results)
    env = E.emit_report(report_dir, signer="s", key="k", alg="hmac-sha256")
    # A failing T5 rule (s3 world acl) blocks T5; O5 has no failing rule → clean.
    assert {ref["item_id"] for ref in env["evidence"]} == {"O5"}
    digest = E.report_manifest_digest(report_dir)
    assert env["evidence"][0]["ledger_ref"].endswith(digest)


def test_report_manifest_digest_missing_fails_closed(tmp_path):
    with pytest.raises(EvidenceError):
        E.report_manifest_digest(tmp_path)


# ── console entry point ──────────────────────────────────────────────────────
def test_main_emit_then_verify(tmp_path, monkeypatch):
    monkeypatch.setenv(E.SIGNING_KEY_ENV, "topsecret")
    report_dir = _guarded_report(tmp_path, {"provider_code": "aws", "services": {}})
    out = tmp_path / "evidence.json"
    rc = E._main(["emit", str(report_dir), "--alg", "hmac-sha256", "-o", str(out)])
    assert rc == 0
    env = json.loads(out.read_text())
    assert {r["item_id"] for r in env["evidence"]} == {"O5", "T5"}

    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps({E.SOURCE: "topsecret"}))
    assert E._main(["verify", "--evidence", str(out), "--trust", str(trust)]) == 0

    badtrust = tmp_path / "bad.json"
    badtrust.write_text(json.dumps({E.SOURCE: "wrong"}))
    assert E._main(["verify", "--evidence", str(out), "--trust", str(badtrust)]) == 3
    # --quiet suppresses per-ref lines but keeps the exit code
    assert E._main(["verify", "--evidence", str(out), "--trust", str(trust), "--quiet"]) == 0


def test_main_emit_stdout(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(E.SIGNING_KEY_ENV, "topsecret")
    report_dir = _guarded_report(tmp_path, {"provider_code": "aws", "services": {}})
    assert E._main(["emit", str(report_dir), "--alg", "hmac-sha256"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == E.SCHEMA_ID


def test_main_verify_missing_file_fails_closed(tmp_path):
    assert (
        E._main(
            [
                "verify",
                "--evidence",
                str(tmp_path / "nope.json"),
                "--trust",
                str(tmp_path / "t.json"),
            ]
        )
        == 2
    )


def test_main_verify_bad_json_fails_closed(tmp_path):
    ev = tmp_path / "e.json"
    ev.write_text("{not json")
    trust = tmp_path / "t.json"
    trust.write_text("{}")
    assert E._main(["verify", "--evidence", str(ev), "--trust", str(trust)]) == 2


def test_main_emit_without_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv(E.SIGNING_KEY_ENV, raising=False)
    report_dir = _guarded_report(tmp_path, {"provider_code": "aws", "services": {}})
    assert E._main(["emit", str(report_dir), "--alg", "hmac-sha256"]) == 2


# ── CLI integration (presidio-scout --evidence-out) ──────────────────────────
def _verify_ok(monkeypatch):
    monkeypatch.setattr(
        scout_integrity,
        "verify_scout",
        lambda *a, **k: scout_integrity.ScoutIntegrityResult(
            "scout", "/usr/bin/scout", "5.14.0", "5.14.0"
        ),
    )


def test_cli_evidence_out_emits_envelope(tmp_path, monkeypatch, capsys):
    report_dir = tmp_path / "out"
    out = tmp_path / "evidence.json"
    monkeypatch.setenv(E.SIGNING_KEY_ENV, "topsecret")
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        sub = plan.report_dir / "scoutsuite-results"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "scoutsuite_results_aws-1.js").write_text(
            "scoutsuite_results =\n" + json.dumps({"provider_code": "aws", "services": {}})
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        [
            "aws",
            "--report-dir",
            str(report_dir),
            "--evidence-out",
            str(out),
            "--evidence-alg",
            "hmac-sha256",
        ]
    )
    assert rc == 0
    assert "evidence:" in capsys.readouterr().out
    env = json.loads(out.read_text())
    assert env["schema"] == E.SCHEMA_ID
    assert {r["item_id"] for r in env["evidence"]} == {"O5", "T5"}
    # the emitted evidence verifies under a matching trust store
    trust = E.load_trust_store(json.dumps({E.SOURCE: "topsecret"}))
    assert all(E.verify_ref(r, trust) for r in E.parse_document(env))


def test_cli_evidence_out_without_key_fails_closed(tmp_path, monkeypatch):
    report_dir = tmp_path / "out"
    monkeypatch.delenv(E.SIGNING_KEY_ENV, raising=False)
    _verify_ok(monkeypatch)

    def fake_run(plan, timeout=None):
        (plan.report_dir / "report.html").write_text("<html><head></head><body>ok</body></html>")
        sub = plan.report_dir / "scoutsuite-results"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "scoutsuite_results_aws-1.js").write_text(
            "scoutsuite_results =\n" + json.dumps({"provider_code": "aws", "services": {}})
        )
        return subprocess.CompletedProcess(plan.argv, 0, stdout="", stderr="")

    monkeypatch.setattr(launcher, "run", fake_run)
    rc = cli.main(
        ["aws", "--report-dir", str(report_dir), "--evidence-out", str(tmp_path / "e.json")]
    )
    assert rc == 3


# ── trust-store hardening (0.29.0) ───────────────────────────────────────────
def test_trust_store_rejects_malformed_ed25519_key():
    # Wrong length and non-hex Ed25519 public keys must fail at load, not silently
    # turn into a verify-false later.
    for bad in ("00", "z" * 64, "AA" * 32):
        with pytest.raises(EvidenceError):
            E.load_trust_store(json.dumps({"s": {"alg": "ed25519", "public_key": bad}}))


@_needs_ed25519
def test_trust_store_accepts_well_formed_ed25519_key():
    # 64 lowercase hex chars normalises fine; loading an ed25519 store needs the
    # [crypto] extra (fail-fast), so this is gated on it.
    trust = E.load_trust_store(json.dumps({"s": {"alg": "ed25519", "public_key": ED_PUB}}))
    assert trust["s"] == {"alg": "ed25519", "keys": [ED_PUB]}


def test_trust_store_unknown_alg_rejected():
    with pytest.raises(EvidenceError):
        E.load_trust_store(json.dumps({"s": {"alg": "rsa", "key": "x"}}))


# ── tamper-case conformance (pins fail-closed behaviour) ─────────────────────
def test_hmac_tamper_cases_all_fail():
    ref = E.EvidenceRef(**_ref_dict())
    # wrong key
    assert E.verify_ref(ref, E.load_trust_store(json.dumps({GOLDEN_SIGNER: "wrong"}))) is False
    # malformed signature hex (not lowercase hex) is rejected at parse time
    with pytest.raises(EvidenceError):
        E.parse_document({"evidence": [_ref_dict(signature="zz" + GOLDEN_HMAC_SIG[2:])]})


@_needs_ed25519
def test_ed25519_wrong_public_key_fails():
    ref = E.EvidenceRef(**_ref_dict(signature=ED_SIG))
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": "00" * 32}})
    )
    assert E.verify_ref(ref, trust) is False


# ── cross-repo interop golden (0.29.0) ───────────────────────────────────────
_INTEROP = Path(__file__).parent / "interop"


def _regenerate_interop_envelope():
    """Rebuild the committed golden from its fixed inputs (see notes.json)."""
    notes = json.loads((_INTEROP / "scout-evidence-aws.notes.json").read_text())
    env = E.build_evidence(
        FindingsReport(findings=[], providers=["aws"]),
        report_digest=notes["report_digest"],
        signer=notes["signer"],
        key=notes["key"],
        alg=notes["alg"],
        providers=["aws"],
        source_version=notes["source_version"],
        claimed_at=notes["claimed_at"],
    )
    return json.dumps(env, indent=2, sort_keys=True) + "\n"


def test_interop_golden_is_byte_stable():
    # Append-only discipline: the committed envelope must reproduce byte-for-byte
    # from its fixed inputs, so a drift in the map or wire format is caught here.
    committed = (_INTEROP / "scout-evidence-aws.json").read_text()
    assert _regenerate_interop_envelope() == committed


def test_interop_golden_verifies_and_tamper_fails():
    refs = E.load_evidence((_INTEROP / "scout-evidence-aws.json").read_text())
    trust = E.load_trust_store((_INTEROP / "scout-evidence-aws.trust.json").read_text())
    results = [E.verify_ref_detailed(r, trust) for r in refs]
    assert results and all(r.ok and not r.legacy_signature for r in results)
    # tampering any field the signature covers breaks verification
    tampered = E.EvidenceRef(**{**refs[0].to_dict(), "content_hash": "dead" * 16})
    assert E.verify_ref(tampered, trust) is False


def test_interop_golden_items_are_known_checklist_ids():
    # The envelope only affirms ids the consumer (ikigov-assess) recognises.
    refs = E.load_evidence((_INTEROP / "scout-evidence-aws.json").read_text())
    assert {r.item_id for r in refs} == {"T5", "O5"}
    assert all(r.item_id in E.VALID_ITEM_IDS for r in refs)


# ── legacy signatures (deprecated; removal per E.LEGACY_SIGNATURE_REMOVAL) ────
def _legacy_envelope(key="sek", signer="sig-er"):
    """An envelope signed the pre-0.30.0 way (every field but ``signature``)."""
    env = E.build_evidence(
        _report([]), report_digest="a" * 64, signer=signer, key=key, alg="hmac-sha256"
    )
    for ref in env["evidence"]:
        ref["signature"] = E._hmac_hex(E._legacy_signing_message(ref), key)
    return env


def test_legacy_hmac_signature_accepted_with_flag_and_warning(caplog):
    ref = E.EvidenceRef(**_ref_dict(signature=LEGACY_HMAC_SIG))
    trust = E.load_trust_store(json.dumps({GOLDEN_SIGNER: GOLDEN_HMAC_KEY}))
    with caplog.at_level("WARNING", logger="presidio_scoutsuite.evidence"):
        result = E.verify_ref_detailed(ref, trust)
    assert result == E.VerifyResult(True, legacy_signature=True)
    assert E.verify_ref(ref, trust) is True
    assert "legacy" in caplog.text and "resign" in caplog.text
    assert GOLDEN_HMAC_KEY not in caplog.text


def test_contract_signature_is_not_flagged_legacy(caplog):
    ref = E.EvidenceRef(**_ref_dict())
    trust = E.load_trust_store(json.dumps({GOLDEN_SIGNER: GOLDEN_HMAC_KEY}))
    with caplog.at_level("WARNING", logger="presidio_scoutsuite.evidence"):
        assert E.verify_ref_detailed(ref, trust) == E.VerifyResult(True, legacy_signature=False)
    assert caplog.text == ""


def test_legacy_signature_still_binds_every_field():
    trust = E.load_trust_store(json.dumps({GOLDEN_SIGNER: GOLDEN_HMAC_KEY}))
    for field, value in (
        ("item_id", "O5"),
        ("claimed_at", "2026-06-18T00:00:00Z"),
        ("ledger_ref", "presidio-report-manifest:sha256/" + "c" * 64),
    ):
        tampered = E.EvidenceRef(**_ref_dict(signature=LEGACY_HMAC_SIG, **{field: value}))
        assert E.verify_ref_detailed(tampered, trust) == E.VerifyResult(False)


def test_resign_document_upgrades_legacy_refs():
    env = _legacy_envelope()
    trust = E.load_trust_store(json.dumps({"sig-er": "sek"}))
    assert all(E.verify_ref_detailed(r, trust).legacy_signature for r in E.parse_document(env))
    new, count = E.resign_document(env, trust, key="sek", alg="hmac-sha256")
    assert count == len(env["evidence"]) == 2
    results = [E.verify_ref_detailed(r, trust) for r in E.parse_document(new)]
    assert all(r.ok and not r.legacy_signature for r in results)
    # only the signature changes; the envelope and every other field are kept
    assert {k: v for k, v in new.items() if k != "evidence"} == {
        k: v for k, v in env.items() if k != "evidence"
    }
    for old, fresh in zip(env["evidence"], new["evidence"], strict=True):
        assert {k: v for k, v in old.items() if k != "signature"} == {
            k: v for k, v in fresh.items() if k != "signature"
        }
    # idempotent: a conformant document is left untouched
    again, count = E.resign_document(new, trust, key="sek", alg="hmac-sha256")
    assert count == 0 and again == new


def test_resign_refuses_unverifiable_ref():
    env = _legacy_envelope(key="sek")
    trust = E.load_trust_store(json.dumps({"sig-er": "other"}))
    with pytest.raises(EvidenceError, match="refusing to re-sign"):
        E.resign_document(env, trust, key="other", alg="hmac-sha256")


def test_resign_refuses_key_not_matching_signer():
    env = _legacy_envelope(key="sek")
    trust = E.load_trust_store(json.dumps({"sig-er": "sek"}))
    with pytest.raises(EvidenceError, match="does not match") as exc:
        E.resign_document(env, trust, key="attacker-key", alg="hmac-sha256")
    assert "attacker-key" not in str(exc.value)


@_needs_ed25519
def test_resign_ed25519_legacy_ref():
    env = {"schema": E.SCHEMA_ID, "evidence": [_ref_dict(signature=LEGACY_ED_SIG)]}
    trust = E.load_trust_store(
        json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}})
    )
    new, count = E.resign_document(env, trust, key=ED_PRIV, alg="ed25519")
    assert count == 1 and new["evidence"][0]["signature"] == ED_SIG


def test_main_resign_round_trip_never_prints_key(tmp_path, capsys, caplog):
    secret = "resign-secret-do-not-print"
    ev = tmp_path / "legacy.json"
    ev.write_text(json.dumps(_legacy_envelope(key=secret)))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps({"sig-er": secret}))
    keyfile = tmp_path / "key"
    keyfile.write_text(secret + "\n")
    out = tmp_path / "resigned.json"

    with caplog.at_level("DEBUG"):
        assert E._main(["verify", "--evidence", str(ev), "--trust", str(trust)]) == 0
        legacy_io = capsys.readouterr()
        assert "[legacy signature]" in legacy_io.out
        assert "presidio-scout-evidence resign" in legacy_io.err

        argv = ["resign", "--evidence", str(ev), "--trust", str(trust)]
        argv += ["--key", str(keyfile), "--alg", "hmac-sha256", "-o", str(out)]
        assert E._main(argv) == 0
        resign_io = capsys.readouterr()
        assert "2 legacy ref(s) re-signed" in resign_io.err

        assert E._main(["verify", "--evidence", str(out), "--trust", str(trust)]) == 0
        fresh_io = capsys.readouterr()
        assert "[legacy signature]" not in fresh_io.out
        assert "warning" not in fresh_io.err

    for text in (legacy_io.out, legacy_io.err, resign_io.out, resign_io.err, caplog.text):
        assert secret not in text
    assert secret not in out.read_text()


def test_main_resign_wrong_key_and_missing_file_fail_closed(tmp_path, capsys):
    ev = tmp_path / "legacy.json"
    ev.write_text(json.dumps(_legacy_envelope(key="sek")))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps({"sig-er": "sek"}))
    keyfile = tmp_path / "key"
    keyfile.write_text("wrong-key-value")
    base = ["resign", "--evidence", str(ev), "--trust", str(trust), "--alg", "hmac-sha256"]
    assert E._main([*base, "--key", str(keyfile)]) == 3
    assert E._main([*base, "--key", str(tmp_path / "nope")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert E._main(["resign", "--evidence", str(bad), "--trust", str(trust)]) == 2
    io = capsys.readouterr()
    assert "wrong-key-value" not in io.out + io.err
