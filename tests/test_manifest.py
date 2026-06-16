from __future__ import annotations

from datetime import datetime, timezone

from presidio_scoutsuite import manifest


def test_canonical_payload_is_order_independent():
    a = manifest.canonical_payload("sha256", {"b": "2", "a": "1"})
    b = manifest.canonical_payload("sha256", {"a": "1", "b": "2"})
    assert a == b


def test_content_digest_changes_with_files():
    base = manifest.content_digest("sha256", {"a": "1"})
    assert base != manifest.content_digest("sha256", {"a": "2"})
    assert base != manifest.content_digest("sha256", {"a": "1", "b": "2"})


def test_sign_is_deterministic_and_key_dependent():
    files = {"a": "1"}
    one = manifest.sign("sha256", files, b"key")
    assert one == manifest.sign("sha256", files, b"key")
    assert one != manifest.sign("sha256", files, b"other")


def test_build_manifest_shape_and_self_digest():
    files = {"z": "9", "a": "1"}
    doc = manifest.build_manifest(files, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert doc["schema"] == manifest.MANIFEST_SCHEMA
    assert doc["algorithm"] == "sha256"
    assert doc["file_count"] == 2
    assert list(doc["files"]) == ["a", "z"]  # sorted
    assert doc["generated_at"] == "2026-01-01T00:00:00Z"
    assert doc["content_digest"] == manifest.content_digest("sha256", files)
    assert "signature" not in doc


def test_build_manifest_with_signature():
    doc = manifest.build_manifest({"a": "1"}, sign_key=b"key")
    assert doc["signature"]["algorithm"] == manifest.SIGNATURE_ALGORITHM
    assert doc["signature"]["value"] == manifest.sign("sha256", {"a": "1"}, b"key")


def test_hmac_key_from_env():
    assert manifest.hmac_key_from_env({}) is None
    assert manifest.hmac_key_from_env({manifest.HMAC_ENV_VAR: "  "}) is None
    assert manifest.hmac_key_from_env({manifest.HMAC_ENV_VAR: " k "}) == b"k"
