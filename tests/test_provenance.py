from __future__ import annotations

import base64
import json

import pytest

from presidio_scoutsuite import provenance as P
from presidio_scoutsuite.errors import ProvenanceVerificationError

REPO = "https://github.com/presidio-v/presidio-hardened-scoutsuite"
DIGEST = "sha256:" + "a" * 64


def _v02(**overrides):
    stmt = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"name": "image", "digest": {"sha256": "a" * 64}}],
        "predicate": {
            "builder": {"id": REPO + "/.github/workflows/release.yml@refs/tags/v0.4.0"},
            "buildType": "https://mobyproject.org/buildkit@v1",
            "invocation": {"configSource": {"uri": "git+" + REPO + "@refs/tags/v0.4.0"}},
            "materials": [{"uri": "git+" + REPO + ".git"}],
        },
    }
    stmt.update(overrides)
    return stmt


def _v1():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "wheel", "digest": {"sha256": "b" * 64}}],
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"repository": REPO}},
                "resolvedDependencies": [{"uri": "git+" + REPO + "@refs/tags/v0.4.0"}],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/"
                    ".github/workflows/x.yml@refs/tags/v1.10.0"
                }
            },
        },
    }


# --- parsing -----------------------------------------------------------------


def test_load_bare_statement():
    prov = P.load_statement(json.dumps(_v02()))
    assert prov.predicate_type == "https://slsa.dev/provenance/v0.2"
    assert DIGEST in prov.subject_digests


def test_load_dsse_envelope():
    env = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(_v02()).encode()).decode(),
        "signatures": [{"sig": "x"}],
    }
    prov = P.load_statement(json.dumps(env))
    assert prov.predicate_type == "https://slsa.dev/provenance/v0.2"


def test_load_jsonlines_takes_first():
    line = json.dumps(_v02())
    prov = P.load_statement(line + "\n" + "garbage")
    assert prov.predicate_type.endswith("v0.2")


def test_load_accepts_bytes():
    assert P.load_statement(json.dumps(_v02()).encode()).builder_id


def test_load_empty_raises():
    with pytest.raises(ProvenanceVerificationError, match="empty"):
        P.load_statement("   ")


def test_load_invalid_json_raises():
    with pytest.raises(ProvenanceVerificationError, match="not valid JSON"):
        P.load_statement("{not json")


def test_load_bad_dsse_payload_raises():
    env = {"payload": "!!!not-base64-json!!!"}
    with pytest.raises(ProvenanceVerificationError, match="DSSE payload"):
        P.load_statement(json.dumps(env))


def test_load_missing_predicate_type_raises():
    with pytest.raises(ProvenanceVerificationError, match="predicateType"):
        P.load_statement(json.dumps({"subject": []}))


def test_load_unsupported_statement_type_raises():
    stmt = _v02(_type="https://in-toto.io/Statement/v9")
    with pytest.raises(ProvenanceVerificationError, match="unsupported statement type"):
        P.load_statement(json.dumps(stmt))


def test_load_from_gh_attestation_verify_array():
    # `gh attestation verify --format json` emits an array of bundles, each
    # wrapping the in-toto statement in a DSSE envelope's base64 payload.
    stmt = _v02()
    envelope_payload = base64.b64encode(json.dumps(stmt).encode()).decode()
    gh_output = [
        {
            "attestation": {
                "bundle": {
                    "dsseEnvelope": {
                        "payload": envelope_payload,
                        "payloadType": "application/vnd.in-toto+json",
                    }
                }
            }
        }
    ]
    prov = P.load_statement(json.dumps(gh_output))
    assert prov.predicate_type == "https://slsa.dev/provenance/v0.2"
    assert DIGEST in prov.subject_digests


def test_load_from_gh_array_with_direct_statement():
    # Tolerate a verifier that nests the decoded statement directly.
    gh_output = [{"verificationResult": {"statement": _v02()}}]
    assert P.load_statement(json.dumps(gh_output)).predicate_type.endswith("v0.2")


# --- field extraction --------------------------------------------------------


def test_v1_field_extraction():
    prov = P.load_statement(json.dumps(_v1()))
    assert "slsa-github-generator" in prov.builder_id
    assert prov.source_uri == REPO
    assert "sha256:" + "b" * 64 in prov.subject_digests


def test_v1_source_falls_back_to_resolved_dependencies():
    stmt = _v1()
    del stmt["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
    prov = P.load_statement(json.dumps(stmt))
    assert prov.source_uri == "git+" + REPO + "@refs/tags/v0.4.0"


def test_source_uri_falls_back_to_materials():
    stmt = _v02()
    del stmt["predicate"]["invocation"]
    prov = P.load_statement(json.dumps(stmt))
    assert prov.source_uri == "git+" + REPO + ".git"


def test_empty_predicate_yields_empty_fields():
    prov = P.load_statement(json.dumps({"predicateType": "https://slsa.dev/provenance/v0.2"}))
    assert prov.builder_id == ""
    assert prov.source_uri == ""
    assert prov.subject_digests == set()


# --- verification ------------------------------------------------------------


def test_verify_v02_ok():
    result = P.verify(P.load_statement(json.dumps(_v02())), artifact_digest=DIGEST)
    assert result.ok
    assert result.errors == []


def test_verify_v1_ok():
    result = P.verify(P.load_statement(json.dumps(_v1())), artifact_digest="sha256:" + "b" * 64)
    assert result.ok


def test_verify_without_digest_skips_digest_check():
    assert P.verify(P.load_statement(json.dumps(_v02()))).ok


def test_verify_rejects_wrong_digest():
    result = P.verify(P.load_statement(json.dumps(_v02())), artifact_digest="sha256:" + "f" * 64)
    assert not result.ok
    assert any("not attested" in e for e in result.errors)


def test_verify_rejects_untrusted_builder():
    stmt = _v02()
    stmt["predicate"]["builder"]["id"] = "https://evil.example/ci"
    result = P.verify(P.load_statement(json.dumps(stmt)))
    assert any("builder id" in e for e in result.errors)


def test_verify_rejects_wrong_source():
    stmt = _v02()
    stmt["predicate"]["invocation"]["configSource"]["uri"] = "git+https://github.com/attacker/x"
    stmt["predicate"]["materials"][0]["uri"] = "git+https://github.com/attacker/x"
    result = P.verify(P.load_statement(json.dumps(stmt)))
    assert any("source uri" in e for e in result.errors)


def test_verify_rejects_disallowed_predicate_type():
    stmt = _v02(predicateType="https://slsa.dev/provenance/v0.1")
    result = P.verify(P.load_statement(json.dumps(stmt)))
    assert any("predicate type" in e for e in result.errors)


def test_verify_container_image_provenance():
    # Shape of provenance for the released multi-arch image (subject = image
    # digest; builder = this repo's release workflow), verified end-to-end.
    image_digest = "sha256:" + "e" * 64
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": "ghcr.io/presidio-v/presidio-hardened-scoutsuite",
                "digest": {"sha256": "e" * 64},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"repository": REPO, "ref": "refs/tags/v0.11.0"}}
            },
            "runDetails": {
                "builder": {"id": REPO + "/.github/workflows/release.yml@refs/tags/v0.11.0"}
            },
        },
    }
    result = P.verify(P.load_statement(json.dumps(stmt)), artifact_digest=image_digest)
    assert result.ok, result.errors


def test_normalize_uri_equivalences():
    assert P._normalize_uri("git+" + REPO + ".git@refs/tags/v1") == REPO
    assert P._normalize_uri(REPO + "/") == REPO
    assert P._normalize_uri(REPO + "#main") == REPO


# --- policy ------------------------------------------------------------------


def test_bundled_policy_loads():
    policy = P.ProvenancePolicy.bundled()
    assert policy.expected_source_uri == REPO
    assert any("presidio-v" in p for p in policy.builder_id_prefixes)


def test_policy_from_dict_malformed():
    with pytest.raises(ProvenanceVerificationError, match="malformed"):
        P.ProvenancePolicy.from_dict({"expected_source_uri": REPO})


def test_custom_policy_overrides_source():
    policy = P.ProvenancePolicy(
        expected_source_uri="https://github.com/other/repo",
        builder_id_prefixes=("https://github.com/other/",),
        allowed_predicate_types=("https://slsa.dev/provenance/v0.2",),
    )
    stmt = _v02()
    stmt["predicate"]["builder"]["id"] = "https://github.com/other/ci"
    stmt["predicate"]["invocation"]["configSource"]["uri"] = "https://github.com/other/repo"
    stmt["predicate"]["materials"][0]["uri"] = "https://github.com/other/repo"
    assert P.verify(P.load_statement(json.dumps(stmt)), policy=policy).ok


# --- CLI ---------------------------------------------------------------------


def test_cli_ok(tmp_path, capsys):
    f = tmp_path / "prov.json"
    f.write_text(json.dumps(_v02()))
    rc = P._main([str(f), "--digest", DIGEST])
    assert rc == 0
    assert "provenance verified" in capsys.readouterr().out


def test_cli_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_v02())))
    rc = P._main(["-", "--digest", DIGEST])
    assert rc == 0


def test_cli_policy_failure_returns_3(tmp_path, capsys):
    f = tmp_path / "prov.json"
    f.write_text(json.dumps(_v02()))
    rc = P._main([str(f), "--digest", "sha256:" + "9" * 64])
    assert rc == 3
    assert "FAIL" in capsys.readouterr().err


def test_cli_parse_error_returns_2(tmp_path, capsys):
    f = tmp_path / "prov.json"
    f.write_text("{garbage")
    rc = P._main([str(f)])
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_cli_source_and_builder_overrides(tmp_path):
    f = tmp_path / "prov.json"
    stmt = _v02()
    stmt["predicate"]["builder"]["id"] = "https://github.com/myorg/ci"
    stmt["predicate"]["invocation"]["configSource"]["uri"] = "https://github.com/myorg/repo"
    stmt["predicate"]["materials"][0]["uri"] = "https://github.com/myorg/repo"
    f.write_text(json.dumps(stmt))
    rc = P._main(
        [
            str(f),
            "--source-uri",
            "https://github.com/myorg/repo",
            "--builder-id-prefix",
            "https://github.com/myorg/",
        ]
    )
    assert rc == 0
